// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
//limitations under the License.

package elfparser

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/aws/aws-ebpf-sdk-go/pkg/cache"
	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/internal/btf"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
)

var (
	bpfInsDefSize        = (binary.Size(utils.BPFInsn{}) - 1)
	bpfMapDefSize        = binary.Size(ebpf_maps.BpfMapDef{})
	probeProgParams      = 1
	kprobeProgParams     = 2
	tracepointProgParams = 3
)

// src_reg values of a BPF_JMP|BPF_CALL insn (include/uapi/linux/bpf.h)
const (
	bpfPseudoCall      = 1
	bpfPseudoKfuncCall = 2
)

var log = logger.Get()
var sdkCache = cache.Get()

// ErrPartialRecovery is returned by RecoverAllBpfProgramsAndMaps (and
// GetAllBpfProgramsAndMaps) when some pins could not be rebuilt but others
// were.
//
// An error wrapping it comes back TOGETHER WITH a usable result: the returned
// map holds everything that was rebuilt, and only the pins named in the wrapped
// errors were skipped. Callers must therefore test
// errors.Is(err, ErrPartialRecovery) and proceed with the returned data rather
// than treating the non-nil error as total failure, which would turn one
// unreadable pin into a full reload of every workload on the node.
var ErrPartialRecovery = errors.New("partial recovery")

// Config carries SDK construction options.
//
// Every BPF map name the caller pins MUST appear in exactly one of
// NamespacedMaps or GlobalMaps. A name in neither list is classified
// inconsistently - the load path caches it as global while recovery treats it
// as unrecognized - so programs referencing it cannot be recovered after a
// restart. Recovery reports such a map as a per-pin error rather than skipping
// it silently.
type Config struct {
	// NamespacedMaps lists BPF map names that are pinned per pod-identifier
	// rather than globally.
	NamespacedMaps []string
	// GlobalMaps lists BPF map names that are pinned once per node, e.g.
	// "aws_conntrack_map" for the pin "global_aws_conntrack_map".
	GlobalMaps []string
	// GlobalPinPrefix is the pin-filename prefix the caller uses for node-wide
	// programs and maps, e.g. "global" for "global_aws_conntrack_map". Per-pod
	// pins instead carry a "<podName>@<namespace>" identifier.
	GlobalPinPrefix string
}

type BpfSDKClient interface {
	IncreaseRlimit() error
	LoadBpfFile(path, customizedPinPath string) (map[string]BpfData, map[string]ebpf_maps.BpfMap, error)
	LoadBpfFileWithCustomData(inputData BpfCustomData) (map[string]BpfData, map[string]ebpf_maps.BpfMap, error)
	RecoverGlobalMaps() (map[string]ebpf_maps.BpfMap, error)
	RecoverAllBpfProgramsAndMaps() (map[string]BpfData, error)
	GetAllBpfProgramsAndMaps() (map[string]BpfData, error)
	GetProgIdentifierFromBPFPinPath(pinPath string) (string, string, bool, error)
}

type BpfData struct {
	Program ebpf_progs.BpfProgram       // Return the program
	Maps    map[string]ebpf_maps.BpfMap // List of associated maps
}

type BpfCustomData struct {
	FilePath      string         // Filepath for the BPF program
	CustomPinPath string         // PinPath
	CustomMapSize map[string]int // Map of bpfMaps with custom size
}

// mapClassifier classifies BPF pin paths as global vs per-namespace using the
// caller-configured map names and global pin prefix.
type mapClassifier struct {
	namespacedMaps  map[string]struct{}
	globalMaps      map[string]struct{}
	globalPinPrefix string
}

// isGlobalMap reports whether mapName is one of the node-wide map names the
// caller configured via Config.GlobalMaps. This is a positive check: a name the
// caller did not list - including the empty name returned for an unparseable
// pin - is not global.
func (m *mapClassifier) isGlobalMap(mapName string) bool {
	_, ok := m.globalMaps[mapName]
	return ok
}

type bpfSDKClient struct {
	mapClassifier
	mapApi  ebpf_maps.BpfMapAPIs
	progApi ebpf_progs.BpfProgAPIs
}

type relocationEntry struct {
	relOffset int
	symbol    elf.Symbol
}

type progEntry struct {
	progSection *elf.Section
	progType    string
	subSystem   string
	subProgType string
}

type elfLoader struct {
	mapClassifier
	elfFile           *elf.File
	customizedPinPath string
	bpfMapApi         ebpf_maps.BpfMapAPIs
	bpfProgApi        ebpf_progs.BpfProgAPIs

	license         string
	mapSection      *elf.Section
	mapSectionIndex int

	reloSectionMap map[uint32]*elf.Section
	progSectionMap map[uint32]progEntry

	// Support for BPF subprograms (__noinline static functions)
	textSectionIndex int
	textSection      *elf.Section

	// Support for kfunc calls (extern ... __ksym functions) from program
	// sections
	kfuncResolver btf.KfuncResolver
	kfuncs        map[string]btf.Kfunc
	// progRelocs holds the relocation entries resolveKfuncs parsed, by
	// program section index, so the relocation pass doesn't parse them again.
	progRelocs map[uint32][]relocationEntry
	// fdArray is passed to BPF_PROG_LOAD as fd_array. A module kfunc call
	// carries an index into it in insn.off; slot 0 is reserved because
	// off == 0 means vmlinux. One fd_array is shared by the ELF's programs,
	// but only those in fdArrayProgs (sections with a module kfunc call) get
	// it, so the others keep the shorter BPF_PROG_LOAD attr.
	fdArray      []int32
	fdArrayIndex map[int]int16
	fdArrayProgs map[uint32]struct{}

	// created holds the maps and programs this load created, so a failed load
	// can release them. Global maps leave it once they are added to sdkCache.
	created []createdObject
}

// New returns a BpfSDKClient that classifies BPF pin paths using cfg. The
// classification is positive on both axes: a map is global only if its name is
// in cfg.GlobalMaps, and a pin is a global pin only if its filename prefix
// equals cfg.GlobalPinPrefix. A caller that leaves those fields unset therefore
// treats nothing as global, which makes RecoverGlobalMaps recover nothing - see
// the Config invariant above.
//
// It returns an error for a cfg that cannot classify the pins it describes:
// a map name in both NamespacedMaps and GlobalMaps, or GlobalMaps set with an
// empty GlobalPinPrefix. Both would otherwise surface much later as unrecovered
// workloads after a restart, so they are rejected at construction. An empty
// Config is valid - it simply classifies nothing as global.
func New(cfg Config) (BpfSDKClient, error) {
	nsSet := make(map[string]struct{}, len(cfg.NamespacedMaps))
	for _, m := range cfg.NamespacedMaps {
		nsSet[m] = struct{}{}
	}
	globalSet := make(map[string]struct{}, len(cfg.GlobalMaps))
	for _, m := range cfg.GlobalMaps {
		globalSet[m] = struct{}{}
	}

	// Config documents that every pinned map name appears in exactly one of the
	// two lists. Enforce it here: a violation is not recoverable at runtime and
	// would otherwise surface only as a pile of per-pin recovery failures after
	// the next restart, by which point the workloads are already unrecovered.
	for _, m := range cfg.NamespacedMaps {
		if _, inBoth := globalSet[m]; inBoth {
			return nil, fmt.Errorf("Config: map %q is in both NamespacedMaps and GlobalMaps; it will be classified global everywhere, so its per-pod pins cannot be recovered", m)
		}
	}
	// A global pin is matched as "<GlobalPinPrefix>_<mapName>", so an empty
	// prefix matches only a filename that literally begins with "_" - which is
	// nothing the SDK pins. The configured global maps are then unrecoverable.
	if len(cfg.GlobalMaps) > 0 && cfg.GlobalPinPrefix == "" {
		return nil, fmt.Errorf("Config: GlobalMaps lists %d map(s) but GlobalPinPrefix is empty; global pins are matched as \"<prefix>_<mapName>\", so none of the configured global maps can be recognized or recovered", len(cfg.GlobalMaps))
	}

	return &bpfSDKClient{
		mapClassifier: mapClassifier{
			namespacedMaps:  nsSet,
			globalMaps:      globalSet,
			globalPinPrefix: cfg.GlobalPinPrefix,
		},
		mapApi:  &ebpf_maps.BpfMap{},
		progApi: &ebpf_progs.BpfProgram{},
	}, nil
}

var _ BpfSDKClient = &bpfSDKClient{}

// This is not needed 5.11 kernel onwards because per-cgroup mem limits
// https://lore.kernel.org/bpf/20201201215900.3569844-1-guro@fb.com/
func (b *bpfSDKClient) IncreaseRlimit() error {
	err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	if err != nil {
		log.Infof("Failed to bump up the rlimit")
		return err
	}
	return nil
}

// newElfLoader builds a loader for a single ELF file. classifier is passed
// through from the SDK client so the loader classifies pin paths using the same
// caller-supplied configuration - namespaced map names and the global pin
// prefix - as recovery does.
func newElfLoader(elfFile *elf.File, bpfmapapi ebpf_maps.BpfMapAPIs, bpfprogapi ebpf_progs.BpfProgAPIs, customizedpinPath string, classifier mapClassifier) *elfLoader {
	elfloader := &elfLoader{
		mapClassifier:     classifier,
		elfFile:           elfFile,
		bpfMapApi:         bpfmapapi,
		bpfProgApi:        bpfprogapi,
		customizedPinPath: customizedpinPath,
		reloSectionMap:    make(map[uint32]*elf.Section),
		progSectionMap:    make(map[uint32]progEntry),
		textSectionIndex:  -1,
		kfuncResolver:     btf.KernelKfuncResolver(),
		fdArrayIndex:      make(map[int]int16),
		fdArrayProgs:      make(map[uint32]struct{}),
	}
	return elfloader
}

func (b *bpfSDKClient) LoadBpfFile(path, customizedPinPath string) (map[string]BpfData, map[string]ebpf_maps.BpfMap, error) {

	bpfFile, err := os.Open(path)
	if err != nil {
		log.Errorf("LoadBpfFile failed to open")
		return nil, nil, err
	}
	defer bpfFile.Close()

	elfFile, err := elf.NewFile(bpfFile)
	if err != nil {
		return nil, nil, err
	}

	elfLoader := newElfLoader(elfFile, b.mapApi, b.progApi, customizedPinPath, b.mapClassifier)

	bpfLoadedProg, bpfLoadedMaps, err := elfLoader.doLoadELF(BpfCustomData{})
	if err != nil {
		return nil, nil, err
	}
	return bpfLoadedProg, bpfLoadedMaps, nil
}

func (b *bpfSDKClient) LoadBpfFileWithCustomData(inputData BpfCustomData) (map[string]BpfData, map[string]ebpf_maps.BpfMap, error) {

	bpfFile, err := os.Open(inputData.FilePath)
	if err != nil {
		log.Errorf("LoadBpfFileWithCustomData failed to open")
		return nil, nil, err
	}
	defer bpfFile.Close()

	elfFile, err := elf.NewFile(bpfFile)
	if err != nil {
		return nil, nil, err
	}

	elfLoader := newElfLoader(elfFile, b.mapApi, b.progApi, inputData.CustomPinPath, b.mapClassifier)

	bpfLoadedProg, bpfLoadedMaps, err := elfLoader.doLoadELF(inputData)
	if err != nil {
		return nil, nil, err
	}
	return bpfLoadedProg, bpfLoadedMaps, nil
}

type createdObject struct {
	fd      int
	pinPath string
	isProg  bool
}

// releaseObject closes an object a failed load created, and unpins it if the
// pin still holds that object. Overridden in tests.
var releaseObject = func(obj createdObject) {
	// Read the object's ID before closing its FD, so the ownership check can
	// reopen the pin with the descriptor that closing frees, even if the load
	// used up the descriptor limit.
	ourID, idErr := objectID(obj)
	// Every recorded FD came from a successful create, so 0 is valid here, for
	// example if stdin was closed.
	if obj.fd >= 0 {
		unix.Close(obj.fd)
	}
	if obj.pinPath == "" {
		return
	}
	if idErr == nil {
		if pinnedID, err := pinnedObjectID(obj); err == nil && pinnedID == ourID {
			if err := utils.UnPinObject(obj.pinPath); err != nil {
				log.Errorf("failed to unpin %s: %v", obj.pinPath, err)
			}
			return
		}
	}
	log.Infof("keeping %s: pin does not hold fd %d", obj.pinPath, obj.fd)
}

// objectID returns the kernel ID of the object behind obj.fd.
func objectID(obj createdObject) (uint32, error) {
	if obj.isProg {
		info, err := ebpf_progs.GetBPFprogInfo(obj.fd)
		return info.ID, err
	}
	info, err := ebpf_maps.GetBPFmapInfo(obj.fd)
	return info.Id, err
}

// pinnedObjectID returns the kernel ID of the object at obj.pinPath. It may not
// be obj's if pinning was skipped or failed, or if another load replaced the
// pin. The check and the unpin are not atomic, so loads of the same pin path
// must be serialized by the caller.
func pinnedObjectID(obj createdObject) (uint32, error) {
	if obj.isProg {
		info, fd, err := (&ebpf_progs.BpfProgram{}).GetProgFromPinPath(obj.pinPath)
		if err != nil {
			return 0, err
		}
		unix.Close(fd)
		return info.ID, nil
	}
	info, err := (&ebpf_maps.BpfMap{}).GetMapFromPinPath(obj.pinPath)
	return info.Id, err
}

// releaseCreated releases what this load created, newest first.
func (e *elfLoader) releaseCreated() {
	for i := len(e.created) - 1; i >= 0; i-- {
		releaseObject(e.created[i])
	}
	e.created = nil
}

func (e *elfLoader) loadMap(parsedMapData []ebpf_maps.CreateEBPFMapInput) (map[string]ebpf_maps.BpfMap, error) {

	programmedMaps := make(map[string]ebpf_maps.BpfMap)
	log.Infof("Total maps found - %d", len(parsedMapData))

	for index := 0; index < len(parsedMapData); index++ {
		log.Infof("Loading maps")
		loadedMaps := parsedMapData[index]

		//Get Pinning info
		mapNameStr := loadedMaps.Name
		if len(e.customizedPinPath) != 0 {
			mapNameStr = e.customizedPinPath + "_" + mapNameStr
		}

		pinPath := constdef.MAP_BPF_FS + mapNameStr
		loadedMaps.PinOptions.PinPath = pinPath

		bpfMap, err := (e.bpfMapApi).CreateBPFMap(loadedMaps)
		if err != nil {
			log.Errorf("failed to create map %v", err)
			return nil, err
		}
		obj := createdObject{fd: int(bpfMap.MapFD)}
		if loadedMaps.PinOptions.Type != constdef.PIN_NONE.Index() {
			obj.pinPath = pinPath
		}
		e.created = append(e.created, obj)

		//Fill ID
		if loadedMaps.PinOptions.Type == constdef.PIN_NONE.Index() {
			mapInfo, err := (e.bpfMapApi).GetBPFmapInfo(bpfMap.MapFD)
			if err != nil {
				return nil, fmt.Errorf("failed to get map info '%s'", mapNameStr)
			}
			bpfMap.MapID = uint32(mapInfo.Id)
		} else {
			mapInfo, err := (e.bpfMapApi).GetMapFromPinPath(pinPath)
			if err != nil {
				return nil, fmt.Errorf("map '%s' doesn't exist", mapNameStr)
			}
			mapID := uint32(mapInfo.Id)
			bpfMap.MapID = mapID
		}

		programmedMaps[loadedMaps.Name] = bpfMap

		// Classify by map name: pinPath can't be split reliably when the
		// pin prefix contains '_'.
		if !e.isNamespacedMap(loadedMaps.Name) {
			//Add to global cache
			sdkCache.Set(loadedMaps.Name, int(bpfMap.MapFD))
			log.Infof("Added map Name %s and FD %d to SDK cache", loadedMaps.Name, bpfMap.MapFD)
			// Cached maps are shared with later loads, so a failed load keeps them.
			e.created = e.created[:len(e.created)-1]
		}
	}
	return programmedMaps, nil
}

func (e *elfLoader) parseRelocationSection(reloSection *elf.Section, elfFile *elf.File) ([]relocationEntry, error) {
	var result []relocationEntry

	symbols, err := elfFile.Symbols()
	if err != nil {
		return nil, fmt.Errorf("unable to load symbols(): %v", err)
	}
	// Read section data
	data, err := reloSection.Data()
	if err != nil {
		return nil, fmt.Errorf("unable to read data from section '%s': %v", reloSection.Name, err)
	}

	reader := bytes.NewReader(data)
	for {
		var err error
		var offset, index int

		switch elfFile.Class {
		case elf.ELFCLASS64:
			var relocEntry elf.Rel64
			err = binary.Read(reader, elfFile.ByteOrder, &relocEntry)
			index = int(elf.R_SYM64(relocEntry.Info)) - 1
			offset = int(relocEntry.Off)
		case elf.ELFCLASS32:
			var relocEntry elf.Rel32
			err = binary.Read(reader, elfFile.ByteOrder, &relocEntry)
			index = int(elf.R_SYM32(relocEntry.Info)) - 1
			offset = int(relocEntry.Off)
		default:
			return nil, fmt.Errorf("unsupported arch %v", elfFile.Class)
		}

		if err != nil {
			// EOF. Nothing more to do.
			if err == io.EOF {
				return result, nil
			}
			return nil, err
		}

		// Validate the derived index value
		if index >= len(symbols) {
			return nil, fmt.Errorf("invalid Relocation section entry'%v': index %v does not exist",
				reloSection, index)
		}
		log.Infof("Relocation section entry: %s @ %v", symbols[index].Name, offset)
		result = append(result, relocationEntry{
			relOffset: offset,
			symbol:    symbols[index],
		})
	}
}

func (e *elfLoader) loadProg(loadedProgData map[string]ebpf_progs.CreateEBPFProgInput, loadedMaps map[string]ebpf_maps.BpfMap) (map[string]BpfData, error) {

	loadedprog := make(map[string]BpfData)

	for _, pgmInput := range loadedProgData {
		bpfData := BpfData{}
		log.Infof("Attempting to load prog: type=%s insnCnt=%d dataLen=%d insDefSize=%d",
			pgmInput.ProgType, len(pgmInput.ProgData)/pgmInput.InsDefSize, len(pgmInput.ProgData), pgmInput.InsDefSize)
		progFD, errno := e.bpfProgApi.LoadProg(pgmInput)
		if progFD == -1 {
			log.Infof("Failed to load prog: fd=%d err=%v", progFD, errno)
			return nil, fmt.Errorf("failed to Load the prog: %w", errno)
		}
		log.Infof("loaded prog with %d", progFD)
		e.created = append(e.created, createdObject{fd: progFD, pinPath: pgmInput.PinPath, isProg: true})

		//Fill ID
		progInfo, newProgFD, err := e.bpfProgApi.GetProgFromPinPath(pgmInput.PinPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get ProgID")
		}
		unix.Close(int(newProgFD))

		progID := int(progInfo.ID)

		bpfData.Program = ebpf_progs.BpfProgram{
			ProgID:      progID,
			ProgFD:      progFD,
			PinPath:     pgmInput.PinPath,
			ProgType:    pgmInput.ProgType,
			SubSystem:   pgmInput.SubSystem,
			SubProgType: pgmInput.SubProgType,
		}
		loadedprog[pgmInput.PinPath] = bpfData
	}
	return loadedprog, nil
}

func isProgTypeSupported(progType string) bool {
	if progType != "xdp" && progType != "tc_cls" && progType != "tc_act" && progType != "kprobe" && progType != "tracepoint" && progType != "kretprobe" {
		return false
	}
	return true
}

func parseProgType(splitProgType []string) (string, string, error) {
	retrievedProgParams := len(splitProgType)

	if retrievedProgParams != probeProgParams && retrievedProgParams != kprobeProgParams && retrievedProgParams != tracepointProgParams {
		return "", "", fmt.Errorf("unsupported prog params")
	}

	var progEntrySubSystem string
	var subProgEntryType string

	if retrievedProgParams == kprobeProgParams {
		subProgEntryType = strings.ToLower(splitProgType[1])
		log.Infof("Found subprog type %s", subProgEntryType)
	}
	if retrievedProgParams == tracepointProgParams {
		progEntrySubSystem = strings.ToLower(splitProgType[1])
		subProgEntryType = strings.ToLower(splitProgType[2])
		log.Infof("Found subprog type %s/%s", subProgEntryType, progEntrySubSystem)
	}
	return subProgEntryType, progEntrySubSystem, nil
}

func (e *elfLoader) parseSection() error {
	for index, section := range e.elfFile.Sections {
		if section.Name == "license" {
			data, err := section.Data()
			if err != nil {
				return fmt.Errorf("failed to read data for section %s", section.Name)
			}
			e.license = string(data)
			log.Infof("Found license - %s", e.license)
		} else if section.Name == "maps" {
			log.Infof("Found maps Section at Index %v", index)
			e.mapSection = section
			e.mapSectionIndex = index
		} else if section.Type == elf.SHT_PROGBITS && section.Name == ".text" {
			log.Infof("Found .text section (BPF subprograms) at index %d", index)
			e.textSection = section
			e.textSectionIndex = index
		} else if section.Type == elf.SHT_PROGBITS {
			log.Infof("Found PROG Section at Index %v and Name %s", index, section.Name)
			splitProgType := strings.Split(section.Name, "/")
			progEntryType := strings.ToLower(splitProgType[0])

			subProgEntryType, progEntrySubSystem, err := parseProgType(splitProgType)
			if err != nil {
				log.Info("Invalid prog type and subtype, supported is progtype such as tc or kprobe/progName or tracepoint/progType/progName")
				return fmt.Errorf("invalid progType or subType")
			}

			log.Infof("Found the progType %s", progEntryType)
			if !isProgTypeSupported(progEntryType) {
				log.Infof("Not supported program %s", progEntryType)
				continue
			}

			pEntry := progEntry{
				progType:    progEntryType,
				subSystem:   progEntrySubSystem,
				subProgType: subProgEntryType,
				progSection: section,
			}
			e.progSectionMap[uint32(index)] = pEntry

		} else if section.Type == elf.SHT_REL {
			log.Infof("Found a relocation section; Info:%v; Name: %s, Type: %s; Size: %v", section.Info,
				section.Name, section.Type, section.Size)
			e.reloSectionMap[section.Info] = section
		}
	}

	if len(e.license) == 0 {
		return fmt.Errorf("license missing in elf file")
	}

	return nil
}

func (e *elfLoader) getLicense() string {
	return e.license
}

func (e *elfLoader) parseMap(customData BpfCustomData) ([]ebpf_maps.CreateEBPFMapInput, error) {
	mapDefinitionSize := bpfMapDefSize
	parsedMapData := []ebpf_maps.CreateEBPFMapInput{}

	if e.mapSection == nil {
		log.Infof("Bpf file has no map section so skipping parse")
		return nil, nil
	}

	data, err := e.mapSection.Data()
	if err != nil {
		log.Infof("Error while loading section")
		return nil, fmt.Errorf("error while loading section : %w", err)
	}

	if len(data) == 0 {
		log.Infof("Missing data in mapsection")
		return nil, fmt.Errorf("missing data in map section")
	}
	symbols, err := e.elfFile.Symbols()
	if err != nil {
		log.Infof("Get symbol failed")
		return nil, fmt.Errorf("get symbols: %w", err)
	}

	for offset := 0; offset < len(data); offset += mapDefinitionSize {
		mapData := ebpf_maps.CreateEBPFMapInput{
			Type:       uint32(binary.LittleEndian.Uint32(data[offset : offset+4])),
			KeySize:    uint32(binary.LittleEndian.Uint32(data[offset+4 : offset+8])),
			ValueSize:  uint32(binary.LittleEndian.Uint32(data[offset+8 : offset+12])),
			MaxEntries: uint32(binary.LittleEndian.Uint32(data[offset+12 : offset+16])),
			Flags:      uint32(binary.LittleEndian.Uint32(data[offset+16 : offset+20])),
		}
		pinOptions := ebpf_maps.BpfMapPinOptions{
			Type: uint32(binary.LittleEndian.Uint32(data[offset+20 : offset+24])),
		}

		mapData.PinOptions = &pinOptions

		for _, sym := range symbols {
			if int(sym.Section) == e.mapSectionIndex && int(sym.Value) == offset {
				mapName := path.Base(sym.Name)
				mapData.Name = mapName
			}
		}
		log.Infof("Found map name %s", mapData.Name)

		if len(customData.CustomMapSize) != 0 {
			//Update the MaxEntries
			if customSize, ok := customData.CustomMapSize[mapData.Name]; ok {
				mapData.MaxEntries = uint32(customSize)
			}
		}
		parsedMapData = append(parsedMapData, mapData)
	}
	return parsedMapData, nil
}

func (e *elfLoader) getRelocatedTextSection(loadedMaps map[string]ebpf_maps.BpfMap) ([]byte, map[int]string, error) {
	if e.textSection == nil {
		return nil, nil, nil
	}

	data, err := e.textSection.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read .text section: %v", err)
	}
	log.Infof("Read .text section: %d bytes (%d insns)", len(data), len(data)/bpfInsDefSize)

	// Maps referenced only from within .text subprograms must still be reported
	// as associated with the owning program, otherwise the prog->map name table
	// (built from the main program section relocations) misses them and callers
	// that look maps up by name (e.g. TC_EGRESS_MAP) get an empty entry.
	textAssociatedMaps := make(map[int]string)

	// Apply map relocations from .rel.text
	reloSection := e.reloSectionMap[uint32(e.textSectionIndex)]
	if reloSection == nil {
		log.Infof("No .rel.text relocation section found")
		return data, textAssociatedMaps, nil
	}

	relocationEntries, err := e.parseRelocationSection(reloSection, e.elfFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse .rel.text: %v", err)
	}

	for _, relEntry := range relocationEntries {
		if relEntry.relOffset < 0 || relEntry.relOffset+bpfInsDefSize > len(data) {
			return nil, nil, fmt.Errorf("invalid .text relocation offset %d (data len %d)", relEntry.relOffset, len(data))
		}

		insnCode := data[relEntry.relOffset]

		// Skip BPF_CALL relocations within .text (internal function calls)
		if insnCode == (unix.BPF_JMP | unix.BPF_CALL) {
			// Kfunc calls are only relocated in program sections. Skipping
			// one here would leave a call the verifier rejects, so fail with
			// a clear error instead.
			if isKfuncSymbol(relEntry.symbol) {
				return nil, nil, fmt.Errorf(".text: kfunc %s is called from a subprogram, which is not supported; call it from the program section (for example, from an __always_inline function)", relEntry.symbol.Name)
			}
			log.Infof(".text: skipping BPF_CALL relocation for %s at offset %d", relEntry.symbol.Name, relEntry.relOffset)
			continue
		}

		// Must be a map relocation
		if insnCode != (unix.BPF_LD | unix.BPF_IMM | unix.BPF_DW) {
			return nil, nil, fmt.Errorf("invalid .text BPF instruction at %d: 0x%x", relEntry.relOffset, insnCode)
		}

		mapName := relEntry.symbol.Name
		var mapFD int
		if progMap, ok := loadedMaps[mapName]; ok {
			mapFD = int(progMap.MapFD)
			// Record the local map so it is reported as associated with the prog.
			textAssociatedMaps[int(progMap.MapID)] = mapName
		} else if globalMapFd, ok := sdkCache.Get(mapName); ok {
			mapFD = globalMapFd
		} else {
			return nil, nil, fmt.Errorf("map '%s' not found for .text relocation", mapName)
		}

		log.Infof(".text: applying map relocation for %s (FD=%d) at offset %d", mapName, mapFD, relEntry.relOffset)
		ebpfInsn := &utils.BPFInsn{
			Code:   data[relEntry.relOffset],
			DstReg: data[relEntry.relOffset+1] & 0xf,
			SrcReg: 1,
			Off:    int16(binary.LittleEndian.Uint16(data[relEntry.relOffset+2:])),
			Imm:    int32(mapFD),
		}
		copy(data[relEntry.relOffset:relEntry.relOffset+8], ebpfInsn.ConvertBPFInstructionToByteStream())
	}

	return data, textAssociatedMaps, nil
}

func (e *elfLoader) parseAndApplyRelocSection(progIndex uint32, loadedMaps map[string]ebpf_maps.BpfMap, textData []byte) ([]byte, map[int]string, error) {
	progEntry := e.progSectionMap[progIndex]
	reloSection := e.reloSectionMap[progIndex]

	progData, err := progEntry.progSection.Data()
	if err != nil {
		return nil, nil, err
	}
	progSectionSize := len(progData)
	log.Infof("Loading Program with relocation section; Info:%v; Name: %s, Type: %s; Size: %v", reloSection.Info,
		reloSection.Name, reloSection.Type, reloSection.Size)

	// Append .text section (subprograms) after program section data
	var data []byte
	if len(textData) > 0 {
		data = make([]byte, len(progData)+len(textData))
		copy(data, progData)
		copy(data[len(progData):], textData)
		log.Infof("Appended .text section: progSize=%d textSize=%d totalSize=%d",
			progSectionSize, len(textData), len(data))
	} else {
		data = progData
	}

	relocationEntries, ok := e.progRelocs[progIndex]
	if !ok {
		relocationEntries, err = e.parseRelocationSection(reloSection, e.elfFile)
	}
	if err != nil || len(relocationEntries) == 0 {
		return nil, nil, fmt.Errorf("unable to parse relocation entries....")
	}

	log.Infof("Applying Relocations..")
	associatedMaps := make(map[int]string)
	for _, relocationEntry := range relocationEntries {
		if relocationEntry.relOffset < 0 || relocationEntry.relOffset+bpfInsDefSize > len(data) {
			return nil, nil, fmt.Errorf("invalid offset for the relocation entry %d (data len %d)", relocationEntry.relOffset, len(data))
		}

		//eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM which consists
		//of two consecutive 'struct bpf_insn' 8-byte blocks and interpreted as single
		//instruction that loads 64-bit immediate value into a dst_reg.
		ebpfInstruction := &utils.BPFInsn{
			Code:   data[relocationEntry.relOffset],
			DstReg: data[relocationEntry.relOffset+1] & 0xf,
			SrcReg: data[relocationEntry.relOffset+1] >> 4,
			Off:    int16(binary.LittleEndian.Uint16(data[relocationEntry.relOffset+2:])),
			Imm:    int32(binary.LittleEndian.Uint32(data[relocationEntry.relOffset+4:])),
		}

		log.Infof("BPF Instruction code: %s; offset: %d; imm: %d", ebpfInstruction.Code, ebpfInstruction.Off, ebpfInstruction.Imm)

		// Handle BPF-to-BPF function call relocations (for __noinline subprograms)
		if ebpfInstruction.Code == (unix.BPF_JMP | unix.BPF_CALL) { // BPF_JMP | BPF_CALL
			funcName := relocationEntry.symbol.Name
			if isKfuncSymbol(relocationEntry.symbol) {
				if err := e.relocateKfuncCall(data[relocationEntry.relOffset:relocationEntry.relOffset+bpfInsDefSize], funcName); err != nil {
					return nil, nil, err
				}
				if e.kfuncs[funcName].Module != "" {
					e.fdArrayProgs[progIndex] = struct{}{}
				}
				continue
			}
			// R_BPF_64_32 relocation for a call insn: clang encodes the callee
			// target into insn.imm as (S + A) / 8 - 1, where S = the symbol's
			// value and A = the addend.
			// Ref: kernel Documentation/bpf/llvm_reloc.rst (R_BPF_64_32, call insn).
			//
			// This SDK only handles STATIC (__noinline) subprograms: clang
			// relocates those against the .text SECTION symbol, so S = 0 and the
			// callee's byte offset within .text is carried entirely in A. The
			// +symbol.Value term below is the general R_BPF_64_32 reconstruction
			// and is 0 in this (only supported) case.
			//
			// Global (non-static) BPF functions are also called via
			// BPF_PSEUDO_CALL, but the verifier checks them independently against
			// their BTF-described argument types instead of inlining caller
			// state. This concatenate-.text + PC-relative rewrite is not built
			// for independently-verified global functions and they are not
			// supported here.
			//
			// Only .text is appended, so the call target must live there.
			if int(relocationEntry.symbol.Section) != e.textSectionIndex {
				return nil, nil, fmt.Errorf("call relocation for %q targets section %d, not .text (%d); calls to subprograms outside .text are not supported",
					funcName, relocationEntry.symbol.Section, e.textSectionIndex)
			}

			// Recover A = (insn.imm + 1) * bpfInsDefSize, then rebase onto the
			// appended .text: target = progSectionSize + S + A.
			ebpfInstruction.SrcReg = bpfPseudoCall
			targetByteOffset := (ebpfInstruction.Imm + 1) * int32(bpfInsDefSize)
			targetOffset := int32(progSectionSize) + int32(relocationEntry.symbol.Value) + targetByteOffset

			// Guard against a corrupt addend producing an out-of-range target;
			// the full target instruction (bpfInsDefSize bytes) must fit.
			if targetOffset < 0 || int(targetOffset)+bpfInsDefSize > len(data) {
				return nil, nil, fmt.Errorf("call relocation for %q computed out-of-bounds target offset %d (combined size %d)",
					funcName, targetOffset, len(data))
			}

			targetInsnIdx := targetOffset / int32(bpfInsDefSize)
			callInsnIdx := int32(relocationEntry.relOffset / bpfInsDefSize)
			ebpfInstruction.Imm = targetInsnIdx - callInsnIdx - 1
			log.Infof("Function call relocation: %s -> targetInsn=%d callInsn=%d relImm=%d progSecSize=%d symVal=%d addend=%d",
				funcName, targetInsnIdx, callInsnIdx, ebpfInstruction.Imm, progSectionSize, relocationEntry.symbol.Value, targetByteOffset)
			copy(data[relocationEntry.relOffset:relocationEntry.relOffset+8], ebpfInstruction.ConvertBPFInstructionToByteStream())
			continue
		}

		//Validate for Invalid BPF instructions
		if ebpfInstruction.Code != (unix.BPF_LD | unix.BPF_IMM | unix.BPF_DW) {
			return nil, nil, fmt.Errorf("invalid BPF instruction (at %d): %d",
				relocationEntry.relOffset, ebpfInstruction.Code)
		}

		// Point BPF instruction to the FD of the map referenced. Update the last 4 bytes of
		// instruction (immediate constant) with the map's FD.
		mapName := relocationEntry.symbol.Name
		log.Infof("Map to be relocated; Name: %s", mapName)
		var mapFD int
		var map_id int

		// Relocated maps can be defined in the same BPF file or defined elsewhere but
		// using it here. So during relocation we search if it is a local map or
		// it is a global map.

		if progMap, ok := loadedMaps[mapName]; ok {
			map_id = int(progMap.MapID)
			associatedMaps[map_id] = mapName
			mapFD = int(progMap.MapFD)

		} else if globalMapFd, ok := sdkCache.Get(mapName); ok {
			log.Infof("Found FD %d in SDK cache", globalMapFd)
			mapFD = globalMapFd
		} else {
			return nil, nil, fmt.Errorf("failed to get map FD '%s' doesn't exist", mapName)
		}

		log.Infof("Map found. Replace the offset with corresponding Map FD: %v", mapFD)
		ebpfInstruction.SrcReg = 1 //dummy value for now
		ebpfInstruction.Imm = int32(mapFD)
		copy(data[relocationEntry.relOffset:relocationEntry.relOffset+8], ebpfInstruction.ConvertBPFInstructionToByteStream())
		log.Infof("From data: BPF Instruction code: %d; offset: %d; imm: %d",
			uint8(data[relocationEntry.relOffset]),
			uint16(binary.LittleEndian.Uint16(data[relocationEntry.relOffset+2:relocationEntry.relOffset+4])),
			uint32(binary.LittleEndian.Uint32(data[relocationEntry.relOffset+4:relocationEntry.relOffset+8])))
	}
	return data, associatedMaps, nil

}

// isKfuncSymbol reports whether a call relocation targets a kfunc. Clang
// relocates calls to an `extern ... __ksym` function against an undefined
// global symbol; calls to subprograms are relocated against a defined symbol.
func isKfuncSymbol(sym elf.Symbol) bool {
	if sym.Section != elf.SHN_UNDEF || sym.Name == "" {
		return false
	}
	bind := elf.ST_BIND(sym.Info)
	typ := elf.ST_TYPE(sym.Info)
	return (bind == elf.STB_GLOBAL || bind == elf.STB_WEAK) && (typ == elf.STT_NOTYPE || typ == elf.STT_FUNC)
}

// resolveKfuncs collects the kfuncs called from program sections and resolves
// them against the running kernel's BTF. Kfunc calls from .text subprograms
// are not supported; getRelocatedTextSection rejects them.
func (e *elfLoader) resolveKfuncs() error {
	// Most ELFs call no kfuncs. Check the symbol table first so that they
	// don't parse their relocations twice and load exactly as before.
	symbols, err := e.elfFile.Symbols()
	if err != nil {
		return nil // the relocation pass that follows reports it
	}
	hasKfuncSymbol := false
	for _, sym := range symbols {
		if isKfuncSymbol(sym) {
			hasKfuncSymbol = true
			break
		}
	}
	if !hasKfuncSymbol {
		return nil
	}

	seen := make(map[string]struct{})
	var names []string
	e.progRelocs = make(map[uint32][]relocationEntry)
	for targetIndex, reloSection := range e.reloSectionMap {
		// Only program sections can contain supported kfunc calls; other
		// relocation sections, such as those for .text or debug info, are
		// skipped.
		if _, isProg := e.progSectionMap[targetIndex]; !isProg {
			continue
		}
		// Unreadable sections are skipped here; the relocation pass that
		// follows reports them.
		target := e.elfFile.Sections[targetIndex]
		data, err := target.Data()
		if err != nil {
			continue
		}
		entries, err := e.parseRelocationSection(reloSection, e.elfFile)
		if err != nil {
			continue
		}
		e.progRelocs[targetIndex] = entries
		for _, entry := range entries {
			// Only calls: an undefined symbol can also be a map defined in
			// another ELF, which the map relocation path resolves by name.
			if !isKfuncSymbol(entry.symbol) || entry.relOffset < 0 || entry.relOffset+bpfInsDefSize > len(data) ||
				data[entry.relOffset] != (unix.BPF_JMP|unix.BPF_CALL) {
				continue
			}
			// A kfunc is usually called from several places; resolve it once.
			if _, ok := seen[entry.symbol.Name]; !ok {
				seen[entry.symbol.Name] = struct{}{}
				names = append(names, entry.symbol.Name)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}

	log.Infof("ELF calls kfuncs %v", names)
	kfuncs, err := e.kfuncResolver.ResolveKfuncs(names)
	if err != nil {
		return err
	}
	e.kfuncs = kfuncs
	return nil
}

// relocateKfuncCall rewrites a call insn into a kfunc call: src_reg =
// BPF_PSEUDO_KFUNC_CALL, imm = the kfunc's BTF ID, off = 0 for vmlinux or the
// module BTF fd's index in fd_array (kernel/bpf/verifier.c add_kfunc_call).
func (e *elfLoader) relocateKfuncCall(insn []byte, name string) error {
	kf, ok := e.kfuncs[name]
	if !ok {
		return fmt.Errorf("kfunc %q was not resolved", name)
	}

	// A vmlinux kfunc keeps off = 0. A module kfunc points at its module's
	// BTF fd in fd_array; each module gets one slot, shared by every call
	// into it, so the first call into a module adds the slot. Module, not
	// the fd, tells them apart, since 0 is a valid fd.
	var off int16
	if kf.Module != "" {
		idx, ok := e.fdArrayIndex[kf.ModuleBTFFD]
		if !ok {
			if len(e.fdArray) == 0 {
				// Slot 0 is never used: off == 0 means vmlinux.
				e.fdArray = append(e.fdArray, 0)
			}
			// insn.off is an s16, so fd_array indexes can't exceed it.
			if len(e.fdArray) > math.MaxInt16 {
				return fmt.Errorf("too many module BTFs for kfunc calls")
			}
			idx = int16(len(e.fdArray))
			e.fdArray = append(e.fdArray, int32(kf.ModuleBTFFD))
			e.fdArrayIndex[kf.ModuleBTFFD] = idx
		}
		off = idx
	}

	// Byte 1 of an insn packs dst_reg (low 4 bits) and src_reg (high 4 bits).
	ebpfInstruction := &utils.BPFInsn{
		Code:   insn[0],
		DstReg: insn[1] & 0xf,
		SrcReg: bpfPseudoKfuncCall,
		Off:    off,
		Imm:    int32(kf.BTFID),
	}
	copy(insn, ebpfInstruction.ConvertBPFInstructionToByteStream())
	log.Debugf("Kfunc call relocation: %s -> BTF ID %d, module %q, fd_array index %d", name, kf.BTFID, kf.Module, off)
	return nil
}

// countEntryPrograms returns the number of GLOBAL function symbols that live in
// a program section (i.e. loadable entry programs, not .text subprograms).
func (e *elfLoader) countEntryPrograms() (int, error) {
	symbolTable, err := e.elfFile.Symbols()
	if err != nil {
		return 0, fmt.Errorf("get symbols: %w", err)
	}
	count := 0
	for _, symbol := range symbolTable {
		if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC || elf.ST_BIND(symbol.Info) != elf.STB_GLOBAL {
			continue
		}
		if _, ok := e.progSectionMap[uint32(symbol.Section)]; ok {
			count++
		}
	}
	return count, nil
}

func (e *elfLoader) parseProg(loadedMaps map[string]ebpf_maps.BpfMap) (map[string]ebpf_progs.CreateEBPFProgInput, error) {
	//Get prog data
	var pgmList = make(map[string]ebpf_progs.CreateEBPFProgInput)

	// Resolve every kfunc the ELF calls up front, in one pass over the
	// kernel's BTF, before any relocation needs them. Resolving per call
	// instead would walk kernel BTF once per kfunc name.
	if err := e.resolveKfuncs(); err != nil {
		return nil, fmt.Errorf("failed to resolve kfuncs: %w", err)
	}

	// Pre-process .text section (BPF subprograms) with map relocations applied.
	// textMaps holds maps referenced only from within subprograms; they must be
	// merged into every prog that pulls in .text so the prog->map association is
	// complete (callers look maps up by name).
	textData, textMaps, err := e.getRelocatedTextSection(loadedMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to process .text section: %v", err)
	}
	if len(textData) > 0 {
		log.Infof("Prepared .text section: %d bytes (%d insns)", len(textData), len(textData)/bpfInsDefSize)

		// KNOWN LIMITATION: the loader appends the entire combined .text
		// section (every subprogram in the ELF) to each program. That is only
		// correct when a single entry program consumes those subprograms. When
		// an ELF has more than one entry program AND uses .text subprograms,
		// every program ends up carrying subprograms it never calls; the kernel
		// verifier then rejects the load with "unreachable insn". Proper support
		// requires extracting only each program's own call-graph subprograms and
		// recomputing call offsets/map associations per program. Until then,
		// fail loud rather than emit bytecode the kernel will reject.
		entryProgs, err := e.countEntryPrograms()
		if err != nil {
			return nil, fmt.Errorf("failed to count entry programs: %w", err)
		}
		if entryProgs > 1 {
			log.Errorf("ELF has %d entry programs and uses .text subprograms; this layout is not supported (would produce unreachable subprograms)", entryProgs)
			return nil, fmt.Errorf("failed to Load the prog: multiple entry programs with .text subprograms is unsupported (appending all .text subprograms to each program creates unreachable instructions the kernel verifier rejects)")
		}
	}

	for progIndex, progEntry := range e.progSectionMap {
		dataProg := progEntry.progSection
		data, err := progEntry.progSection.Data()
		if err != nil {
			return nil, fmt.Errorf("failed to get progEntry Data")
		}

		if len(data) == 0 {
			log.Infof("Missing data in prog Section")
			return nil, fmt.Errorf("missing data in prog section")
		}

		var linkedMaps map[int]string
		//Apply relocation
		if e.reloSectionMap[progIndex] == nil {
			log.Infof("Relocation is not needed")
		} else {
			progData, associatedMaps, err := e.parseAndApplyRelocSection(progIndex, loadedMaps, textData)
			if err != nil {
				return nil, fmt.Errorf("failed to apply relocation: %v", err)
			}
			//Replace data with relocated data
			data = progData
			linkedMaps = associatedMaps
			// Merge in maps referenced only from .text subprograms so the
			// program's associated-map name table is complete.
			if len(textData) > 0 {
				for mapID, mapName := range textMaps {
					if _, exists := linkedMaps[mapID]; !exists {
						linkedMaps[mapID] = mapName
						log.Infof("Adding .text-referenced map %s (ID %d) to prog associated maps", mapName, mapID)
					}
				}
			}
		}

		symbolTable, err := e.elfFile.Symbols()
		if err != nil {
			log.Infof("Get symbol failed")
			return nil, fmt.Errorf("get symbols: %w", err)
		}
		// Iterate over the symbols in the symbol table
		for _, symbol := range symbolTable {
			// Check if the symbol is a function
			if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC {
				// Check if sectionIndex matches
				if uint32(symbol.Section) == uint32(progIndex) && elf.ST_BIND(symbol.Info) == elf.STB_GLOBAL {
					// Check if the symbol's value (offset) is within the range of the section data

					progSize := symbol.Size
					secOff := symbol.Value
					ProgName := symbol.Name

					if secOff+progSize > dataProg.Size {
						log.Infof("Section out of bound secOff %d - progSize %d for name %s and data size %d", progSize, secOff, ProgName, dataProg.Size)
						return nil, fmt.Errorf("failed to Load the prog")
					}

					log.Infof("Sec '%s': found program '%s' at insn offset %d (%d bytes), code size %d insns (%d bytes)\n",
						progEntry.progType, ProgName, secOff/uint64(bpfInsDefSize), secOff, progSize/uint64(bpfInsDefSize), progSize)
					if symbol.Value >= dataProg.Addr && symbol.Value < dataProg.Addr+dataProg.Size {

						dataStart := (symbol.Value - dataProg.Addr)

						// Bounds-check against the actual relocated buffer using
						// subtraction form to avoid uint64 overflow. dataProg.Size
						// is the original section length; `data` may be longer
						// because .text subprograms were appended after it.
						dataLen := uint64(len(data))
						if dataStart > dataLen || progSize > dataLen-dataStart || dataProg.Size > dataLen {
							log.Infof("Program '%s' out of bounds: dataStart=%d progSize=%d dataLen=%d sectionLen=%d", ProgName, dataStart, progSize, dataLen, dataProg.Size)
							return nil, fmt.Errorf("failed to Load the prog")
						}

						// Slice exactly this program's own bytes (by its symbol
						// size). Using the section end here would make the first
						// of several programs that share a section swallow the
						// bytes of the programs that follow it.
						progBody := data[dataStart : dataStart+progSize]

						// .text subprograms (if any) were appended to `data`
						// after the original program section. Carry them along
						// so BPF-to-BPF calls resolve.
						var textPortion []byte
						if dataLen > dataProg.Size {
							textPortion = data[dataProg.Size:]

							// BPF-to-BPF call offsets are computed (in
							// parseAndApplyRelocSection) relative to the start of
							// the whole program section. That only matches the
							// trimmed layout we build here (this program's body +
							// .text) when the program occupies the entire section.
							// If the program shares its section with other
							// programs AND the section uses .text subprograms, the
							// call offsets would be wrong. Fail loud rather than
							// load corrupt bytecode.
							if dataStart != 0 || progSize != dataProg.Size {
								log.Errorf("Program '%s' shares a section with other programs and that section uses .text subprograms; BPF-to-BPF call relocation is not supported for this layout", ProgName)
								return nil, fmt.Errorf("failed to Load the prog: unsupported shared-section + .text layout for program '%s'", ProgName)
							}
						}

						loadSize := len(progBody) + len(textPortion)
						log.Infof("Program '%s': funcSize=%d sectionLen=%d textLen=%d loadSize=%d insns=%d",
							ProgName, progSize, dataProg.Size, len(textPortion), loadSize, loadSize/bpfInsDefSize)
						programData := make([]byte, loadSize)
						copy(programData, progBody)
						copy(programData[len(progBody):], textPortion)

						pinLocation := ProgName
						if len(e.customizedPinPath) != 0 {
							pinLocation = e.customizedPinPath + "_" + ProgName
						}
						pinPath := constdef.PROG_BPF_FS + pinLocation

						progMetaData := ebpf_progs.CreateEBPFProgInput{
							ProgType:       progEntry.progType,
							SubSystem:      progEntry.subSystem,
							SubProgType:    progEntry.subProgType,
							ProgData:       programData,
							LicenseStr:     e.license,
							PinPath:        pinPath,
							InsDefSize:     bpfInsDefSize,
							AssociatedMaps: linkedMaps,
						}
						if _, ok := e.fdArrayProgs[progIndex]; ok {
							progMetaData.FDArray = e.fdArray
						}
						pgmList[pinPath] = progMetaData
					} else {
						log.Infof("Invalid ELF file\n")
						return nil, fmt.Errorf("failed to Load the prog")
					}
				}
			}
		}
	}
	return pgmList, nil

}

func (e *elfLoader) doLoadELF(inputData BpfCustomData) (_ map[string]BpfData, _ map[string]ebpf_maps.BpfMap, err error) {
	defer func() {
		if err != nil {
			e.releaseCreated()
		}
	}()

	//Parse all sections
	if err := e.parseSection(); err != nil {
		fmt.Println(err)
		return nil, nil, fmt.Errorf("failed to parse sections in elf file %w", err)
	}

	//Parse Map
	parsedMapData, err := e.parseMap(inputData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse maps %w", err)
	}

	//Load Map
	loadedMapData, err := e.loadMap(parsedMapData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load maps %w", err)
	}

	//Parse Prog, need to pass loadedMapData for applying relocation
	parsedProgData, err := e.parseProg(loadedMapData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse prog %w", err)
	}

	//Load prog
	loadedProgData, err := e.loadProg(parsedProgData, loadedMapData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load progs %w", err)
	}

	//Link loaded map with prog
	for pgmPinPath := range loadedProgData {
		progMaps := make(map[string]ebpf_maps.BpfMap)
		if pgmEntry, ok := loadedProgData[pgmPinPath]; ok {
			associatedmapIDs, err := e.bpfProgApi.GetBPFProgAssociatedMapsIDs(pgmEntry.Program.ProgFD)
			if err != nil {
				log.Infof("Failed to load prog")
				return nil, nil, fmt.Errorf("failed to Load the prog, get associatedmapIDs failed")
			}
			//walk thru all mapIDs and get loaded FDs and fill BPFData
			for mapInfoIdx := 0; mapInfoIdx < len(associatedmapIDs); mapInfoIdx++ {
				mapID := associatedmapIDs[mapInfoIdx]
				if mapName, ok := parsedProgData[pgmPinPath].AssociatedMaps[int(mapID)]; ok {
					progMaps[mapName] = loadedMapData[mapName]
					log.Infof("Found %s with ID %d and FD %d", mapName, progMaps[mapName].MapID, progMaps[mapName].MapFD)
				}
			}
			pgmEntry.Maps = progMaps
			loadedProgData[pgmPinPath] = pgmEntry
		}
	}

	return loadedProgData, loadedMapData, nil
}

func (m *mapClassifier) isNamespacedMap(mapName string) bool {
	_, ok := m.namespacedMaps[mapName]
	return ok
}

// GetMapNameFromBPFPinPath splits a map pin filename into the map name and the
// pod identifier that owns it.
//
// Per-pod pins are "<podName>@<namespace>_<mapName>". The pod name portion can
// itself contain underscores, because the agent converts dots in pod names to
// underscores when building the identifier - so the identifier/mapName boundary
// is NOT necessarily the first underscore in the filename. It is always the
// first underscore after the "@": "@" cannot appear in a map name, and a
// namespace is a DNS-1123 label, which cannot contain an underscore.
//
// Global pins are "<globalPinPrefix>_<mapName>" and have no "@".
//
// A filename matching neither shape cannot be split unambiguously - for example
// a pre-"@" pin that the one-shot legacy migration did not rename. Rather than
// guess a boundary and register the map under a wrong name, it returns an error
// with both names empty, so the caller skips it. The same applies to a filename
// that has the right separators but an empty pod name, namespace or map name: it
// would otherwise produce an identifier such as "@default" or "pod@".
//
// Pure: an unparseable pin is reported by returning an error naming the
// specific defect - no map name after the namespace, an empty component, or a
// filename matching neither shape - and nothing is logged here. Reporting
// belongs to the caller, because what an unparseable pin costs depends on who
// is asking: the recovery and listing walks log it and carry it in the error
// they return, so it reaches the caller through ErrPartialRecovery, while
// RecoverGlobalMaps only logs it - a pin it cannot parse is not a global map,
// and a legacy pin must not fail global recovery. Logging here instead would
// report the same pin twice on walks that already surface it.
func (m *mapClassifier) GetMapNameFromBPFPinPath(pinPath string) (string, string, error) {
	splittedPinPath := strings.Split(pinPath, "/")
	pinnedMap := splittedPinPath[len(splittedPinPath)-1]

	if podName, rest, found := strings.Cut(pinnedMap, "@"); found {
		mapNamespace, mapName, ok := strings.Cut(rest, "_")
		if !ok {
			return "", "", fmt.Errorf("map pin %q: no map name after the namespace", pinnedMap)
		}
		// The separators being present is not enough: a pin such as
		// "@default_ingress_map", "pod@_ingress_map" or "pod@default_" splits
		// cleanly but yields an identifier of "@default" / "pod@" or an empty
		// map name. Registering state under one of those is the same wrong-key
		// outcome anchoring on "@" exists to prevent, so treat the pin as
		// unparseable instead. A real pod name and namespace are DNS-1123 and
		// therefore never empty, as is any map name the SDK pins.
		if podName == "" || mapNamespace == "" || mapName == "" {
			return "", "", fmt.Errorf("map pin %q: empty pod name, namespace or map name", pinnedMap)
		}
		return mapName, podName + "@" + mapNamespace, nil
	}

	// Global pins are "<globalPinPrefix>_<mapName>" where mapName is one of the
	// configured global maps. Matching the name exactly - rather than trusting the
	// prefix alone - keeps a pod whose name begins "global." from being mistaken
	// for a global pin if its pin was never migrated to the "@" format.
	if prefix, mapName, ok := strings.Cut(pinnedMap, "_"); ok && prefix == m.globalPinPrefix && m.isGlobalMap(mapName) {
		return mapName, mapName, nil
	}

	return "", "", fmt.Errorf("map pin %q: unrecognized pin format, expected %q or %q",
		pinnedMap, "<podName>@<namespace>_<mapName>", m.globalPinPrefix+"_<globalMapName>")
}

// GetProgIdentifierFromBPFPinPath returns the pod identifier that owns the
// program pinned at pinPath, and whether the pin is a node-wide (global) one.
//
// Two pin shapes are recognized:
//
//   - Per-pod:   "<podName>@<namespace>_<progName>". As with map pins, the pod
//     name portion can contain underscores - the agent converts dots in pod
//     names to underscores - so the identifier/progName boundary is the first
//     underscore after the "@", never the first underscore in the filename.
//     Returns ("<podName>@<namespace>", progName, false, nil).
//   - Global:    "<globalPinPrefix>_<progName>" (no "@"). Returns
//     ("", progName, true, nil). The SDK never creates global programs, so this
//     only exists to let callers skip such a pin if one is ever encountered.
//
// A filename matching neither shape returns ("", "", false, err) so the caller
// skips it rather than proceeding with a truncated identifier. So does a
// filename with the right separators but an empty pod name, namespace or prog
// name.
//
// Pure: as with GetMapNameFromBPFPinPath, an unparseable pin is reported by
// returning an error naming the specific defect, not by logging. The caller
// decides whether it matters and owns the log line.
//
// Known limitation: a legacy pin (pre-"@" format) for a pod whose name begins
// with the global prefix (e.g. "global.foo") has no "@" and a first segment of
// "global", so it is classified as global and skipped rather than recovered.
// This is bounded - such pins are renamed to the "@" format by the one-shot
// migration in the agent - so it is accepted rather than special-cased here.
func (b *bpfSDKClient) GetProgIdentifierFromBPFPinPath(pinPath string) (podIdentifier string, progName string, isGlobal bool, err error) {
	splittedPinPath := strings.Split(pinPath, "/")
	pinnedProg := splittedPinPath[len(splittedPinPath)-1]

	if podName, rest, found := strings.Cut(pinnedProg, "@"); found {
		progNamespace, progName, ok := strings.Cut(rest, "_")
		if !ok {
			return "", "", false, fmt.Errorf("prog pin %q: no prog name after the namespace", pinnedProg)
		}
		// As in GetMapNameFromBPFPinPath: the separators being present is not
		// enough. "@default_handle_ingress" or "pod@_handle_ingress" splits
		// cleanly but yields an identifier of "@default" / "pod@", under which
		// recovery would key a real program. Reject it instead of guessing.
		if podName == "" || progNamespace == "" || progName == "" {
			return "", "", false, fmt.Errorf("prog pin %q: empty pod name, namespace or prog name", pinnedProg)
		}
		return podName + "@" + progNamespace, progName, false, nil
	}

	if prefix, progName, ok := strings.Cut(pinnedProg, "_"); ok && prefix == b.globalPinPrefix && progName != "" {
		return "", progName, true, nil
	}

	return "", "", false, fmt.Errorf("prog pin %q: unrecognized pin format, expected %q or %q",
		pinnedProg, "<podName>@<namespace>_<progName>", b.globalPinPrefix+"_<progName>")
}

// RecoverGlobalMaps walks the BPF filesystem and reconstructs a map of all
// node-wide (global) maps that were pinned there. It returns a map keyed by the
// pin path, with each value containing the map's ID, FD, and metadata.
//
// All-or-nothing, in contrast to RecoverAllBpfProgramsAndMaps, which collects
// per-pin failures and returns everything it could rebuild alongside a non-nil
// ErrPartialRecovery error. A partial global map set is unusable here: every
// pod program on the node binds to all of the global maps, so it either returns
// the complete set configured in Config.GlobalMaps or returns a nil map and an
// error. That means it fails on
//
//   - the first unreadable global pin, and
//   - a walk that completes but recovers only a subset of Config.GlobalMaps,
//     including a map that is declared but has no pin on this node.
//
// On every failure path the FDs it opened are closed and the sdkCache entries
// it published are removed, so a caller that reacts to the error by recreating
// global state cannot pick up a half-recovered map through the cache.
//
// Recovering nothing is not a failure when there was nothing to recover: on a
// first start, before any pin exists - including when the map directory itself
// is absent - it returns an empty set and a nil error.
//
// A pin whose filename cannot be parsed is logged and skipped, not treated as a
// failure: it is not a global map, and a legacy pin left behind by a skipped
// migration must not stop global recovery. The per-pod walks are the ones that
// report it to the caller.
func (b *bpfSDKClient) RecoverGlobalMaps() (map[string]ebpf_maps.BpfMap, error) {
	_, err := os.Stat(constdef.BPF_DIR_MNT)
	if err != nil {
		log.Infof("BPF FS director is not present")
		return nil, fmt.Errorf("BPF directory is not present: %w", err)
	}
	loadedGlobalMaps := make(map[string]ebpf_maps.BpfMap)

	// Recovery is all-or-nothing, and "nothing" has to mean nothing: each map
	// recovered below opens an FD and publishes it to the process-global
	// sdkCache, which the load path reads when relocating a program against a
	// global map. Returning an error without undoing those two side effects
	// would leave the caller - which has just been told recovery failed, and so
	// recreates global state - binding its new programs to FDs from the attempt
	// that failed. So every FD opened here is tracked and rolled back unless
	// the whole walk succeeds.
	type recoveredGlobal struct {
		name string
		fd   int
	}
	var recoveredGlobals []recoveredGlobal
	recoveredNames := make(map[string]struct{})
	recoveredOK := false
	defer func() {
		if recoveredOK {
			return
		}
		// Slice, not the name set: if the same global map were somehow pinned
		// at two paths, both FDs must be closed, not just the last one.
		//
		// Delete rather than restore whatever the entry held before this call
		// overwrote it. Only two places write sdkCache - loadMap and this
		// function - so a pre-existing entry for a global map name requires the
		// caller to have loaded or recovered global maps BEFORE calling
		// recovery, which inverts the documented order: recovery exists to
		// discover already-pinned state before anything is loaded. Even in that
		// order nothing is lost, because the pin this walk reads is the one the
		// earlier load pinned, so the prior FD and the FD being dropped refer to
		// the same kernel map. And a caller that has just been handed a fatal
		// error from here recreates global state, which re-populates the cache.
		for _, g := range recoveredGlobals {
			log.Infof("Rolling back recovered global map %s FD %d", g.name, g.fd)
			sdkCache.Delete(g.name)
			if closeErr := unix.Close(g.fd); closeErr != nil {
				log.Errorf("failed to close global map FD %d for %s during rollback: %v", g.fd, g.name, closeErr)
			}
		}
	}()

	// A global pin we cannot read is fatal: the conntrack and events maps are
	// node-wide and every pod program binds to them, so a partial global map set
	// is not usable. Fail fast on the first per-pin error rather than returning
	// an incomplete set - unlike RecoverAllBpfProgramsAndMaps, which is per-pod
	// and recovers partially.
	// Counted so that "walked pins but matched none" can be distinguished from
	// "there were no pins". The former means GlobalMaps or GlobalPinPrefix does
	// not describe what is actually on this node, and returning an empty set
	// with a nil error there would let the caller conclude no global state
	// exists and rebind every pod to a freshly created conntrack map.
	pinsSeen := 0
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(constdef.BPF_DIR_MNT, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		var mapDirErr error
		if _, err := os.Stat(constdef.MAP_BPF_FS); err == nil {
			mapDirErr = filepath.Walk(constdef.MAP_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !fsinfo.IsDir() {
					pinsSeen++
					// Parsed once, then classified by the resulting name.
					mapName, _, parseErr := b.GetMapNameFromBPFPinPath(pinPath)
					if parseErr != nil {
						// Not fatal here - an unparseable pin is not a global
						// map, and a legacy pin left behind by a skipped
						// migration must not stop global recovery. But it is
						// logged rather than dropped: it is a pin nothing on
						// this node can account for, and leaving no trace would
						// make it depend on the caller also invoking one of the
						// per-pod walks to ever learn about it.
						//
						// This does not reintroduce per-pin log volume. A
						// per-pod pin parses cleanly and is skipped silently
						// below; only genuinely malformed or legacy filenames
						// reach here, and those are rare.
						log.Errorf("Skipping map pin %s during global recovery: %v", pinPath, parseErr)
						return nil
					}
					// Every per-pod pin on the node also lands in this
					// directory and is skipped here by design, so only the
					// global ones are logged below.
					if b.isGlobalMap(mapName) {
						log.Infof("Found global pinpath %s for map %s", pinPath, mapName)
						bpfMapInfo, err := b.mapApi.GetMapFromPinPath(pinPath)
						if err != nil {
							log.Errorf("error getting mapInfo for Global pin path %s, this shouldn't happen", pinPath)
							return err
						}
						mapID := bpfMapInfo.Id

						recoveredBpfMap := ebpf_maps.BpfMap{}

						//Fill BPF map
						recoveredBpfMap.MapID = uint32(mapID)
						//Fill New FD since old FDs will be deleted on recovery
						mapFD, err := utils.GetMapFDFromID(int(mapID))
						if err != nil {
							log.Errorf("map pin %s: unable to get FD from ID %d: %v", pinPath, int(mapID), err)
							return fmt.Errorf("unable to get FD from ID %d: %w", int(mapID), err)
						}
						recoveredBpfMap.MapFD = uint32(mapFD)
						log.Infof("Recovered map Name %s and FD %d", mapName, mapFD)
						sdkCache.Set(mapName, mapFD)
						// Track before anything else can fail, so the rollback
						// above owns this FD and cache entry from here on.
						recoveredGlobals = append(recoveredGlobals, recoveredGlobal{name: mapName, fd: mapFD})
						recoveredNames[mapName] = struct{}{}
						//Fill BPF map metadata
						recoveredBpfMapMetaData := ebpf_maps.CreateEBPFMapInput{
							Type:       bpfMapInfo.Type,
							KeySize:    bpfMapInfo.KeySize,
							ValueSize:  bpfMapInfo.ValueSize,
							MaxEntries: bpfMapInfo.MaxEntries,
							Flags:      bpfMapInfo.MapFlags,
							Name:       mapName,
						}
						recoveredBpfMap.MapMetaData = recoveredBpfMapMetaData
						loadedGlobalMaps[pinPath] = recoveredBpfMap
					}
				}
				return nil
			})
		} else if !os.IsNotExist(err) {
			mapDirErr = err
		}
		// A missing map directory is deliberately not an error: on a first
		// start the BPF FS is mounted but nothing has been pinned yet, so there
		// is genuinely nothing to recover. Walking it unguarded would hand the
		// callback an ENOENT and fail global recovery on every fresh node. Any
		// other stat failure is real and does abort.
		if mapDirErr != nil {
			log.Errorf("Error walking bpf map directory: %v", mapDirErr)
			return nil, fmt.Errorf("error walking the bpf directory: %w", mapDirErr)
		}
	} else {
		log.Infof("error checking BPF FS, please make sure it is mounted %v", err)
		return nil, fmt.Errorf("error checking BPF FS, please make sure it is mounted")
	}

	// Only an error when the caller declared global maps: a consumer that
	// configures none legitimately recovers an empty set. But if GlobalMaps is
	// non-empty and *nothing* on a non-empty filesystem matched, then
	// GlobalMaps or GlobalPinPrefix does not describe this node, and returning
	// (empty, nil) would let the caller conclude no global state exists.
	if len(loadedGlobalMaps) == 0 && pinsSeen > 0 && len(b.globalMaps) > 0 {
		log.Errorf("recovered no global maps from %d pin(s); check Config.GlobalMaps and Config.GlobalPinPrefix", pinsSeen)
		return nil, fmt.Errorf("recovered no global maps from %d pin(s): none matched the configured global pin prefix %q", pinsSeen, b.globalPinPrefix)
	}
	// Completeness: having recovered at least one global map, every map the
	// caller declared must be among them. A subset is not a usable starting
	// point - the pods already on this node are bound to all of the global
	// maps, so handing back some of them lets the caller rebind its programs
	// to a mixture of pre-restart and freshly created maps, which is the state
	// this function's fail-fast contract exists to prevent. Recovering nothing
	// at all is handled above; recovering nothing from nothing (a first start,
	// before any pin exists) is legitimate and returns an empty set.
	if len(recoveredNames) > 0 && len(recoveredNames) != len(b.globalMaps) {
		missing := make([]string, 0, len(b.globalMaps))
		for name := range b.globalMaps {
			if _, ok := recoveredNames[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		log.Errorf("recovered %d of %d configured global map(s) from %d pin(s); missing %v", len(recoveredNames), len(b.globalMaps), pinsSeen, missing)
		return nil, fmt.Errorf("recovered %d of %d configured global map(s), missing %v: a partial global map set is not usable", len(recoveredNames), len(b.globalMaps), missing)
	}

	recoveredOK = true
	return loadedGlobalMaps, nil
}

// RecoverAllBpfProgramsAndMaps walks the BPF filesystem and rebuilds the
// per-pod programs and maps pinned there, keyed by program pin path. Recovered
// maps carry freshly opened FDs, because the FDs from before the restart are
// gone.
//
// Partial by design: a pin it cannot read or parse costs only the workload that
// owns it, so the walk continues and the caller receives everything that was
// rebuilt. When any pin was skipped it returns a NON-NIL error wrapping
// ErrPartialRecovery TOGETHER WITH a usable result. Callers MUST therefore test
// errors.Is(err, ErrPartialRecovery) and proceed with the returned data rather
// than treating a non-nil error as total failure - the latter turns one stray
// file under the pin directory into a full reload.
//
// One skip is deliberately NOT counted, so a nil error means "every pin that
// could belong to a workload was recovered" rather than "every file was": a
// program pin classified as global is skipped silently. The SDK creates no
// global programs, so such a pin is foreign - counting it would make a node
// carrying any third-party pin under the programs directory report partial
// recovery on every start, forever. The one case where this hides a real loss
// is an unmigrated legacy pin for a pod named "<GlobalPinPrefix>*", and that
// pod still surfaces here through its map pin, which does not parse either.
//
// A program whose maps cannot be fully resolved is dropped rather than returned
// with an incomplete Maps set, because callers gate on Program.ProgFD alone and
// would reuse a partially populated program as if it were whole.
//
// FD ownership: FDs reachable from the returned data belong to the caller. Any
// map FD this call opened that no returned program references is closed before
// returning.
func (b *bpfSDKClient) RecoverAllBpfProgramsAndMaps() (map[string]BpfData, error) {
	_, err := os.Stat(constdef.BPF_DIR_MNT)
	if err != nil {
		log.Infof("BPF FS directory is not present")
		return nil, fmt.Errorf("eBPF FS directory is not present: %w", err)
	}

	var statfs syscall.Statfs_t

	//Pass DS here
	loadedPrograms := make(map[string]BpfData)
	mapIDsToNames := make(map[int]string)
	mapPodSelector := make(map[string]map[int]string)
	mapIDsToFDs := make(map[int]int)

	// mapIDsToFDs contains handles opened during this recovery attempt. Close all FDs which were not
	// recovered in the loadedPrograms map

	defer func() {
		returnedMapIDs := make(map[int]struct{})

		for _, bpfData := range loadedPrograms {
			for _, bpfMap := range bpfData.Maps {
				returnedMapIDs[int(bpfMap.MapID)] = struct{}{}
			}
		}

		for mapID, mapFD := range mapIDsToFDs {
			if _, returned := returnedMapIDs[mapID]; returned {
				continue
			}

			log.Infof("Closing non recovered map FD %d for map ID %d", mapFD, mapID)

			if err := unix.Close(mapFD); err != nil {
				log.Errorf(
					"Failed to close non recovered map FD %d for map ID %d: %v",
					mapFD, mapID, err,
				)
			}
		}
	}()

	mapsDirExists := true
	progsDirExists := true
	_, err = os.Stat(constdef.MAP_BPF_FS)
	if err != nil {
		mapsDirExists = false
	}

	_, err = os.Stat(constdef.PROG_BPF_FS)
	if err != nil {
		progsDirExists = false
	}

	// recoveryErrs collects per-pin failures. A pin we cannot read costs only the
	// workload that owns it, so the walk continues and the caller receives the
	// state we did rebuild alongside the list of what we could not.
	var recoveryErrs []error

	if err := syscall.Statfs(constdef.BPF_DIR_MNT, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		if mapsDirExists {
			if err := filepath.Walk(constdef.MAP_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					log.Errorf("Skipping map pin %s during recovery: %v", pinPath, err)
					recoveryErrs = append(recoveryErrs, fmt.Errorf("map pin %s: %w", pinPath, err))
					return nil
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - %s", pinPath)

					bpfMapInfo, err := b.mapApi.GetMapFromPinPath(pinPath)
					if err != nil {
						log.Errorf("Skipping map pin %s, unable to get mapInfo: %v", pinPath, err)
						recoveryErrs = append(recoveryErrs, fmt.Errorf("map pin %s: unable to get mapInfo: %w", pinPath, err))
						return nil
					}
					mapID := bpfMapInfo.Id
					log.Infof("Got ID %d", mapID)
					//Get map name
					mapName, mapNamespace, err := b.GetMapNameFromBPFPinPath(pinPath)
					if err != nil {
						// Unparseable pin filename. Skip it rather than
						// registering an empty name against this map ID. The
						// parser does not log - this walk owns the reporting, so
						// the reason is named once here and once in recoveryErrs.
						log.Errorf("Skipping map pin %s: %v", pinPath, err)
						recoveryErrs = append(recoveryErrs, err)
						return nil
					}
					mapIDsToNames[int(mapID)] = mapName

					if b.isGlobalMap(mapName) {
						// Global maps carry no per-workload FD here; programs
						// resolve them through sdkCache, populated by
						// RecoverGlobalMaps.
						return nil
					}
					if !b.isNamespacedMap(mapName) {
						// Classified as neither global nor namespaced. The load
						// path (loadMap) treats such a name as global and caches
						// it, while this walk and GetMapNameFromBPFPinPath treat
						// it as neither - so the two disagree about the same map.
						// That only happens when Config omits the name from both
						// lists, which is a configuration error; surface it
						// instead of skipping silently.
						log.Errorf("map pin %s: map %q is in neither Config.NamespacedMaps nor Config.GlobalMaps; programs referencing it cannot be recovered", pinPath, mapName)
						recoveryErrs = append(recoveryErrs, fmt.Errorf("map pin %s: map %q is in neither NamespacedMaps nor GlobalMaps", pinPath, mapName))
						return nil
					}
					//Fill New FD since old FDs will be deleted on recovery
					mapFD, err := utils.GetMapFDFromID(int(mapID))
					if err != nil {
						log.Errorf("Skipping map pin %s, unable to get FD from ID %d: %v", pinPath, int(mapID), err)
						recoveryErrs = append(recoveryErrs, fmt.Errorf("map pin %s: unable to get FD from ID %d: %w", pinPath, int(mapID), err))
						return nil
					}
					log.Infof("Got FD %d", mapFD)
					mapIDsToFDs[int(mapID)] = mapFD

					log.Infof("Adding ID %d to name %s and NS %s", mapID, mapName, mapNamespace)
					mapPodSelector[mapNamespace] = mapIDsToNames
				}
				return nil
			}); err != nil {
				// NOTE: This branch is effectively dead code under normal operation:
				// the Walk callback above always returns nil (collecting per-pin
				// failures into recoveryErrs), so filepath.Walk only returns a non-nil
				// error if the root directory itself is unreadable.
				// This is kept so that it handles any unexpected errors that may occur
				// while walking the map directory.
				log.Errorf("Error walking bpf map directory: %v", err)
				return loadedPrograms, fmt.Errorf("failed walking the bpf directory: %w", err)
			}
		}

		if progsDirExists {
			if err := filepath.Walk(constdef.PROG_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					log.Errorf("Skipping prog pin %s during recovery: %v", pinPath, err)
					recoveryErrs = append(recoveryErrs, fmt.Errorf("prog pin %s: %w", pinPath, err))
					return nil
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - %s", pinPath)

					pgmData := ebpf_progs.BpfProgram{
						PinPath: pinPath,
					}
					progNamespace, _, isGlobal, err := b.GetProgIdentifierFromBPFPinPath(pinPath)
					if isGlobal {
						// The SDK never creates global programs, so reaching here
						// means either a foreign pin or - per the known limitation
						// on GetProgIdentifierFromBPFPinPath - a legacy pin for a
						// pod whose name begins with the global prefix. The latter
						// is a pod we are silently failing to recover, so log at
						// error: the same pod's map pin is reported through
						// ErrPartialRecovery, and this path should not be the one
						// place that leaves no trace.
						log.Errorf("Skipping prog pin %s classified as global; the SDK creates no global programs, so this is a foreign pin or a legacy pin for a pod named %q*", pinPath, b.globalPinPrefix)
						return nil
					}
					if err != nil {
						// Unparseable pin filename - see the map-walk note above.
						log.Errorf("Skipping prog pin %s: %v", pinPath, err)
						recoveryErrs = append(recoveryErrs, err)
						return nil
					}

					bpfProgInfo, progFD, err := (b.progApi).GetProgFromPinPath(pinPath)
					if err != nil {
						log.Errorf("Skipping prog pin %s, unable to get progInfo: %v", pinPath, err)
						recoveryErrs = append(recoveryErrs, fmt.Errorf("prog pin %s: unable to get progInfo: %w", pinPath, err))
						return nil
					}
					pgmData.ProgFD = progFD

					recoveredMapData := make(map[string]ebpf_maps.BpfMap)
					if bpfProgInfo.NrMapIDs > 0 {
						log.Infof("Have associated maps to link")
						associatedBpfMapList, associatedBPFMapIDs, err := ebpf_progs.BpfGetMapInfoFromProgInfo(progFD, bpfProgInfo.NrMapIDs)
						if err != nil {
							log.Errorf("Skipping prog pin %s, unable to get associated maps: %v", pinPath, err)
							recoveryErrs = append(recoveryErrs, fmt.Errorf("prog pin %s: unable to get associated maps: %w", pinPath, err))
							// The program is not going into loadedPrograms, so nothing
							// will own this FD. The pin keeps the program alive in the
							// kernel, so closing only releases our handle.
							unix.Close(progFD)
							return nil
						}
						for mapInfoIdx := 0; mapInfoIdx < len(associatedBpfMapList); mapInfoIdx++ {
							bpfMapInfo := associatedBpfMapList[mapInfoIdx]
							newMapID := associatedBPFMapIDs[mapInfoIdx]
							recoveredBpfMap := ebpf_maps.BpfMap{}

							//Fill BPF map
							recoveredBpfMap.MapID = uint32(newMapID)

							mapIds, ok := mapPodSelector[progNamespace]
							if !ok {
								// None of this workload's map pins were recovered, so we
								// have no name to key its maps under. Drop the whole
								// program rather than returning it with an incomplete
								// Maps set: callers gate on Program.ProgFD alone, so a
								// partially-populated program is reused as if it were
								// whole and its missing maps read back zero-valued.
								// Omitting it makes the caller reload from scratch.
								log.Errorf("prog pin %s: no recovered maps for %s, dropping program", pinPath, progNamespace)
								recoveryErrs = append(recoveryErrs, fmt.Errorf("prog pin %s: no recovered maps for %s", pinPath, progNamespace))
								unix.Close(progFD)
								return nil
							}
							mapName, ok := mapIds[int(recoveredBpfMap.MapID)]
							if !ok {
								// This workload has recovered map pins, but not the one
								// this program references - so we have no name to key it
								// under. Same reasoning as the branch above: a program
								// returned with an incomplete Maps set is reused as if it
								// were whole, so drop it and let the caller reload.
								//
								// The FD lookup below would also fail here (mapIDsToNames
								// is always written before mapIDsToFDs, so a missing name
								// implies a missing FD), but checking explicitly keeps the
								// error message accurate instead of reporting an empty
								// map name.
								log.Errorf("prog pin %s: no recovered map for %s with map ID %d, dropping program", pinPath, progNamespace, int(newMapID))
								recoveryErrs = append(recoveryErrs, fmt.Errorf("prog pin %s: no recovered map for %s with map ID %d", pinPath, progNamespace, int(newMapID)))
								unix.Close(progFD)
								return nil
							}

							var mapFD int
							//Check in global cache for global maps
							globalMapFd, ok := sdkCache.Get(mapName)
							if ok {
								log.Infof("Found FD %d in SDK cache", globalMapFd)
								mapFD = globalMapFd
							} else {
								//Fill New FD since old FDs will be deleted on recovery
								localMapFD, ok := mapIDsToFDs[int(newMapID)]
								if !ok {
									// Same reasoning as above: a program whose maps we
									// cannot fully resolve is worse than no program, so
									// drop it and let the caller reload.
									log.Errorf("prog pin %s: unable to get FD from map ID %d (%s), dropping program", pinPath, int(newMapID), mapName)
									recoveryErrs = append(recoveryErrs, fmt.Errorf("prog pin %s: unable to get FD from map ID %d (%s)", pinPath, int(newMapID), mapName))
									unix.Close(progFD)
									return nil
								}
								mapFD = localMapFD
							}
							recoveredBpfMap.MapFD = uint32(mapFD)

							log.Infof("Mapinfo MapName - %v", bpfMapInfo.Name)
							//Fill BPF map metadata
							recoveredBpfMapMetaData := ebpf_maps.CreateEBPFMapInput{
								Type:       bpfMapInfo.Type,
								KeySize:    bpfMapInfo.KeySize,
								ValueSize:  bpfMapInfo.ValueSize,
								MaxEntries: bpfMapInfo.MaxEntries,
								Flags:      bpfMapInfo.MapFlags,
								Name:       mapName,
							}
							recoveredBpfMap.MapMetaData = recoveredBpfMapMetaData
							recoveredMapData[mapName] = recoveredBpfMap
						}

					}
					recoveredBPFdata := BpfData{
						Program: pgmData,
						Maps:    recoveredMapData,
					}
					loadedPrograms[pinPath] = recoveredBPFdata
				}
				return nil
			}); err != nil {
				// NOTE: Same as the map-walk branch above — effectively dead code
				// because the callback always returns nil. Only triggers if the
				// programs directory itself becomes unreadable mid-walk.
				log.Errorf("Error walking bpf prog directory: %v", err)
				return loadedPrograms, fmt.Errorf("failed walking the bpf directory: %w", err)
			}
		}
	} else {
		log.Infof("error checking BPF FS, please make sure it is mounted %v", err)
		return nil, fmt.Errorf("error checking BPF FS, please make sure it is mounted")
	}

	if len(recoveryErrs) > 0 {
		// Partial recovery: loadedPrograms holds everything we could rebuild. The
		// caller must treat a non-nil error with a non-empty result as incomplete
		// rather than as total failure.
		return loadedPrograms, fmt.Errorf("%w: %d pin(s) skipped: %w",
			ErrPartialRecovery, len(recoveryErrs), errors.Join(recoveryErrs...))
	}

	//Return DS here
	return loadedPrograms, nil
}

// GetAllBpfProgramsAndMaps walks the BPF filesystem and returns a read-only
// listing of the per-pod programs and maps pinned there, keyed by program pin
// path. Unlike RecoverAllBpfProgramsAndMaps this is for inspection only: it
// hands back no file descriptors - Program.ProgID is set, Program.ProgFD is
// not, and every Map.MapFD is zero - and it closes every descriptor it opens
// before returning.
//
// Partial by design, with the same contract as RecoverAllBpfProgramsAndMaps: a
// pin it cannot read or parse is skipped, and the call returns a NON-NIL error
// wrapping ErrPartialRecovery TOGETHER WITH a usable result. Callers MUST test
// errors.Is(err, ErrPartialRecovery) rather than treating a non-nil error as
// total failure.
//
// Because the result carries no FDs, a program whose maps cannot all be
// resolved is still listed, with the unresolved maps omitted - the opposite of
// the recovery path, which drops such a program.
func (b *bpfSDKClient) GetAllBpfProgramsAndMaps() (map[string]BpfData, error) {
	_, err := os.Stat(constdef.BPF_DIR_MNT)
	if err != nil {
		log.Infof("BPF FS directory is not present")
		return nil, fmt.Errorf("eBPF FS directory is not present: %w", err)
	}

	var statfs syscall.Statfs_t

	//Pass DS here
	loadedPrograms := make(map[string]BpfData)
	mapIDsToNames := make(map[int]string)
	mapPodSelector := make(map[string]map[int]string)

	mapsDirExists := true
	progsDirExists := true
	_, err = os.Stat(constdef.MAP_BPF_FS)
	if err != nil {
		mapsDirExists = false
	}

	_, err = os.Stat(constdef.PROG_BPF_FS)
	if err != nil {
		progsDirExists = false
	}

	// walkErrs collects per-pin failures so one unreadable pin does not cost the
	// whole listing.
	var walkErrs []error

	if err := syscall.Statfs(constdef.BPF_DIR_MNT, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		if mapsDirExists {
			if err := filepath.Walk(constdef.MAP_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					log.Errorf("Skipping map pin %s: %v", pinPath, err)
					walkErrs = append(walkErrs, fmt.Errorf("map pin %s: %w", pinPath, err))
					return nil
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - %s", pinPath)

					bpfMapInfo, err := b.mapApi.GetMapFromPinPath(pinPath)
					if err != nil {
						log.Errorf("Skipping map pin %s, unable to get mapInfo: %v", pinPath, err)
						walkErrs = append(walkErrs, fmt.Errorf("map pin %s: unable to get mapInfo: %w", pinPath, err))
						return nil
					}
					mapID := bpfMapInfo.Id
					log.Infof("Got ID %d", mapID)
					//Get map name
					mapName, mapNamespace, err := b.GetMapNameFromBPFPinPath(pinPath)
					if err != nil {
						// Unparseable pin filename. Skip it rather than
						// registering an empty name against this map ID. The
						// parser does not log - this walk owns the reporting.
						log.Errorf("Skipping map pin %s: %v", pinPath, err)
						walkErrs = append(walkErrs, err)
						return nil
					}
					mapIDsToNames[int(mapID)] = mapName

					log.Infof("Adding ID %d to name %s and NS %s", mapID, mapName, mapNamespace)
					mapPodSelector[mapNamespace] = mapIDsToNames
				}
				return nil
			}); err != nil {
				// NOTE: Effectively dead code — the Walk callback always returns nil,
				// collecting per-pin failures into walkErrs. Only triggers if the
				// maps directory itself becomes unreadable mid-walk.
				log.Errorf("Error walking bpf map directory: %v", err)
				return loadedPrograms, fmt.Errorf("failed walking the bpf directory: %w", err)
			}
		}

		if progsDirExists {
			if err := filepath.Walk(constdef.PROG_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					log.Errorf("Skipping prog pin %s: %v", pinPath, err)
					walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: %w", pinPath, err))
					return nil
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - %s", pinPath)

					pgmData := ebpf_progs.BpfProgram{
						PinPath: pinPath,
					}
					mapNamespace, _, isGlobal, err := b.GetProgIdentifierFromBPFPinPath(pinPath)
					if isGlobal {
						// Same reasoning as the recovery walk: a pin classified
						// global here is either foreign or a legacy pin for a pod
						// named "<globalPinPrefix>*", and the latter is a pod
						// missing from this listing with no other signal.
						log.Errorf("Skipping prog pin %s classified as global; the SDK creates no global programs, so this is a foreign pin or a legacy pin for a pod named %q*", pinPath, b.globalPinPrefix)
						return nil
					}
					if err != nil {
						// Unparseable pin filename - see the map-walk note above.
						log.Errorf("Skipping prog pin %s: %v", pinPath, err)
						walkErrs = append(walkErrs, err)
						return nil
					}

					bpfProgInfo, progFD, err := (b.progApi).GetProgFromPinPath(pinPath)
					if err != nil {
						log.Errorf("Skipping prog pin %s, unable to get progInfo: %v", pinPath, err)
						walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: unable to get progInfo: %w", pinPath, err))
						return nil
					}
					// This listing reports ProgID only and never hands an FD back to
					// the caller, so our handle must be closed on every path out of
					// this callback - including the NrMapIDs == 0 path below, which
					// skips the block that used to own the only close. The pin keeps
					// the program alive in the kernel, so this releases just our
					// handle.
					defer func() {
						if closeErr := unix.Close(progFD); closeErr != nil {
							log.Errorf("prog pin %s: failed to close prog FD %d: %v", pinPath, progFD, closeErr)
						}
					}()

					pgmData.ProgID = int(bpfProgInfo.ID)
					//Conv type to string here

					recoveredMapData := make(map[string]ebpf_maps.BpfMap)
					if bpfProgInfo.NrMapIDs > 0 {
						log.Infof("Have associated maps to link")
						associatedBpfMapList, associatedBPFMapIDs, err := ebpf_progs.BpfGetMapInfoFromProgInfo(progFD, bpfProgInfo.NrMapIDs)
						if err != nil {
							log.Errorf("Skipping prog pin %s, unable to get associated maps: %v", pinPath, err)
							walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: unable to get associated maps: %w", pinPath, err))
							return nil
						}
						for mapInfoIdx := 0; mapInfoIdx < len(associatedBpfMapList); mapInfoIdx++ {
							bpfMapInfo := associatedBpfMapList[mapInfoIdx]
							newMapID := associatedBPFMapIDs[mapInfoIdx]
							recoveredBpfMap := ebpf_maps.BpfMap{}

							//Fill BPF map
							recoveredBpfMap.MapID = uint32(newMapID)

							mapIds, ok := mapPodSelector[mapNamespace]
							if !ok {
								// No map pins recovered for this workload, so we have no
								// name to key its maps under. Unlike the recovery path, this
								// listing carries no FDs (MapFD is set to 0 below) and callers
								// read only Program.ProgID or print it, so keep the program
								// with the maps that did resolve rather than omitting it.
								log.Errorf("prog pin %s: no recovered maps for %s, omitting map ID %d from listing", pinPath, mapNamespace, int(newMapID))
								walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: no recovered maps for %s", pinPath, mapNamespace))
								continue
							}
							mapName, ok := mapIds[int(recoveredBpfMap.MapID)]
							if !ok {
								// Other map pins for this workload may have been recovered,
								// but this specific associated map was not. Omit it rather
								// than registering the map under an empty name.
								log.Errorf("prog pin %s: no recovered map for %s with map ID %d, omitting from listing", pinPath, mapNamespace, int(newMapID))
								walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: no recovered map for %s with map ID %d", pinPath, mapNamespace, int(newMapID)))
								continue
							}

							recoveredBpfMap.MapFD = 0

							log.Infof("Mapinfo MapName - %v", bpfMapInfo.Name)
							//Fill BPF map metadata
							recoveredBpfMapMetaData := ebpf_maps.CreateEBPFMapInput{
								Type:       bpfMapInfo.Type,
								KeySize:    bpfMapInfo.KeySize,
								ValueSize:  bpfMapInfo.ValueSize,
								MaxEntries: bpfMapInfo.MaxEntries,
								Flags:      bpfMapInfo.MapFlags,
								Name:       mapName,
							}
							recoveredBpfMap.MapMetaData = recoveredBpfMapMetaData
							recoveredMapData[mapName] = recoveredBpfMap
						}

					}
					recoveredBPFdata := BpfData{
						Program: pgmData,
						Maps:    recoveredMapData,
					}
					loadedPrograms[pinPath] = recoveredBPFdata
				}
				return nil
			}); err != nil {
				// NOTE: Same as the map-walk branch above — effectively dead code
				// because the callback always returns nil. Only triggers if the
				// programs directory itself becomes unreadable mid-walk.
				log.Errorf("Error walking bpf prog directory: %v", err)
				return loadedPrograms, fmt.Errorf("failed walking the bpf directory: %w", err)
			}
		}
	} else {
		log.Infof("error checking BPF FS, please make sure it is mounted %v", err)
		return nil, fmt.Errorf("error checking BPF FS, please make sure it is mounted")
	}

	if len(walkErrs) > 0 {
		// Partial listing: loadedPrograms holds everything we could read.
		return loadedPrograms, fmt.Errorf("%w: %d pin(s) skipped: %w",
			ErrPartialRecovery, len(walkErrs), errors.Join(walkErrs...))
	}

	//Return DS here
	return loadedPrograms, nil
}
