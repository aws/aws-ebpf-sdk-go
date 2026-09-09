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
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/aws/aws-ebpf-sdk-go/pkg/cache"
	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
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

var log = logger.Get()
var sdkCache = cache.Get()

// ErrPartialRecovery is returned by RecoverAllBpfProgramsAndMaps (and
// GetAllBpfProgramsAndMaps) when some pins could not be rebuilt but others
// were
var ErrPartialRecovery = errors.New("partial recovery")

// Config carries SDK construction options.
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
	GetProgIdentifierFromBPFPinPath(pinPath string) (string, string, bool)
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
}

func New(cfg Config) BpfSDKClient {
	nsSet := make(map[string]struct{}, len(cfg.NamespacedMaps))
	for _, m := range cfg.NamespacedMaps {
		nsSet[m] = struct{}{}
	}
	globalSet := make(map[string]struct{}, len(cfg.GlobalMaps))
	for _, m := range cfg.GlobalMaps {
		globalSet[m] = struct{}{}
	}
	return &bpfSDKClient{
		mapClassifier: mapClassifier{
			namespacedMaps:  nsSet,
			globalMaps:      globalSet,
			globalPinPrefix: cfg.GlobalPinPrefix,
		},
		mapApi:  &ebpf_maps.BpfMap{},
		progApi: &ebpf_progs.BpfProgram{},
	}
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

		if e.IsMapGlobal(pinPath) {
			//Add to global cache
			sdkCache.Set(loadedMaps.Name, int(bpfMap.MapFD))
			log.Infof("Added map Name %s and FD %d to SDK cache", loadedMaps.Name, bpfMap.MapFD)
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

	relocationEntries, err := e.parseRelocationSection(reloSection, e.elfFile)
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
			ebpfInstruction.SrcReg = 1 // BPF_PSEUDO_CALL
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

func (e *elfLoader) doLoadELF(inputData BpfCustomData) (map[string]BpfData, map[string]ebpf_maps.BpfMap, error) {
	var err error

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
// Global pins are "global_<mapName>" and have no "@".
//
// A filename matching neither shape cannot be split unambiguously - for example
// a pre-"@" pin that the one-shot legacy migration did not rename. Rather than
// guess a boundary and register the map under a wrong name, both return values
// are empty so the caller skips it.
func (m *mapClassifier) GetMapNameFromBPFPinPath(pinPath string) (string, string) {
	splittedPinPath := strings.Split(pinPath, "/")
	pinnedMap := splittedPinPath[len(splittedPinPath)-1]

	if podName, rest, found := strings.Cut(pinnedMap, "@"); found {
		mapNamespace, mapName, ok := strings.Cut(rest, "_")
		if !ok {
			// This should not happen in the first place
			log.Errorf("Map pin %s has no map name after the namespace, skipping", pinnedMap)
			return "", ""
		}
		podIdentifier := podName + "@" + mapNamespace
		log.Infof("Adding %s -> %s", mapName, podIdentifier)
		return mapName, podIdentifier
	}

	// Global pins are "<globalPinPrefix>_<mapName>" where mapName is one of the
	// configured global maps. Matching the name exactly - rather than trusting the
	// prefix alone - keeps a pod whose name begins "global." from being mistaken
	// for a global pin if its pin was never migrated to the "@" format.
	if prefix, mapName, ok := strings.Cut(pinnedMap, "_"); ok && prefix == m.globalPinPrefix && m.isGlobalMap(mapName) {
		log.Infof("Adding GLOBAL %s -> %s", mapName, mapName)
		return mapName, mapName
	}

	log.Errorf("Unrecognized map pin format %s, skipping", pinnedMap)
	return "", ""
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
//     Returns ("<podName>@<namespace>", false).
//   - Global:    "<globalPinPrefix>_<progName>" (no "@"). Returns ("", true).
//     The SDK never creates global programs, so this only exists to let callers
//     skip such a pin if one is ever encountered.
//
// A filename matching neither shape returns ("", false) so the caller skips it
// rather than proceeding with a truncated identifier.
//
// Known limitation: a legacy pin (pre-"@" format) for a pod whose name begins
// with the global prefix (e.g. "global.foo") has no "@" and a first segment of
// "global", so it is classified as global and skipped rather than recovered.
// This is bounded - such pins are renamed to the "@" format by the one-shot
// migration in the agent - so it is accepted rather than special-cased here.
func (b *bpfSDKClient) GetProgIdentifierFromBPFPinPath(pinPath string) (podIdentifier string, progName string, isGlobal bool) {
	splittedPinPath := strings.Split(pinPath, "/")
	pinnedProg := splittedPinPath[len(splittedPinPath)-1]

	if podName, rest, found := strings.Cut(pinnedProg, "@"); found {
		progNamespace, progName, ok := strings.Cut(rest, "_")
		if !ok {
			log.Errorf("Prog pin %s has no prog name after the namespace, skipping", pinnedProg)
			return "", "", false
		}
		podIdentifier = podName + "@" + progNamespace
		log.Infof("Found Identified - %s : %s", podIdentifier, progName)
		return podIdentifier, progName, false
	}

	if prefix, progName, ok := strings.Cut(pinnedProg, "_"); ok && prefix == b.globalPinPrefix {
		return "", progName, true
	}

	log.Errorf("Unrecognized prog pin format %s, skipping", pinnedProg)
	return "", "", false
}

// IsMapGlobal reports whether the pin at pinPath is a node-wide map rather than
// a per-pod one. This is a positive check against the configured global map
// names: a name that is neither global nor namespaced - including the empty name
// returned for an unparseable pin - is not reported as global, so callers do not
// treat an unrecognized pin as one.
func (m *mapClassifier) IsMapGlobal(pinPath string) bool {
	mapName, _ := m.GetMapNameFromBPFPinPath(pinPath)
	return m.isGlobalMap(mapName)
}

// RecoverGlobalMaps walks the BPF filesystem and reconstructs a map of all
// node-wide (global) maps that were pinned there. It returns a map keyed by the
// pin path, with each value containing the map's ID, FD, and metadata.
//
// Fails fast: on the first unreadable global pin it returns a nil map and the
// error, because a partial global map set is unusable. This contrasts with
// RecoverAllBpfProgramsAndMaps which collects per-pin failures and returns
// everything it could rebuild alongside a non-nil ErrPartialRecovery error.
func (b *bpfSDKClient) RecoverGlobalMaps() (map[string]ebpf_maps.BpfMap, error) {
	_, err := os.Stat(constdef.BPF_DIR_MNT)
	if err != nil {
		log.Infof("BPF FS director is not present")
		return nil, fmt.Errorf("BPF directory is not present %v", err)
	}
	loadedGlobalMaps := make(map[string]ebpf_maps.BpfMap)
	// A global pin we cannot read is fatal: the conntrack and events maps are
	// node-wide and every pod program binds to them, so a partial global map set
	// is not usable. Fail fast on the first per-pin error rather than returning
	// an incomplete set - unlike RecoverAllBpfProgramsAndMaps, which is per-pod
	// and recovers partially.
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(constdef.BPF_DIR_MNT, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		if err := filepath.Walk(constdef.MAP_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !fsinfo.IsDir() {
				log.Infof("Dumping pinpaths - %s", pinPath)
				if b.IsMapGlobal(pinPath) {
					log.Infof("Found global pinpaths - %s", pinPath)
					bpfMapInfo, err := b.mapApi.GetMapFromPinPath(pinPath)
					if err != nil {
						log.Errorf("error getting mapInfo for Global pin path %s, this shouldn't happen", pinPath)
						return err
					}
					mapID := bpfMapInfo.Id
					log.Infof("Got ID %d", mapID)

					//Get map name
					mapName, _ := b.GetMapNameFromBPFPinPath(pinPath)

					log.Infof("Adding ID %d to name %s", mapID, mapName)

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
		}); err != nil {
			log.Errorf("Error walking bpf map directory: %v", err)
			return nil, fmt.Errorf("error walking the bpfdirectory %v", err)
		}
	} else {
		log.Infof("error checking BPF FS, please make sure it is mounted %v", err)
		return nil, fmt.Errorf("error checking BPF FS, please make sure it is mounted")
	}

	return loadedGlobalMaps, nil
}

func (b *bpfSDKClient) RecoverAllBpfProgramsAndMaps() (map[string]BpfData, error) {
	_, err := os.Stat(constdef.BPF_DIR_MNT)
	if err != nil {
		log.Infof("BPF FS directory is not present")
		return nil, fmt.Errorf("eBPF FS directory is not present %v", err)
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
					mapName, mapNamespace := b.GetMapNameFromBPFPinPath(pinPath)
					if mapName == "" {
						// Unparseable pin filename - already logged. Skip it rather
						// than registering an empty name against this map ID.
						recoveryErrs = append(recoveryErrs, fmt.Errorf("map pin %s: unrecognized pin format", pinPath))
						return nil
					}
					mapIDsToNames[int(mapID)] = mapName

					if b.isGlobalMap(mapName) || !b.isNamespacedMap(mapName) {
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
				return loadedPrograms, fmt.Errorf("failed walking the bpfdirectory %v", err)
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
					progNamespace, _, isGlobal := b.GetProgIdentifierFromBPFPinPath(pinPath)
					if isGlobal {
						log.Infof("Skipping global progs if any - %s", pinPath)
						return nil
					}
					if progNamespace == "" {
						// Unparseable pin filename - already logged.
						recoveryErrs = append(recoveryErrs, fmt.Errorf("prog pin %s: unrecognized pin format", pinPath))
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
							mapName := mapIds[int(recoveredBpfMap.MapID)]

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
				return loadedPrograms, fmt.Errorf("failed walking the bpfdirectory %v", err)
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

func (b *bpfSDKClient) GetAllBpfProgramsAndMaps() (map[string]BpfData, error) {
	_, err := os.Stat(constdef.BPF_DIR_MNT)
	if err != nil {
		log.Infof("BPF FS directory is not present")
		return nil, fmt.Errorf("eBPF FS directory is not present %v", err)
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
					mapName, mapNamespace := b.GetMapNameFromBPFPinPath(pinPath)
					if mapName == "" {
						// Unparseable pin filename - already logged. Skip it rather
						// than registering an empty name against this map ID.
						walkErrs = append(walkErrs, fmt.Errorf("map pin %s: unrecognized pin format", pinPath))
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
				return loadedPrograms, fmt.Errorf("failed walking the bpfdirectory %v", err)
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
					mapNamespace, _, isGlobal := b.GetProgIdentifierFromBPFPinPath(pinPath)
					if isGlobal {
						log.Infof("Skipping global progs")
						return nil
					}
					if mapNamespace == "" {
						// Unparseable pin filename - already logged.
						walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: unrecognized pin format", pinPath))
						return nil
					}

					bpfProgInfo, progFD, err := (b.progApi).GetProgFromPinPath(pinPath)
					if err != nil {
						log.Errorf("Skipping prog pin %s, unable to get progInfo: %v", pinPath, err)
						walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: unable to get progInfo: %w", pinPath, err))
						return nil
					}
					pgmData.ProgID = int(bpfProgInfo.ID)
					//Conv type to string here

					recoveredMapData := make(map[string]ebpf_maps.BpfMap)
					if bpfProgInfo.NrMapIDs > 0 {
						log.Infof("Have associated maps to link")
						associatedBpfMapList, associatedBPFMapIDs, err := ebpf_progs.BpfGetMapInfoFromProgInfo(progFD, bpfProgInfo.NrMapIDs)
						if err != nil {
							log.Errorf("Skipping prog pin %s, unable to get associated maps: %v", pinPath, err)
							walkErrs = append(walkErrs, fmt.Errorf("prog pin %s: unable to get associated maps: %w", pinPath, err))
							unix.Close(progFD)
							return nil
						}
						//Close progFD..we don't need it
						unix.Close(progFD)
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
							mapName := mapIds[int(recoveredBpfMap.MapID)]

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
				return loadedPrograms, fmt.Errorf("failed walking the bpfdirectory %v", err)
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
