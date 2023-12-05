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

type BpfSDKClient interface {
	IncreaseRlimit() error
	LoadBpfFile(path, customizedPinPath string) (map[string]BpfData, map[string]ebpf_maps.BpfMap, error)
	RecoverGlobalMaps() (map[string]ebpf_maps.BpfMap, error)
	RecoverAllBpfProgramsAndMaps() (map[string]BpfData, error)
	GetAllBpfProgramsAndMaps() (map[string]BpfData, error)
}

type BpfData struct {
	Program ebpf_progs.BpfProgram       // Return the program
	Maps    map[string]ebpf_maps.BpfMap // List of associated maps
}

type bpfSDKClient struct {
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
	elfFile           *elf.File
	customizedPinPath string
	bpfMapApi         ebpf_maps.BpfMapAPIs
	bpfProgApi        ebpf_progs.BpfProgAPIs

	license         string
	mapSection      *elf.Section
	mapSectionIndex int

	reloSectionMap map[uint32]*elf.Section
	progSectionMap map[uint32]progEntry
}

func New() BpfSDKClient {
	return &bpfSDKClient{
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

func newElfLoader(elfFile *elf.File, bpfmapapi ebpf_maps.BpfMapAPIs, bpfprogapi ebpf_progs.BpfProgAPIs, customizedpinPath string) *elfLoader {
	elfloader := &elfLoader{
		elfFile:           elfFile,
		bpfMapApi:         bpfmapapi,
		bpfProgApi:        bpfprogapi,
		customizedPinPath: customizedpinPath,
		reloSectionMap:    make(map[uint32]*elf.Section),
		progSectionMap:    make(map[uint32]progEntry),
	}
	return elfloader
}

func (b *bpfSDKClient) LoadBpfFile(path, customizedPinPath string) (map[string]BpfData, map[string]ebpf_maps.BpfMap, error) {
	bpfFile, err := os.Open(path)
	if err != nil {
		log.Infof("LoadBpfFile failed to open")
		return nil, nil, err
	}
	defer bpfFile.Close()

	elfFile, err := elf.NewFile(bpfFile)
	if err != nil {
		return nil, nil, err
	}

	elfLoader := newElfLoader(elfFile, b.mapApi, b.progApi, customizedPinPath)

	bpfLoadedProg, bpfLoadedMaps, err := elfLoader.doLoadELF()
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
		mapInfo, err := (e.bpfMapApi).GetMapFromPinPath(pinPath)
		if err != nil {
			return nil, fmt.Errorf("map '%s' doesn't exist", mapNameStr)
		}
		mapID := uint32(mapInfo.Id)
		bpfMap.MapID = mapID

		programmedMaps[loadedMaps.Name] = bpfMap

		if IsMapGlobal(pinPath) {
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
		progFD, _ := e.bpfProgApi.LoadProg(pgmInput)
		if progFD == -1 {
			log.Infof("Failed to load prog")
			return nil, fmt.Errorf("failed to Load the prog")
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

func (e *elfLoader) parseMap() ([]ebpf_maps.CreateEBPFMapInput, error) {
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
		parsedMapData = append(parsedMapData, mapData)
	}
	return parsedMapData, nil
}

func (e *elfLoader) parseAndApplyRelocSection(progIndex uint32, loadedMaps map[string]ebpf_maps.BpfMap) ([]byte, map[int]string, error) {
	progEntry := e.progSectionMap[progIndex]
	reloSection := e.reloSectionMap[progIndex]

	data, err := progEntry.progSection.Data()
	if err != nil {
		return nil, nil, err
	}
	log.Infof("Loading Program with relocation section; Info:%v; Name: %s, Type: %s; Size: %v", reloSection.Info,
		reloSection.Name, reloSection.Type, reloSection.Size)

	relocationEntries, err := e.parseRelocationSection(reloSection, e.elfFile)
	if err != nil || len(relocationEntries) == 0 {
		return nil, nil, fmt.Errorf("unable to parse relocation entries....")
	}

	log.Infof("Applying Relocations..")
	associatedMaps := make(map[int]string)
	for _, relocationEntry := range relocationEntries {
		if relocationEntry.relOffset >= len(data) {
			return nil, nil, fmt.Errorf("invalid offset for the relocation entry %d", relocationEntry.relOffset)
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

		//Validate for Invalid BPF instructions
		if ebpfInstruction.Code != (unix.BPF_LD | unix.BPF_IMM | unix.BPF_DW) {
			return nil, nil, fmt.Errorf("invalid BPF instruction (at %d): %d",
				relocationEntry.relOffset, ebpfInstruction.Code)
		}

		// Point BPF instruction to the FD of the map referenced. Update the last 4 bytes of
		// instruction (immediate constant) with the map's FD.
		// BPF_MEM | <size> | BPF_STX:  *(size *) (dst_reg + off) = src_reg
		// BPF_MEM | <size> | BPF_ST:   *(size *) (dst_reg + off) = imm32
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

func (e *elfLoader) parseProg(loadedMaps map[string]ebpf_maps.BpfMap) (map[string]ebpf_progs.CreateEBPFProgInput, error) {
	//Get prog data
	var pgmList = make(map[string]ebpf_progs.CreateEBPFProgInput)

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
			progData, associatedMaps, err := e.parseAndApplyRelocSection(progIndex, loadedMaps)
			if err != nil {
				return nil, fmt.Errorf("failed to apply relocation: %v", err)
			}
			//Replace data with relocated data
			data = progData
			linkedMaps = associatedMaps
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
						dataEnd := dataStart + progSize
						programData := make([]byte, progSize)
						copy(programData, data[dataStart:dataEnd])

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

func (e *elfLoader) doLoadELF() (map[string]BpfData, map[string]ebpf_maps.BpfMap, error) {
	var err error

	//Parse all sections
	if err := e.parseSection(); err != nil {
		return nil, nil, fmt.Errorf("failed to parse sections in elf file")
	}

	//Parse Map
	parsedMapData, err := e.parseMap()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse maps")
	}

	//Load Map
	loadedMapData, err := e.loadMap(parsedMapData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load maps")
	}

	//Parse Prog, need to pass loadedMapData for applying relocation
	parsedProgData, err := e.parseProg(loadedMapData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse prog")
	}

	//Load prog
	loadedProgData, err := e.loadProg(parsedProgData, loadedMapData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load progs")
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

func GetMapNameFromBPFPinPath(pinPath string) (string, string) {

	splitedPinPath := strings.Split(pinPath, "/")
	podIdentifier := strings.SplitN(splitedPinPath[len(splitedPinPath)-1], "_", 2)
	log.Infof("Found Identified - %s : %s", podIdentifier[0], podIdentifier[1])

	mapNamespace := podIdentifier[0]
	mapName := podIdentifier[1]

	log.Infof("Found ->  ", mapNamespace, mapName)

	directionIdentifier := strings.Split(splitedPinPath[len(splitedPinPath)-1], "_")
	direction := directionIdentifier[1]

	if direction == "ingress" {
		log.Infof("Adding ingress_map -> ", mapNamespace)
		return "ingress_map", mapNamespace
	} else if direction == "egress" {
		log.Infof("Adding egress_map -> ", mapNamespace)
		return "egress_map", mapNamespace
	}

	//This is global map, we cannot use global since there are multiple maps
	log.Infof("Adding GLOBAL %s -> %s", mapName, mapName)
	return mapName, mapName
}

func IsMapGlobal(pinPath string) bool {
	mapName, _ := GetMapNameFromBPFPinPath(pinPath)
	if mapName == "ingress_map" || mapName == "egress_map" {
		return false
	}
	return true
}

func (b *bpfSDKClient) RecoverGlobalMaps() (map[string]ebpf_maps.BpfMap, error) {
	_, err := os.Stat(constdef.BPF_DIR_MNT)
	if err != nil {
		log.Infof("BPF FS director is not present")
		return nil, fmt.Errorf("BPF directory is not present %v", err)
	}
	loadedGlobalMaps := make(map[string]ebpf_maps.BpfMap)
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(constdef.BPF_DIR_MNT, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		if err := filepath.Walk(constdef.MAP_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !fsinfo.IsDir() {
				log.Infof("Dumping pinpaths - ", pinPath)
				if IsMapGlobal(pinPath) {
					log.Infof("Found global pinpaths - ", pinPath)
					bpfMapInfo, err := b.mapApi.GetMapFromPinPath(pinPath)
					if err != nil {
						log.Errorf("error getting mapInfo for Global pin path, this shouldn't happen")
						return err
					}
					mapID := bpfMapInfo.Id
					log.Infof("Got ID %d", mapID)

					//Get map name
					mapName, _ := GetMapNameFromBPFPinPath(pinPath)

					log.Infof("Adding ID %d to name %s", mapID, mapName)

					recoveredBpfMap := ebpf_maps.BpfMap{}

					//Fill BPF map
					recoveredBpfMap.MapID = uint32(mapID)
					//Fill New FD since old FDs will be deleted on recovery
					mapFD, err := utils.GetMapFDFromID(int(mapID))
					if err != nil {
						log.Infof("Unable to GetFDfromID and ret %d and err %s", int(mapFD), err)
						return fmt.Errorf("unable to get FD: %s", err)
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
			log.Infof("Error walking bpf map directory:", err)
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

	if err := syscall.Statfs(constdef.BPF_DIR_MNT, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		if mapsDirExists {
			if err := filepath.Walk(constdef.MAP_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - ", pinPath)

					bpfMapInfo, err := b.mapApi.GetMapFromPinPath(pinPath)
					if err != nil {
						log.Infof("error getting mapInfo for pin path, this shouldn't happen")
						return err
					}
					mapID := bpfMapInfo.Id
					log.Infof("Got ID %d", mapID)
					//Get map name
					mapName, mapNamespace := GetMapNameFromBPFPinPath(pinPath)
					mapIDsToNames[int(mapID)] = mapName

					if IsMapGlobal(pinPath) {
						return nil
					}
					//Fill New FD since old FDs will be deleted on recovery
					mapFD, err := utils.GetMapFDFromID(int(mapID))
					if err != nil {
						log.Infof("Unable to GetFDfromID and ret %d and err %s", int(mapFD), err)
						return fmt.Errorf("unable to get FD: %s", err)
					}
					log.Infof("Got FD %d", mapFD)
					mapIDsToFDs[int(mapID)] = mapFD

					log.Infof("Adding ID %d to name %s and NS %s", mapID, mapName, mapNamespace)
					mapPodSelector[mapNamespace] = mapIDsToNames
				}
				return nil
			}); err != nil {
				log.Infof("Error walking bpf map directory:", err)
				return nil, fmt.Errorf("failed walking the bpfdirectory %v", err)
			}
		}

		if progsDirExists {
			if err := filepath.Walk(constdef.PROG_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - ", pinPath)

					pgmData := ebpf_progs.BpfProgram{
						PinPath: pinPath,
					}
					splitedPinPath := strings.Split(pinPath, "/")
					podIdentifier := strings.SplitN(splitedPinPath[len(splitedPinPath)-1], "_", 2)
					log.Infof("Found Identified - %s : %s", podIdentifier[0], podIdentifier[1])

					progNamespace := podIdentifier[0]

					bpfProgInfo, progFD, err := (b.progApi).GetProgFromPinPath(pinPath)
					if err != nil {
						log.Infof("Failed to progInfo for pinPath %s", pinPath)
						return err
					}
					pgmData.ProgFD = progFD

					recoveredMapData := make(map[string]ebpf_maps.BpfMap)
					if bpfProgInfo.NrMapIDs > 0 {
						log.Infof("Have associated maps to link")
						associatedBpfMapList, associatedBPFMapIDs, err := ebpf_progs.BpfGetMapInfoFromProgInfo(progFD, bpfProgInfo.NrMapIDs)
						if err != nil {
							log.Infof("Failed to get associated maps")
							return err
						}
						for mapInfoIdx := 0; mapInfoIdx < len(associatedBpfMapList); mapInfoIdx++ {
							bpfMapInfo := associatedBpfMapList[mapInfoIdx]
							newMapID := associatedBPFMapIDs[mapInfoIdx]
							recoveredBpfMap := ebpf_maps.BpfMap{}

							//Fill BPF map
							recoveredBpfMap.MapID = uint32(newMapID)

							mapIds, ok := mapPodSelector[progNamespace]
							if !ok {
								log.Infof("Failed to get ID for %s", progNamespace)
								return fmt.Errorf("failed to get err")
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
									log.Infof("Unable to get FD from ID %d", int(newMapID))
									return fmt.Errorf("unable to get FD")
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
				log.Infof("Error walking bpf prog directory:", err)
				return nil, fmt.Errorf("failed walking the bpfdirectory %v", err)
			}
		}
	} else {
		log.Infof("error checking BPF FS, please make sure it is mounted %v", err)
		return nil, fmt.Errorf("error checking BPF FS, please make sure it is mounted")
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

	if err := syscall.Statfs(constdef.BPF_DIR_MNT, &statfs); err == nil && statfs.Type == unix.BPF_FS_MAGIC {
		if mapsDirExists {
			if err := filepath.Walk(constdef.MAP_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - ", pinPath)

					bpfMapInfo, err := b.mapApi.GetMapFromPinPath(pinPath)
					if err != nil {
						log.Infof("error getting mapInfo for pin path, this shouldn't happen")
						return err
					}
					mapID := bpfMapInfo.Id
					log.Infof("Got ID %d", mapID)
					//Get map name
					mapName, mapNamespace := GetMapNameFromBPFPinPath(pinPath)
					mapIDsToNames[int(mapID)] = mapName

					log.Infof("Adding ID %d to name %s and NS %s", mapID, mapName, mapNamespace)
					mapPodSelector[mapNamespace] = mapIDsToNames
				}
				return nil
			}); err != nil {
				log.Infof("Error walking bpfdirectory:", err)
				return nil, fmt.Errorf("failed walking the bpfdirectory %v", err)
			}
		}

		if progsDirExists {
			if err := filepath.Walk(constdef.PROG_BPF_FS, func(pinPath string, fsinfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !fsinfo.IsDir() {
					log.Infof("Dumping pinpaths - ", pinPath)

					pgmData := ebpf_progs.BpfProgram{
						PinPath: pinPath,
					}
					splitedPinPath := strings.Split(pinPath, "/")
					podIdentifier := strings.SplitN(splitedPinPath[len(splitedPinPath)-1], "_", 2)
					log.Infof("Found Identified - %s : %s", podIdentifier[0], podIdentifier[1])

					mapNamespace := podIdentifier[0]
					if mapNamespace == "global" {
						log.Infof("Skipping global progs")
						return nil
					}

					bpfProgInfo, progFD, err := (b.progApi).GetProgFromPinPath(pinPath)
					if err != nil {
						log.Infof("Failed to progInfo for pinPath %s", pinPath)
						return err
					}
					pgmData.ProgID = int(bpfProgInfo.ID)
					//Conv type to string here

					recoveredMapData := make(map[string]ebpf_maps.BpfMap)
					if bpfProgInfo.NrMapIDs > 0 {
						log.Infof("Have associated maps to link")
						associatedBpfMapList, associatedBPFMapIDs, err := ebpf_progs.BpfGetMapInfoFromProgInfo(progFD, bpfProgInfo.NrMapIDs)
						if err != nil {
							log.Infof("Failed to get associated maps")
							return err
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
								log.Infof("Failed to ID for %s", mapNamespace)
								return fmt.Errorf("failed to get err")
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
				log.Infof("Error walking bpfdirectory:", err)
				return nil, fmt.Errorf("failed walking the bpfdirectory %v", err)
			}
		}
	} else {
		log.Infof("error checking BPF FS, please make sure it is mounted %v", err)
		return nil, fmt.Errorf("error checking BPF FS, please make sure it is mounted")
	}
	//Return DS here
	return loadedPrograms, nil
}
