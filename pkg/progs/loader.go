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

package progs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type BpfProgAPIs interface {
	PinProg(progFD uint32, pinPath string) error
	UnPinProg(pinPath string) error
	LoadProg(progMetaData CreateEBPFProgInput) (int, error)
	BpfGetProgFromPinPath(pinPath string) (BpfProgInfo, int, error)
	GetBPFProgAssociatedMapsIDs(progFD int) ([]uint32, error)
}

var log = logger.Get()

type CreateEBPFProgInput struct {
	ProgType       string
	SubSystem      string
	SubProgType    string
	ProgData       []byte
	LicenseStr     string
	PinPath        string
	InsDefSize     int
	AssociatedMaps map[int]string
}

type BpfProgram struct {
	// return program name, prog FD and pinPath
	ProgID      int
	ProgFD      int
	PinPath     string
	ProgType    string
	SubSystem   string
	SubProgType string
}

type BpfProgInfo struct {
	Type                 uint32
	ID                   uint32
	Tag                  [constdef.BPFTagSize]byte
	JitedProgLen         uint32
	XlatedProgLen        uint32
	JitedProgInsns       uint64
	XlatedProgInsns      uint64
	LoadTime             int64
	CreatedByUID         uint32
	NrMapIDs             uint32
	MapIDs               uint64
	Name                 [constdef.BPFObjNameLen]byte
	IfIndex              uint32
	GPLCompatible        uint32 `strcut:"bitfield"`
	Pad                  uint32 `strcut:"pad"`
	NetnsDev             uint64
	NetnsIno             uint64
	NrJitedKsyms         uint32
	NrJitedFuncLens      uint32
	JitedKsyms           uint64
	JitedFuncLens        uint64
	BTFID                uint32
	FuncInfoRecSize      uint32
	FuncInfo             uint64
	NrFuncInfo           uint32
	NrLineInfo           uint32
	LineInfo             uint64
	JitedLineInfo        uint64
	NrJitedLineInfo      uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
	NrProgTags           uint32
	ProgTags             uint64
	RunTimeNS            uint64
	RunCnt               uint64
}

type BpfProgAttr struct {
	prog_id    uint32
	next_id    uint32
	open_flags uint32
}

/*
 * struct { anonymous struct used by BPF_OBJ_GET_INFO_BY_FD
 *	__u32		bpf_fd;
 *	__u32		info_len;
 *	__aligned_u64	info;
 * } info;
*
*/
type BpfObjGetInfo struct {
	bpf_fd   uint32
	info_len uint32
	info     uintptr
}

/*
 *	struct { anonymous struct used by BPF_OBJ_* commands
 *	__aligned_u64	pathname;
 *	__u32		bpf_fd;
 *	__u32		file_flags;
 * };
 */
type BpfObjGet struct {
	pathname   uintptr
	bpf_fd     uint32
	file_flags uint32
}

func MountBpfFS() error {
	log.Infof("Let's mount BPF FS")
	err := syscall.Mount("bpf", constdef.BPF_DIR_MNT, "bpf", 0, "mode=0700")
	if err != nil {
		log.Errorf("error mounting bpffs: %v", err)
	}
	return err
}

func (m *BpfProgram) PinProg(progFD uint32, pinPath string) error {

	var err error
	if utils.IsfileExists(pinPath) {
		log.Infof("Found file %s so deleting the path", pinPath)
		err = utils.UnPinObject(pinPath)
		if err != nil {
			log.Errorf("failed to UnPinObject during pinning")
			return err
		}
	}

	err = os.MkdirAll(filepath.Dir(pinPath), 0755)
	if err != nil {
		log.Infof("error creating directory %q: %v", filepath.Dir(pinPath), err)
		return fmt.Errorf("error creating directory %q: %v", filepath.Dir(pinPath), err)
	}
	_, err = os.Stat(pinPath)
	if err == nil {
		log.Infof("aborting, found file at %q", pinPath)
		return fmt.Errorf("aborting, found file at %q", pinPath)
	}
	if err != nil && !os.IsNotExist(err) {
		log.Infof("failed to stat %q: %v", pinPath, err)
		return fmt.Errorf("failed to stat %q: %v", pinPath, err)
	}

	return utils.PinObject(progFD, pinPath)
}

func (m *BpfProgram) UnPinProg(pinPath string) error {
	err := utils.UnPinObject(pinPath)
	if err != nil {
		log.Errorf("failed to unpin prog")
		return err
	}
	if m.ProgFD <= 0 {
		log.Errorf("map FD is invalid or closed %d", m.ProgFD)
		return nil
	}
	return unix.Close(int(m.ProgFD))
}

func (m *BpfProgram) LoadProg(progMetaData CreateEBPFProgInput) (int, error) {

	var prog_type uint32
	switch progMetaData.ProgType {
	case "xdp":
		prog_type = uint32(netlink.BPF_PROG_TYPE_XDP)
	case "tc_cls":
		prog_type = uint32(netlink.BPF_PROG_TYPE_SCHED_CLS)
	case "tc_act":
		prog_type = uint32(netlink.BPF_PROG_TYPE_SCHED_ACT)
	case "kprobe":
		prog_type = uint32(netlink.BPF_PROG_TYPE_KPROBE)
	case "kretprobe":
		prog_type = uint32(netlink.BPF_PROG_TYPE_KPROBE)
	case "tracepoint":
		prog_type = uint32(netlink.BPF_PROG_TYPE_TRACEPOINT)
	default:
		prog_type = uint32(netlink.BPF_PROG_TYPE_UNSPEC)
	}

	logBuf := make([]byte, 65535)
	program := netlink.BPFAttr{
		ProgType: prog_type,
		LogBuf:   uintptr(unsafe.Pointer(&logBuf[0])),
		LogSize:  uint32(cap(logBuf) - 1),
		LogLevel: 1,
	}

	program.Insns = uintptr(unsafe.Pointer(&progMetaData.ProgData[0]))
	program.InsnCnt = uint32(len(progMetaData.ProgData) / progMetaData.InsDefSize)

	license := []byte(progMetaData.LicenseStr)
	program.License = uintptr(unsafe.Pointer(&license[0]))

	fd, _, errno := unix.Syscall(unix.SYS_BPF,
		uintptr(constdef.BPF_PROG_LOAD),
		uintptr(unsafe.Pointer(&program)),
		unsafe.Sizeof(program))
	runtime.KeepAlive(progMetaData.ProgData)
	runtime.KeepAlive(license)

	log.Infof("Load prog done with fd : %d", int(fd))
	if errno != 0 {
		log.Errorf(string(logBuf))
		return -1, errno
	}

	//Pin the prog
	err := m.PinProg(uint32(fd), progMetaData.PinPath)
	if err != nil {
		log.Errorf("pin prog failed %v", err)
		return -1, err
	}
	return int(fd), nil
}

func (attr *BpfProgAttr) isBpfProgGetNextID() bool {
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(constdef.BPF_PROG_GET_NEXT_ID),
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Errorf("done get_next_id for Prog - ret %d and err %s", int(ret), errno)
		return false
	}

	attr.prog_id = attr.next_id
	return true
}

func (attr *BpfProgAttr) BpfProgGetFDbyID() (int, error) {
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(constdef.BPF_PROG_GET_FD_BY_ID),
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Errorf("failed to get Prog FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	return int(ret), nil
}

func (objattr *BpfObjGetInfo) BpfGetProgramInfoForFD() error {
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(constdef.BPF_OBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(objattr)),
		unsafe.Sizeof(*objattr),
	)
	if errno != 0 {
		log.Errorf("failed to get object info by FD - ret %d and err %s", int(ret), errno)
		return errno
	}
	return nil
}

func GetBPFprogInfo(progFD int) (BpfProgInfo, error) {
	var bpfProgInfo BpfProgInfo
	objInfo := BpfObjGetInfo{
		bpf_fd:   uint32(progFD),
		info_len: uint32(unsafe.Sizeof(bpfProgInfo)),
		info:     uintptr(unsafe.Pointer(&bpfProgInfo)),
	}

	err := objInfo.BpfGetProgramInfoForFD()
	if err != nil {
		log.Errorf("failed to get program Info for FD - ", progFD)
		return BpfProgInfo{}, err
	}

	log.Infof("TYPE - %d", bpfProgInfo.Type)
	log.Infof("Prog Name - %s", string(bpfProgInfo.Name[:]))
	log.Infof("Maps linked - %d", bpfProgInfo.NrMapIDs)

	return bpfProgInfo, nil
}

func (m *BpfProgram) GetBPFProgAssociatedMapsIDs(progFD int) ([]uint32, error) {
	bpfProgInfo, err := GetBPFprogInfo(progFD)

	if bpfProgInfo.NrMapIDs <= 0 {
		return nil, nil
	}
	numMaps := bpfProgInfo.NrMapIDs

	associatedMaps := make([]uint32, numMaps)
	newBpfProgInfo := BpfProgInfo{
		NrMapIDs: numMaps,
		MapIDs:   uint64(uintptr(unsafe.Pointer(&associatedMaps[0]))),
	}
	objInfo := BpfObjGetInfo{
		bpf_fd:   uint32(progFD),
		info_len: uint32(unsafe.Sizeof(newBpfProgInfo)),
		info:     uintptr(unsafe.Pointer(&newBpfProgInfo)),
	}

	err = objInfo.BpfGetProgramInfoForFD()
	if err != nil {
		log.Errorf("failed to get program Info for FD - ", progFD)
		return nil, err
	}
	return associatedMaps, nil
}

func BpfGetMapInfoFromProgInfo(progFD int, numMaps uint32) ([]ebpf_maps.BpfMapInfo, []int, error) {
	associatedMaps := make([]uint32, numMaps)
	newBpfProgInfo := BpfProgInfo{
		NrMapIDs: numMaps,
		MapIDs:   uint64(uintptr(unsafe.Pointer(&associatedMaps[0]))),
	}

	objInfo := BpfObjGetInfo{
		bpf_fd:   uint32(progFD),
		info_len: uint32(unsafe.Sizeof(newBpfProgInfo)),
		info:     uintptr(unsafe.Pointer(&newBpfProgInfo)),
	}

	err := objInfo.BpfGetProgramInfoForFD()
	if err != nil {
		log.Errorf("failed to get program Info for FD - ", progFD)
		return nil, nil, err
	}

	log.Infof("TYPE - %d", newBpfProgInfo.Type)
	log.Infof("Prog Name - %s", unix.ByteSliceToString(newBpfProgInfo.Name[:]))
	log.Infof("Maps linked - %d", newBpfProgInfo.NrMapIDs)
	//Printing associated maps
	loadedMaps := []ebpf_maps.BpfMapInfo{}
	loadedMapsIDs := make([]int, 0)
	for mapIdx := 0; mapIdx < len(associatedMaps); mapIdx++ {
		log.Infof("MAP ID - %d", associatedMaps[mapIdx])

		mapfd, err := utils.GetMapFDFromID(int(associatedMaps[mapIdx]))
		if err != nil {
			log.Errorf("failed to get map Info")
			return nil, nil, err
		}
		log.Infof("Creating temporary map FD - %d", mapfd)

		bpfMapInfo, err := ebpf_maps.GetBPFmapInfo(mapfd)
		if err != nil {
			log.Errorf("failed to get map Info for FD", mapfd)
			return nil, nil, err
		}

		log.Infof("Closing map FD %d", mapfd)
		unix.Close(mapfd)

		loadedMaps = append(loadedMaps, bpfMapInfo)
		loadedMapsIDs = append(loadedMapsIDs, int(associatedMaps[mapIdx]))
	}
	return loadedMaps, loadedMapsIDs, nil
}

func BpfGetAllProgramInfo() ([]BpfProgInfo, error) {
	loadedPrograms := []BpfProgInfo{}
	attr := BpfProgAttr{}
	log.Infof("In get all prog info")
	for attr.isBpfProgGetNextID() {
		log.Infof("Got ID - %d", attr.next_id)

		progfd, err := utils.GetProgFDFromID(int(attr.next_id))
		if err != nil {
			log.Errorf("failed to get program Info")
			return nil, err
		}
		log.Infof("Found prog FD - %d", progfd)
		bpfProgInfo, err := GetBPFprogInfo(progfd)
		if err != nil {
			log.Errorf("failed to get program Info for FD", progfd)
			return nil, err
		}
		unix.Close(progfd)

		loadedPrograms = append(loadedPrograms, bpfProgInfo)
	}
	log.Infof("Done all prog info!!!")
	return loadedPrograms, nil
}

func (attr *BpfObjGet) BpfGetObject() (int, error) {
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(constdef.BPF_OBJ_GET),
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Errorf("failed to get Prog FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	return int(ret), nil
}

func (m *BpfProgram) BpfGetProgFromPinPath(pinPath string) (BpfProgInfo, int, error) {
	log.Infof("Printing pinpath - %s ", pinPath)
	if len(pinPath) == 0 {
		return BpfProgInfo{}, -1, fmt.Errorf("invalid pinPath")
	}

	cPath := []byte(pinPath + "\x00")
	objInfo := BpfObjGet{
		pathname: uintptr(unsafe.Pointer(&cPath[0])),
	}

	progFD, err := objInfo.BpfGetObject()
	if err != nil {
		log.Errorf("failed to get object")
		return BpfProgInfo{}, -1, err

	}

	log.Infof("Got progFD - %d", progFD)
	bpfProgInfo, err := GetBPFprogInfo(progFD)
	if err != nil {
		log.Errorf("failed to get program Info for FD - %d", progFD)
		return bpfProgInfo, -1, err
	}

	return bpfProgInfo, progFD, nil
}
