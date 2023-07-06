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

package utils

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"golang.org/x/sys/unix"
)

const (
	// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
	BPF_MAP_TYPE_UNSPEC           = 0
	BPF_MAP_TYPE_HASH             = 1
	BPF_MAP_TYPE_ARRAY            = 2
	BPF_MAP_TYPE_PROG_ARRAY       = 3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4
	BPF_MAP_TYPE_PERCPU_HASH      = 5
	BPF_MAP_TYPE_PERCPU_ARRAY     = 6
	BPF_MAP_TYPE_STACK_TRACE      = 7
	BPF_MAP_TYPE_CGROUP_ARRAY     = 8
	BPF_MAP_TYPE_LRU_HASH         = 9
	BPF_MAP_TYPE_LRU_PERCPU_HASH  = 10
	BPF_MAP_TYPE_LPM_TRIE         = 11
	BPF_MAP_TYPE_ARRAY_OF_MAPS    = 12
	BPF_MAP_TYPE_HASH_OF_MAPS     = 13
	BPF_MAP_TYPE_DEVMAP           = 14

	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	BPF_MAP_CREATE         = 0
	BPF_MAP_LOOKUP_ELEM    = 1
	BPF_MAP_UPDATE_ELEM    = 2
	BPF_MAP_DELETE_ELEM    = 3
	BPF_MAP_GET_NEXT_KEY   = 4
	BPF_PROG_LOAD          = 5
	BPF_OBJ_PIN            = 6
	BPF_OBJ_GET            = 7
	BPF_PROG_ATTACH        = 8
	BPF_PROG_DETACH        = 9
	BPF_PROG_TEST_RUN      = 10
	BPF_PROG_GET_NEXT_ID   = 11
	BPF_MAP_GET_NEXT_ID    = 12
	BPF_PROG_GET_FD_BY_ID  = 13
	BPF_MAP_GET_FD_BY_ID   = 14
	BPF_OBJ_GET_INFO_BY_FD = 15

	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2

	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1

	// BPF MAP pinning
	PIN_NONE      = 0
	PIN_OBJECT_NS = 1
	PIN_GLOBAL_NS = 2
	PIN_CUSTOM_NS = 3

	BPF_DIR_MNT     = "/sys/fs/bpf/"
	BPF_DIR_GLOBALS = "globals"
	BPF_FS_MAGIC    = 0xcafe4a11

	BPFObjNameLen    = 16
	BPFProgInfoAlign = 8
	BPFTagSize       = 8

	/*
	 * C struct of bpf_ins is 8 bytes because of this -
	 * struct bpf_insn {
	 *	__u8	code;
	 * 	__u8	dst_reg:4;
	 *	__u8	src_reg:4;
	 * 	__s16	off;
	 * 	__s32	imm;
	 *	};
	 * while go struct will return 9 since we dont have bit fields hence we dec(1).
	 */
	PROG_BPF_FS = "/sys/fs/bpf/globals/aws/programs/"
	MAP_BPF_FS  = "/sys/fs/bpf/globals/aws/maps/"
)

type BPFInsn struct {
	Code   uint8 // Opcode
	DstReg uint8 // 4 bits: destination register, r0-r10
	SrcReg uint8 // 4 bits: source register, r0-r10
	Off    int16 // Signed offset
	Imm    int32 // Immediate constant
}

type BpfPin struct {
	Pathname  uintptr
	Fd        uint32
	FileFlags uint32
}

type BpfMapAttr struct {
	MapFD uint32
	pad0  [4]byte
	Key   uint64
	Value uint64 // union: value or next_key
	Flags uint64
}

func PinObject(objFD uint32, pinPath string) error {
	var log = logger.Get()

	if pinPath == "" {
		return nil
	}
	cPath := []byte(pinPath + "\x00")

	pinAttr := BpfPin{
		Fd:       uint32(objFD),
		Pathname: uintptr(unsafe.Pointer(&cPath[0])),
	}
	pinData := unsafe.Pointer(&pinAttr)
	pinDataSize := unsafe.Sizeof(pinAttr)

	log.Infof("Calling BPFsys for FD %d and Path %s", objFD, pinPath)

	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(BPF_OBJ_PIN),
		uintptr(pinData),
		uintptr(int(pinDataSize)),
	)
	if errno < 0 {
		log.Infof("Unable to pin map and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to pin map: %s", errno)
	}
	//TODO : might have to return FD for node agent
	log.Infof("Pin done with fd : %d and errno %d", ret, errno)
	return nil
}

func IsfileExists(fname string) bool {
	info, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func UnPinObject(pinPath string) error {
	var log = logger.Get()
	if pinPath == "" || !IsfileExists(pinPath) {
		log.Infof("PinPath is empty or file doesn't exist")
		return nil
	}

	err := os.Remove(pinPath)
	if err != nil {
		log.Infof("File remove failed ", pinPath)
		return err
	}

	return err
}

/*
 *
 *	struct { anonymous struct used by BPF_*_GET_*_ID
 *		union {
 *			__u32		start_id;
 *			__u32		prog_id;
 *			__u32		map_id;
 *			__u32		btf_id;
 *			__u32		link_id;
 *		};
 *		__u32		next_id;
 *		__u32		open_flags;
 *	};
 */

type BpfShowAttr struct {
	id         uint32
	next_id    uint32
	open_flags uint32
}

func GetMapFDFromID(mapID int) (int, error) {
	var log = logger.Get()
	attr := BpfShowAttr{
		id: uint32(mapID),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_GET_FD_BY_ID,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Failed to get Map FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	fd := int(ret)
	runtime.KeepAlive(fd)
	return fd, nil
}

func GetProgFDFromID(mapID int) (int, error) {
	var log = logger.Get()
	attr := BpfShowAttr{
		id: uint32(mapID),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		BPF_PROG_GET_FD_BY_ID,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Failed to get Map FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	fd := int(ret)
	runtime.KeepAlive(fd)
	return fd, nil
}

// Converts BPF instruction into bytes
func (b *BPFInsn) ConvertBPFInstructionToByteStream() []byte {
	res := make([]byte, 8)
	res[0] = b.Code
	res[1] = (b.SrcReg << 4) | (b.DstReg & 0x0f)
	binary.LittleEndian.PutUint16(res[2:], uint16(b.Off))
	binary.LittleEndian.PutUint32(res[4:], uint32(b.Imm))

	return res
}
