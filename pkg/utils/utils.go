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
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"golang.org/x/sys/unix"
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
	_     [4]byte
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
		uintptr(constdef.BPF_OBJ_PIN),
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
	log := logger.Get()
	info, err := os.Stat(fname)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false
	case err != nil:
		log.Errorf("Error while checking file %s: %v", fname, err)
		return false
	default:
		return !info.IsDir()
	}
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
		uintptr(constdef.BPF_MAP_GET_FD_BY_ID),
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
		uintptr(constdef.BPF_PROG_GET_FD_BY_ID),
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

func Mount_bpf_fs() error {
	fmt.Println("Let's mount BPF FS")
	err := syscall.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "mode=0700")
	if err != nil {
		fmt.Println("error mounting bpffs")
	}
	return err
}

func Unmount_bpf_fs() error {
	fmt.Println("Let's unmount BPF FS")
	err := syscall.Unmount("/sys/fs/bpf", 0)
	if err != nil {
		fmt.Println("error unmounting bpffs")
	}
	return err
}

func GetLogBufferSize() int {
	return math.MaxUint32 >> 8
}
