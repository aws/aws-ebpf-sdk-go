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

package btf

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

// Kfunc is a kernel function resolved against the running kernel's BTF.
type Kfunc struct {
	// BTFID is the BTF_KIND_FUNC type ID, which goes in the call insn's imm.
	BTFID uint32
	// Module is the kernel module that defines the kfunc, or "" for vmlinux.
	Module string
	// ModuleBTFFD is an fd for the module's BTF object; it is unused for
	// vmlinux (Module == ""), since 0 is a valid fd. A module kfunc call must
	// reference this fd through BPF_PROG_LOAD's fd_array. The fd is owned by
	// the resolver and stays open.
	ModuleBTFFD int
}

// KfuncResolver resolves kfunc names to BTF IDs.
type KfuncResolver interface {
	ResolveKfuncs(names []string) (map[string]Kfunc, error)
}

var (
	kernelResolverOnce sync.Once
	kernelResolver     *kernelKfuncResolver
)

// KernelKfuncResolver returns the process-wide resolver for the running
// kernel. Results are cached, so the kernel's BTF is only walked the first
// time a name is requested. Module BTF fds stay open for the life of the
// process: if a module is unloaded and reloaded, programs that call its
// kfuncs fail to load until the process restarts.
func KernelKfuncResolver() KfuncResolver {
	kernelResolverOnce.Do(func() {
		kernelResolver = newKernelKfuncResolver()
	})
	return kernelResolver
}

func newKernelKfuncResolver() *kernelKfuncResolver {
	return &kernelKfuncResolver{
		cache:     make(map[string]Kfunc),
		moduleFDs: make(map[string]int),
	}
}

type kernelKfuncResolver struct {
	mu        sync.Mutex
	cache     map[string]Kfunc
	moduleFDs map[string]int
}

// ResolveKfuncs looks every name up in vmlinux BTF first and then in each
// loaded module's BTF. It fails if any name is not found.
func (r *kernelKfuncResolver) ResolveKfuncs(names []string) (map[string]Kfunc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Serve what we can from the cache. Walking kernel BTF means reading and
	// parsing several MB, so it is only done for names not seen before.
	result := make(map[string]Kfunc, len(names))
	var missing []string
	for _, name := range names {
		if kf, ok := r.cache[name]; ok {
			result[name] = kf
		} else {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return result, nil
	}

	objs, err := loadKernelBTF()
	if err != nil {
		return nil, err
	}
	// loadKernelBTF opened an fd for every BTF object. Keep only the module
	// fds that a cached Kfunc now refers to (BPF_PROG_LOAD needs them in
	// fd_array); close the rest, including vmlinux's, which kfunc calls into
	// vmlinux don't need.
	defer func() {
		for _, o := range objs {
			if kept, ok := r.moduleFDs[o.name]; o.fd >= 0 && (!ok || kept != o.fd) {
				unix.Close(o.fd)
			}
		}
	}()

	// vmlinux has to be parsed first, even when every kfunc lives in a
	// module: module BTF is split BTF, whose type IDs and string offsets
	// continue from the end of vmlinux BTF, so a module can't be parsed
	// without it. Without vmlinux BTF there are no kfuncs at all.
	var vmlinux *btfSpec
	for _, o := range objs {
		if o.name == "vmlinux" {
			vmlinux, err = parseBase(o.data)
			if err != nil {
				return nil, fmt.Errorf("parse vmlinux BTF: %w", err)
			}
			break
		}
	}
	if vmlinux == nil {
		return nil, errors.New("vmlinux BTF not found; kfuncs need CONFIG_DEBUG_INFO_BTF")
	}

	// Look in vmlinux first. A vmlinux kfunc has no module, so its call
	// needs no fd_array entry.
	for _, name := range missing {
		if id, err := vmlinux.findFunc(name); err == nil {
			r.cache[name] = Kfunc{BTFID: id}
		}
	}
	var unparsed []string
	// Then each module, until every name is found. Parsing a module is
	// skipped once nothing is left to look for.
	for _, o := range objs {
		if allCached(r.cache, missing) {
			break
		}
		if o.name == "vmlinux" {
			continue // already searched above
		}
		// A module whose BTF fails to parse can't be searched, but the
		// kfuncs may be in another module, so keep going. If a name is never
		// found, the error below names the modules that were skipped.
		mod, err := parseSplit(o.data, vmlinux)
		if err != nil {
			log.Infof("skipping BTF of module %s: %v", o.name, err)
			unparsed = append(unparsed, fmt.Sprintf("%s (%v)", o.name, err))
			continue
		}
		for _, name := range missing {
			if _, ok := r.cache[name]; ok {
				continue // found in vmlinux or an earlier module
			}
			id, err := mod.findFunc(name)
			if err != nil {
				continue // not in this module
			}
			// Reuse the module's fd if an earlier call already kept one,
			// so each module is referenced by a single fd for the life of
			// the process.
			fd, ok := r.moduleFDs[o.name]
			if !ok {
				fd = o.fd
				r.moduleFDs[o.name] = fd
			}
			r.cache[name] = Kfunc{BTFID: id, Module: o.name, ModuleBTFFD: fd}
		}
	}

	// Fail the whole batch if any name is missing: a program can't load with
	// an unresolved kfunc call, so a partial result is of no use to callers.
	for _, name := range missing {
		kf, ok := r.cache[name]
		if !ok {
			if len(unparsed) > 0 {
				return nil, fmt.Errorf("kfunc %q not found in kernel BTF; could not parse the BTF of modules: %s", name, strings.Join(unparsed, ", "))
			}
			return nil, fmt.Errorf("kfunc %q not found in kernel BTF", name)
		}
		log.Infof("Resolved kfunc %s: BTF ID %d, module %q", name, kf.BTFID, kf.Module)
		result[name] = kf
	}
	return result, nil
}

// allCached reports whether every name has been resolved.
func allCached(cache map[string]Kfunc, names []string) bool {
	for _, name := range names {
		if _, ok := cache[name]; !ok {
			return false
		}
	}
	return true
}

type kernelBTF struct {
	name string
	fd   int
	data []byte
}

// loadKernelBTF returns the raw BTF of vmlinux and every loaded module, read
// through the bpf() syscall so it works without /sys/kernel/btf. The caller
// owns the returned fds.
func loadKernelBTF() ([]kernelBTF, error) {
	var objs []kernelBTF
	// BTF object IDs are walked in increasing order: GET_NEXT_ID returns the
	// smallest ID above the one given (0 starts the walk) and ENOENT once
	// there are no more.
	var id uint32
	for {
		next, err := btfGetNextID(id)
		if errors.Is(err, unix.ENOENT) {
			return objs, nil
		}
		if err != nil {
			closeAll(objs)
			return nil, fmt.Errorf("BPF_BTF_GET_NEXT_ID: %w", err)
		}
		id = next

		fd, err := btfGetFDByID(id)
		if errors.Is(err, unix.ENOENT) {
			continue // freed since GET_NEXT_ID
		}
		if err != nil {
			closeAll(objs)
			return nil, fmt.Errorf("BPF_BTF_GET_FD_BY_ID %d: %w", id, err)
		}
		// An object that can't be read fails the walk: it may be the one
		// that holds the kfuncs, and skipping it would turn into a
		// misleading "not found".
		name, data, isKernel, err := btfGetInfo(fd)
		if err != nil {
			unix.Close(fd)
			closeAll(objs)
			return nil, fmt.Errorf("read BTF ID %d: %w", id, err)
		}
		// The ID space also holds BTF that BPF programs loaded; only kernel
		// BTF (vmlinux and modules) defines kfuncs.
		if !isKernel {
			unix.Close(fd)
			continue
		}
		objs = append(objs, kernelBTF{name: name, fd: fd, data: data})
	}
}

func closeAll(objs []kernelBTF) {
	for _, o := range objs {
		unix.Close(o.fd)
	}
}

// union bpf_attr for BPF_BTF_GET_NEXT_ID and BPF_BTF_GET_FD_BY_ID.
type btfIDAttr struct {
	id        uint32 // start_id / btf_id
	nextID    uint32
	openFlags uint32
}

// union bpf_attr for BPF_OBJ_GET_INFO_BY_FD.
type objInfoAttr struct {
	bpfFD   uint32
	infoLen uint32
	info    unsafe.Pointer
}

// struct bpf_btf_info. The pointer fields are __aligned_u64 in the UAPI,
// which unsafe.Pointer matches on the 64-bit hosts the SDK supports.
type btfInfo struct {
	btf       unsafe.Pointer
	btfSize   uint32
	id        uint32
	name      unsafe.Pointer
	nameLen   uint32
	kernelBTF uint32
}

func btfGetNextID(start uint32) (uint32, error) {
	attr := btfIDAttr{id: start}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_BTF_GET_NEXT_ID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return 0, errno
	}
	return attr.nextID, nil
}

func btfGetFDByID(id uint32) (int, error) {
	attr := btfIDAttr{id: id}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_BTF_GET_FD_BY_ID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// btfGetInfo returns the BTF object's name, raw data and whether it is kernel
// BTF (vmlinux or a module) rather than BTF loaded by a program.
func btfGetInfo(fd int) (string, []byte, bool, error) {
	// Kernel BTF names are "vmlinux" or a module name, which is at most
	// MODULE_NAME_LEN (56) bytes including the NUL; 64 leaves headroom.
	nameBuf := make([]byte, 64)
	info := btfInfo{name: unsafe.Pointer(&nameBuf[0]), nameLen: uint32(len(nameBuf))}
	if err := objGetInfo(fd, &info); err != nil {
		return "", nil, false, err
	}
	name := string(nameBuf[:bytes.IndexByte(append(nameBuf, 0), 0)])
	// The first call only learns the name, whether it's kernel BTF and the
	// size of the raw BTF. Skip the read for non-kernel BTF.
	if info.kernelBTF == 0 || info.btfSize == 0 {
		return name, nil, info.kernelBTF != 0, nil
	}

	// The second call copies the raw BTF into a buffer of that size.
	data := make([]byte, info.btfSize)
	info = btfInfo{btf: unsafe.Pointer(&data[0]), btfSize: uint32(len(data)), name: unsafe.Pointer(&nameBuf[0]), nameLen: uint32(len(nameBuf))}
	if err := objGetInfo(fd, &info); err != nil {
		return "", nil, false, err
	}
	// The kernel reports the full size even when the buffer was too small,
	// so a different size means the data is incomplete.
	if int(info.btfSize) != len(data) {
		return "", nil, false, fmt.Errorf("BTF %s changed size during read", name)
	}
	return name, data, true, nil
}

func objGetInfo(fd int, info *btfInfo) error {
	attr := objInfoAttr{bpfFD: uint32(fd), infoLen: uint32(unsafe.Sizeof(*info)), info: unsafe.Pointer(info)}
	_, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(info)
	if errno != 0 {
		return errno
	}
	return nil
}
