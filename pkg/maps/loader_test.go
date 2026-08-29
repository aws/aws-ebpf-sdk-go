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

package maps_test

import (
	"os"
	"testing"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestUpdateProgArrayEntryRejectsWrongMapType(t *testing.T) {
	m := &maps.BpfMap{MapMetaData: maps.CreateEBPFMapInput{
		Name: "not_a_prog_array",
		Type: constdef.BPF_MAP_TYPE_HASH.Index(),
	}}
	assert.Error(t, m.UpdateProgArrayEntry(0, 3))
}

func TestDeleteProgArrayEntryRejectsWrongMapType(t *testing.T) {
	m := &maps.BpfMap{MapMetaData: maps.CreateEBPFMapInput{
		Name: "not_a_prog_array",
		Type: constdef.BPF_MAP_TYPE_ARRAY.Index(),
	}}
	assert.Error(t, m.DeleteProgArrayEntry(0))
}

// A caller-supplied FD of -1 (e.g. forwarding a failed LoadProg result
// without checking it) should be rejected, not written into the map as-is.
func TestUpdateProgArrayEntryRejectsNegativeFD(t *testing.T) {
	m := &maps.BpfMap{MapMetaData: maps.CreateEBPFMapInput{
		Name: "prog_array",
		Type: constdef.BPF_MAP_TYPE_PROG_ARRAY.Index(),
	}}
	assert.Error(t, m.UpdateProgArrayEntry(0, -1))
}

// buildTrivialXDPProg assembles `return <retval>;` by hand (mov r0, retval;
// exit) so tests can load a real program without needing clang/libbpf to
// compile one.
func buildTrivialXDPProg(retval int32) []byte {
	movR0 := utils.BPFInsn{Code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K, DstReg: 0, Imm: retval}
	exit := utils.BPFInsn{Code: unix.BPF_JMP | unix.BPF_EXIT}
	return append(movR0.ConvertBPFInstructionToByteStream(), exit.ConvertBPFInstructionToByteStream()...)
}

// loadTrivialXDPProg loads buildTrivialXDPProg(retval) under name, and
// registers cleanup so callers don't have to repeat the close+unpin dance
// at every call site.
func loadTrivialXDPProg(t *testing.T, progApi *progs.BpfProgram, name string, retval int32) int {
	t.Helper()
	pinPath := "/sys/fs/bpf/globals/aws/programs/" + name
	fd, err := progApi.LoadProg(progs.CreateEBPFProgInput{
		ProgType:   "xdp",
		ProgData:   buildTrivialXDPProg(retval),
		LicenseStr: "GPL",
		PinPath:    pinPath,
		InsDefSize: 8,
	})
	assert.NoError(t, err)
	t.Cleanup(func() {
		unix.Close(fd)
		progApi.UnPinProg(pinPath)
	})
	return fd
}

// readProgArraySlot looks up a tail-call slot the way GetMapEntry requires:
// raw uintptr-backed pointers to a fixed-size key/value.
func readProgArraySlot(progArray maps.BpfMap, index uint32) (uint32, error) {
	key, value := index, uint32(0)
	err := progArray.GetMapEntry(uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)))
	return value, err
}

// TestProgArrayRealKernelRoundTrip exercises the same flow an application
// uses to wire up bpf_tail_call() targets: load the target programs, then
// point each tail-call index at the right program FD. It creates a real
// BPF_MAP_TYPE_PROG_ARRAY map and two trivial XDP programs against the
// running kernel, populates two slots, reads them back, and deletes one.
//
// Requires root and a bpf-capable kernel, same as the other real-kernel
// tests in this SDK; skipped otherwise.
func TestProgArrayRealKernelRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps and load programs into the kernel")
	}

	utils.Mount_bpf_fs()
	t.Cleanup(func() { utils.Unmount_bpf_fs() })

	bpfMapApi := &maps.BpfMap{}
	progArray, err := bpfMapApi.CreateBPFMap(maps.CreateEBPFMapInput{
		Name:       "test_prog_array",
		Type:       constdef.BPF_MAP_TYPE_PROG_ARRAY.Index(),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4,
	})
	assert.NoError(t, err)
	t.Cleanup(func() { unix.Close(int(progArray.MapFD)) })

	bpfProgApi := &progs.BpfProgram{}
	dropFD := loadTrivialXDPProg(t, bpfProgApi, "test_tailcall_drop", 1) // XDP_DROP
	passFD := loadTrivialXDPProg(t, bpfProgApi, "test_tailcall_pass", 2) // XDP_PASS

	assert.NoError(t, progArray.UpdateProgArrayEntry(0, dropFD))
	assert.NoError(t, progArray.UpdateProgArrayEntry(1, passFD))

	// A prog array lookup returns a program ID, not the FD we inserted, so
	// compare against GetBPFprogInfo's ID rather than the FD itself. This
	// needs progs.GetBPFprogInfo specifically: BPF_OBJ_GET_INFO_BY_FD returns
	// a different struct layout for a program FD than for a map FD, and this
	// package's own GetBPFmapInfo assumes the map layout.
	dropInfo, err := progs.GetBPFprogInfo(dropFD)
	assert.NoError(t, err)
	passInfo, err := progs.GetBPFprogInfo(passFD)
	assert.NoError(t, err)

	gotDrop, err := readProgArraySlot(progArray, 0)
	assert.NoError(t, err)
	assert.Equal(t, dropInfo.ID, gotDrop)

	gotPass, err := readProgArraySlot(progArray, 1)
	assert.NoError(t, err)
	assert.Equal(t, passInfo.ID, gotPass)

	// After deleting a slot, a tail call to it should miss - same as the
	// kernel's own behavior for an empty slot.
	assert.NoError(t, progArray.DeleteProgArrayEntry(0))
	_, err = readProgArraySlot(progArray, 0)
	assert.Error(t, err)
}
