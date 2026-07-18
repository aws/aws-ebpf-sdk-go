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
// limitations under the License.

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
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestUpdateProgArrayEntryRejectsNegativeFD(t *testing.T) {
	m := &maps.BpfMap{MapMetaData: maps.CreateEBPFMapInput{
		Name: "prog_array",
		Type: constdef.BPF_MAP_TYPE_PROG_ARRAY.Index(),
	}}
	assert.Error(t, m.UpdateProgArrayEntry(0, -1))
}

func buildTrivialXDPProg(retval int32) []byte {
	movR0 := utils.BPFInsn{Code: unix.BPF_ALU64 | unix.BPF_MOV | unix.BPF_K, DstReg: 0, Imm: retval}
	exit := utils.BPFInsn{Code: unix.BPF_JMP | unix.BPF_EXIT}
	return append(movR0.ConvertBPFInstructionToByteStream(), exit.ConvertBPFInstructionToByteStream()...)
}

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
	require.NoError(t, err)
	t.Cleanup(func() {
		unix.Close(fd)
		progApi.UnPinProg(pinPath)
	})
	return fd
}

func readProgArraySlot(t *testing.T, progArray maps.BpfMap, index uint32) (uint32, error) {
	t.Helper()
	key := new(uint32)
	*key = index
	value := new(uint32)
	err := progArray.GetMapEntry(uintptr(unsafe.Pointer(key)), uintptr(unsafe.Pointer(value)))
	return *value, err
}

// Requires root and a bpf-capable kernel.
func TestProgArrayRealKernelRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
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
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(int(progArray.MapFD)) })

	bpfProgApi := &progs.BpfProgram{}
	dropFD := loadTrivialXDPProg(t, bpfProgApi, "test_tailcall_drop", 1)
	passFD := loadTrivialXDPProg(t, bpfProgApi, "test_tailcall_pass", 2)

	require.NoError(t, progArray.UpdateProgArrayEntry(0, dropFD))
	require.NoError(t, progArray.UpdateProgArrayEntry(1, passFD))

	dropInfo, err := progs.GetBPFprogInfo(dropFD)
	require.NoError(t, err)
	passInfo, err := progs.GetBPFprogInfo(passFD)
	require.NoError(t, err)

	gotDrop, err := readProgArraySlot(t, progArray, 0)
	require.NoError(t, err)
	assert.Equal(t, dropInfo.ID, gotDrop)

	gotPass, err := readProgArraySlot(t, progArray, 1)
	require.NoError(t, err)
	assert.Equal(t, passInfo.ID, gotPass)

	require.NoError(t, progArray.DeleteProgArrayEntry(0))
	_, err = readProgArraySlot(t, progArray, 0)
	assert.Error(t, err)
}
