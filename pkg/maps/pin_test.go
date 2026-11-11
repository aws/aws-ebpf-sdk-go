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

package maps

import (
	"errors"
	"os"
	"testing"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// GetMapFromPinPath closes the FD it opened when the info query fails.
func TestGetMapFromPinPathClosesFDOnInfoError(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps in the kernel")
	}
	require.NoError(t, utils.Mount_bpf_fs())
	defer utils.Unmount_bpf_fs()
	pinPath := constdef.MAP_BPF_FS + "rk_infoerr_map"
	created, err := (&BpfMap{}).CreateBPFMap(CreateEBPFMapInput{
		Type: uint32(constdef.BPF_MAP_TYPE_HASH.Index()), KeySize: 4, ValueSize: 4, MaxEntries: 1,
		PinOptions: &BpfMapPinOptions{Type: constdef.PIN_GLOBAL_NS.Index(), PinPath: pinPath},
	})
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(int(created.MapFD)) })

	orig := mapInfoByFD
	t.Cleanup(func() { mapInfoByFD = orig })
	mapInfoByFD = func(int) (BpfMapInfo, error) { return BpfMapInfo{}, errors.New("injected") }
	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		require.NoError(t, err)
		return len(entries)
	}

	before := countFDs()
	_, err = (&BpfMap{}).GetMapFromPinPath(pinPath)
	assert.ErrorContains(t, err, "injected")
	assert.Equal(t, before, countFDs())
}

// CreateBPFMap fails, and closes the map it created, when the map cannot be pinned.
func TestCreateBPFMapClosesFDOnPinError(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps in the kernel")
	}
	require.NoError(t, utils.Mount_bpf_fs())
	t.Cleanup(func() { utils.Unmount_bpf_fs() })

	tests := []struct {
		name    string
		pinPath func(t *testing.T) string
		wantErr error
	}{
		{
			// PinMap's own pre-check: something other than a pin already sits at the path.
			name: "path already taken",
			pinPath: func(t *testing.T) string {
				p := constdef.MAP_BPF_FS + "rk_pinerr_map"
				require.NoError(t, os.MkdirAll(p, 0755))
				t.Cleanup(func() { os.RemoveAll(p) }) // runs before the unmount registered above
				return p
			},
		},
		{
			// The BPF_OBJ_PIN syscall itself fails: the kernel only pins inside bpffs.
			name:    "pin syscall fails",
			pinPath: func(t *testing.T) string { return t.TempDir() + "/rk_pinerr_map" },
			wantErr: unix.EPERM,
		},
	}
	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		require.NoError(t, err)
		return len(entries)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pinPath := tt.pinPath(t)
			before := countFDs()
			created, err := (&BpfMap{}).CreateBPFMap(CreateEBPFMapInput{
				Type: uint32(constdef.BPF_MAP_TYPE_HASH.Index()), KeySize: 4, ValueSize: 4, MaxEntries: 1,
				PinOptions: &BpfMapPinOptions{Type: constdef.PIN_GLOBAL_NS.Index(), PinPath: pinPath},
			})
			assert.ErrorContains(t, err, "unable to pin map")
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Zero(t, created.MapFD)
			assert.Equal(t, before, countFDs())
		})
	}
}

// PinObject reports a failed pin instead of returning nil.
func TestPinObjectReportsSyscallFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps in the kernel")
	}
	require.NoError(t, utils.Mount_bpf_fs())
	t.Cleanup(func() { utils.Unmount_bpf_fs() })
	created, err := (&BpfMap{}).CreateBPFMap(CreateEBPFMapInput{
		Type: uint32(constdef.BPF_MAP_TYPE_HASH.Index()), KeySize: 4, ValueSize: 4, MaxEntries: 1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(int(created.MapFD)) })

	pinPath := constdef.MAP_BPF_FS + "rk_pinobj_map"
	require.NoError(t, os.MkdirAll(constdef.MAP_BPF_FS, 0755))
	require.NoError(t, utils.PinObject(created.MapFD, pinPath))
	t.Cleanup(func() { os.Remove(pinPath) })

	// A second pin at the same path is what a concurrent load sharing it hits.
	assert.ErrorIs(t, utils.PinObject(created.MapFD, pinPath), unix.EEXIST)
	assert.ErrorIs(t, utils.PinObject(created.MapFD, t.TempDir()+"/m"), unix.EPERM)
}
