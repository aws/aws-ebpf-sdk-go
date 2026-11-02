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
