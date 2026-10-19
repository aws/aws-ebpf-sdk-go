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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sysKernelBTF = "/sys/kernel/btf"

// bpftoolBTF holds the parts of `bpftool -j btf dump file` output the test
// compares: the last type ID and the first ID of each FUNC name.
type bpftoolBTF struct {
	lastID uint32
	funcs  map[string]uint32
}

func bpftoolDump(t *testing.T, path string, base string) bpftoolBTF {
	args := []string{"-j"}
	if base != "" {
		args = append(args, "-B", base)
	}
	args = append(args, "btf", "dump", "file", path)
	// bpftool failing, or printing JSON this test can't read, says nothing
	// about the parser (an older bpftool may not know a newer kernel's BTF
	// kinds), so skip rather than fail.
	out, err := exec.Command("bpftool", args...).Output()
	if err != nil {
		t.Skipf("bpftool %v failed: %v", args, err)
	}

	var dump struct {
		Types []struct {
			ID   uint32 `json:"id"`
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"types"`
	}
	if err := json.Unmarshal(out, &dump); err != nil {
		t.Skipf("can't parse bpftool %v output: %v", args, err)
	}

	res := bpftoolBTF{funcs: make(map[string]uint32)}
	for _, typ := range dump.Types {
		if typ.ID > res.lastID {
			res.lastID = typ.ID
		}
		if typ.Kind == "FUNC" && typ.Name != "" {
			if _, dup := res.funcs[typ.Name]; !dup {
				res.funcs[typ.Name] = typ.ID
			}
		}
	}
	return res
}

// TestParseKernelBTF checks the parser against bpftool on the running kernel's
// BTF: vmlinux and every loaded module. Matching the last type ID means every
// type was walked with the right size; matching every FUNC's ID is what kfunc
// resolution depends on.
func TestParseKernelBTF(t *testing.T) {
	vmlinuxPath := filepath.Join(sysKernelBTF, "vmlinux")
	raw, err := os.ReadFile(vmlinuxPath)
	if err != nil {
		t.Skipf("kernel BTF not available: %v", err)
	}
	if _, err := exec.LookPath("bpftool"); err != nil {
		t.Skip("bpftool not in PATH")
	}

	vmlinux, err := parseBase(raw)
	require.NoError(t, err)

	paths, err := filepath.Glob(filepath.Join(sysKernelBTF, "*"))
	require.NoError(t, err)
	for _, path := range paths {
		name := filepath.Base(path)
		t.Run(name, func(t *testing.T) {
			spec, base := vmlinux, ""
			if name != "vmlinux" {
				raw, err := os.ReadFile(path)
				require.NoError(t, err)
				spec, err = parseSplit(raw, vmlinux)
				require.NoError(t, err)
				base = vmlinuxPath
			}
			want := bpftoolDump(t, path, base)
			assert.Equal(t, want.lastID, spec.firstTypeID+spec.nrTypes-1, "last type ID")
			assert.Equal(t, want.funcs, spec.funcs, "FUNC IDs")
		})
	}
}
