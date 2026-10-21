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
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

var ctKfuncs = []string{"bpf_skb_ct_lookup", "bpf_ct_change_timeout", "bpf_ct_release"}

// requireKernelBTF parses vmlinux BTF, skipping the test when the kernel has
// none or when the resolver's bpf() calls would fail for lack of privilege.
func requireKernelBTF(t *testing.T) *btfSpec {
	if os.Geteuid() != 0 {
		t.Skip("needs root to open kernel BTF objects")
	}
	raw, err := os.ReadFile(filepath.Join(sysKernelBTF, "vmlinux"))
	if err != nil {
		t.Skipf("kernel BTF not available: %v", err)
	}
	vmlinux, err := parseBase(raw)
	require.NoError(t, err)
	return vmlinux
}

// ctModule returns the BTF object that should define the nf_conntrack kfuncs:
// "nf_conntrack" for a loaded module, "" when it is built in. It skips the
// test when neither has them (kernels before 6.0, or nf_conntrack not loaded).
func ctModule(t *testing.T) string {
	vmlinux := requireKernelBTF(t)
	if _, err := vmlinux.findFunc(ctKfuncs[1]); err == nil {
		return ""
	}
	if raw, err := os.ReadFile(filepath.Join(sysKernelBTF, "nf_conntrack")); err == nil {
		mod, err := parseSplit(raw, vmlinux)
		require.NoError(t, err)
		if _, err := mod.findFunc(ctKfuncs[1]); err == nil {
			return "nf_conntrack"
		}
	}
	t.Skip("nf_conntrack kfuncs not available")
	return ""
}

func newTestResolver(t *testing.T) *kernelKfuncResolver {
	r := newKernelKfuncResolver()
	t.Cleanup(func() {
		for _, fd := range r.moduleFDs {
			unix.Close(fd)
		}
	})
	return r
}

func countFDs(t *testing.T) int {
	fds, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(fds)
}

func TestKernelResolveKfuncs(t *testing.T) {
	wantModule := ctModule(t)
	r := newTestResolver(t)

	before := countFDs(t)
	kfuncs, err := r.ResolveKfuncs(ctKfuncs)
	require.NoError(t, err)
	// Every BTF object was opened; only the module fds the cache refers to
	// may stay open.
	assert.LessOrEqual(t, countFDs(t)-before, len(r.moduleFDs))

	require.Len(t, kfuncs, len(ctKfuncs))
	for _, name := range ctKfuncs {
		kf := kfuncs[name]
		assert.NotZero(t, kf.BTFID, name)
		assert.Equal(t, wantModule, kf.Module, name)
		if wantModule != "" {
			// The kept fd must still refer to the module's BTF.
			btfName, _, isKernel, err := btfGetInfo(kf.ModuleBTFFD)
			require.NoError(t, err, name)
			assert.True(t, isKernel, name)
			assert.Equal(t, wantModule, btfName, name)
		}
	}

	// A second call is served from the cache: same result and fds, and no
	// new fds opened.
	before = countFDs(t)
	again, err := r.ResolveKfuncs(ctKfuncs)
	require.NoError(t, err)
	assert.Equal(t, kfuncs, again)
	assert.Equal(t, before, countFDs(t))
}

func TestKernelResolveUnknownKfunc(t *testing.T) {
	requireKernelBTF(t)
	r := newTestResolver(t)

	before := countFDs(t)
	_, err := r.ResolveKfuncs([]string{"no_such_kfunc"})
	if errors.Is(err, errKernelBTFUnsupported) {
		// Kernels before 5.11 fail the walk itself, before any lookup.
		t.Log("kernel too old to read kernel BTF via bpf()")
	} else {
		assert.ErrorContains(t, err, `kfunc "no_such_kfunc" not found`)
	}
	// Nothing was found, so every fd opened during the walk is closed.
	assert.Equal(t, before, countFDs(t))
	assert.Empty(t, r.cache)
}
