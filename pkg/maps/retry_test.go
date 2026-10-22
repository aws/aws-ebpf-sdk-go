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
	"testing"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// fakeMutation returns a mutate func that yields errnos from the given
// sequence, one per call, and records how many times it was invoked.
func fakeMutation(ret uintptr, errnos []unix.Errno) (func() (uintptr, unix.Errno), *int) {
	calls := 0
	return func() (uintptr, unix.Errno) {
		e := errnos[calls]
		calls++
		return ret, e
	}, &calls
}

func TestMutateWithRetry_SuccessFirstTry(t *testing.T) {
	retriesBefore := metrics.MapMutateENOMEMRetries()
	exhaustedBefore := metrics.MapMutateENOMEMExhausted()

	mutate, calls := fakeMutation(0, []unix.Errno{0})
	ret, errno := mutateWithRetry("BPF_MAP_UPDATE_ELEM", mutate)

	assert.Equal(t, uintptr(0), ret)
	assert.Equal(t, unix.Errno(0), errno)
	assert.Equal(t, 1, *calls, "should not retry on success")
	assert.Equal(t, retriesBefore, metrics.MapMutateENOMEMRetries())
	assert.Equal(t, exhaustedBefore, metrics.MapMutateENOMEMExhausted())
}

func TestMutateWithRetry_RecoversAfterENOMEM(t *testing.T) {
	retriesBefore := metrics.MapMutateENOMEMRetries()
	exhaustedBefore := metrics.MapMutateENOMEMExhausted()

	// ENOMEM twice, then success on the third attempt.
	mutate, calls := fakeMutation(0, []unix.Errno{unix.ENOMEM, unix.ENOMEM, 0})
	_, errno := mutateWithRetry("BPF_MAP_UPDATE_ELEM", mutate)

	assert.Equal(t, unix.Errno(0), errno)
	assert.Equal(t, 3, *calls)
	assert.Equal(t, retriesBefore+2, metrics.MapMutateENOMEMRetries(), "two retries recorded")
	assert.Equal(t, exhaustedBefore, metrics.MapMutateENOMEMExhausted(), "no exhaustion on recovery")
}

func TestMutateWithRetry_ExhaustsAllAttempts(t *testing.T) {
	retriesBefore := metrics.MapMutateENOMEMRetries()
	exhaustedBefore := metrics.MapMutateENOMEMExhausted()

	errnos := make([]unix.Errno, maxMapMutateAttempts)
	for i := range errnos {
		errnos[i] = unix.ENOMEM
	}
	mutate, calls := fakeMutation(0, errnos)
	_, errno := mutateWithRetry("BPF_MAP_UPDATE_ELEM", mutate)

	assert.Equal(t, unix.ENOMEM, errno, "final errno surfaces to caller")
	assert.Equal(t, maxMapMutateAttempts, *calls, "tries exactly maxMapMutateAttempts times")
	assert.Equal(t, retriesBefore+uint64(maxMapMutateAttempts-1), metrics.MapMutateENOMEMRetries())
	assert.Equal(t, exhaustedBefore+1, metrics.MapMutateENOMEMExhausted())
}

// A saturated map returns ENOSPC and a malformed key EINVAL; retrying either
// only delays the error reaching the caller.
func TestMutateWithRetry_OtherErrnosNotRetried(t *testing.T) {
	for _, errno := range []unix.Errno{unix.ENOSPC, unix.EINVAL, unix.EBADF, unix.EEXIST, unix.ENOENT} {
		t.Run(unix.ErrnoName(errno), func(t *testing.T) {
			retriesBefore := metrics.MapMutateENOMEMRetries()

			mutate, calls := fakeMutation(0, []unix.Errno{errno})
			_, got := mutateWithRetry("BPF_MAP_UPDATE_ELEM", mutate)

			assert.Equal(t, errno, got)
			assert.Equal(t, 1, *calls, "non-ENOMEM errnos are returned immediately")
			assert.Equal(t, retriesBefore, metrics.MapMutateENOMEMRetries())
		})
	}
}

// scriptSyscall replaces the map-mutation syscall with a scripted errno
// sequence so the real map methods can be driven without a kernel. The last
// element repeats once the sequence is exhausted. Returns a pointer to the call
// count.
func scriptSyscall(t *testing.T, errnos ...unix.Errno) *int {
	t.Helper()
	calls := 0
	orig := bpfMutateSyscall
	t.Cleanup(func() { bpfMutateSyscall = orig })
	bpfMutateSyscall = func(_ uintptr, _ unsafe.Pointer, _ uintptr) (uintptr, unix.Errno) {
		e := errnos[min(calls, len(errnos)-1)]
		calls++
		if e != 0 {
			return ^uintptr(0), e
		}
		return 0, 0
	}
	return &calls
}

// Map mutations wrap the errno with %w, so callers can classify a failure
// without matching on message text. Driven against a real BpfMap with an
// invalid FD, so the errno comes from the kernel rather than the test.
func TestMapOpsWrapErrno(t *testing.T) {
	m := &BpfMap{MapFD: 0xffff}
	key, value := uint32(0), uint64(0)
	k, v := uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value))

	for name, op := range map[string]func() error{
		"UpdateMapEntry": func() error { return m.UpdateMapEntry(k, v) },
		"DeleteMapEntry": func() error { return m.DeleteMapEntry(k) },
	} {
		t.Run(name, func(t *testing.T) {
			err := op()
			var errno unix.Errno
			if assert.True(t, errors.As(err, &errno), "error %q does not wrap an errno", err) {
				assert.Contains(t, []unix.Errno{unix.EBADF, unix.EPERM}, errno)
				assert.True(t, errors.Is(err, errno))
			}
		})
	}
}

// A transient ENOMEM must be absorbed inside the real method, not just inside
// the retry helper.
func TestMapMutationsAbsorbTransientENOMEM(t *testing.T) {
	for _, tt := range []struct {
		name string
		call func(m *BpfMap, k, v uintptr) error
	}{
		{"CreateUpdateMapEntry", func(m *BpfMap, k, v uintptr) error { return m.UpdateMapEntry(k, v) }},
		{"DeleteMapEntry", func(m *BpfMap, k, _ uintptr) error { return m.DeleteMapEntry(k) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			retriesBefore := metrics.MapMutateENOMEMRetries()
			exhaustedBefore := metrics.MapMutateENOMEMExhausted()

			// ENOMEM, ENOMEM, then success.
			calls := scriptSyscall(t, unix.ENOMEM, unix.ENOMEM, 0)
			key, value := uint32(0), uint64(0)
			err := tt.call(&BpfMap{MapFD: 1},
				uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)))

			assert.NoError(t, err, "a transient ENOMEM must not reach the caller")
			assert.Equal(t, 3, *calls, "two retries then success")
			assert.Equal(t, retriesBefore+2, metrics.MapMutateENOMEMRetries())
			assert.Equal(t, exhaustedBefore, metrics.MapMutateENOMEMExhausted(),
				"an absorbed ENOMEM must not count as exhausted")
		})
	}
}

// A persistent ENOMEM must stop after exactly maxMapMutateAttempts attempts and
// surface to the caller. The attempt count is asserted as a literal so a change
// to the constant is caught here.
func TestMapMutationsStopAfterFourAttempts(t *testing.T) {
	for _, tt := range []struct {
		name string
		call func(m *BpfMap, k, v uintptr) error
	}{
		{"CreateUpdateMapEntry", func(m *BpfMap, k, v uintptr) error { return m.UpdateMapEntry(k, v) }},
		{"DeleteMapEntry", func(m *BpfMap, k, _ uintptr) error { return m.DeleteMapEntry(k) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			retriesBefore := metrics.MapMutateENOMEMRetries()
			exhaustedBefore := metrics.MapMutateENOMEMExhausted()

			calls := scriptSyscall(t, unix.ENOMEM)
			key, value := uint32(0), uint64(0)
			err := tt.call(&BpfMap{MapFD: 1},
				uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)))

			assert.ErrorIs(t, err, unix.ENOMEM)
			assert.Equal(t, 4, *calls, "exactly maxMapMutateAttempts attempts")
			assert.Equal(t, retriesBefore+3, metrics.MapMutateENOMEMRetries())
			assert.Equal(t, exhaustedBefore+1, metrics.MapMutateENOMEMExhausted())
		})
	}
}

// Errnos that do not clear on their own must be returned on the first attempt
// and must not touch the exhaustion counter, which exists to flag real
// enforcement gaps.
func TestMapMutationsDoNotRetryOtherErrnos(t *testing.T) {
	for _, errno := range []unix.Errno{unix.ENOSPC, unix.E2BIG, unix.EINVAL, unix.EBADF, unix.EPERM} {
		t.Run(unix.ErrnoName(errno), func(t *testing.T) {
			retriesBefore := metrics.MapMutateENOMEMRetries()
			exhaustedBefore := metrics.MapMutateENOMEMExhausted()

			calls := scriptSyscall(t, errno)
			key, value := uint32(0), uint64(0)
			err := (&BpfMap{MapFD: 1}).UpdateMapEntry(
				uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)))

			assert.ErrorIs(t, err, errno)
			assert.Equal(t, 1, *calls, "must not retry")
			assert.Equal(t, retriesBefore, metrics.MapMutateENOMEMRetries())
			assert.Equal(t, exhaustedBefore, metrics.MapMutateENOMEMExhausted(),
				"a permanent errno is not an exhausted retry")
		})
	}
}

// BPF_NOEXIST + EEXIST is reported as success, and that must survive the retry
// wrapper being introduced around the syscall.
func TestCreateMapEntryTreatsEEXISTAsSuccess(t *testing.T) {
	calls := scriptSyscall(t, unix.EEXIST)
	key, value := uint32(0), uint64(0)
	err := (&BpfMap{MapFD: 1}).CreateMapEntry(
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value)))

	assert.NoError(t, err, "an existing entry is the desired state")
	assert.Equal(t, 1, *calls, "EEXIST must not be retried")
}
