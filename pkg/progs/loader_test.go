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

package progs

import (
	"syscall"
	"testing"

	"github.com/aws/aws-ebpf-sdk-go/pkg/metrics"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// fakeLoader returns a load func that yields errnos from the given sequence,
// one per call, and records how many times it was invoked.
func fakeLoader(fd uintptr, errnos []syscall.Errno) (func() (uintptr, syscall.Errno), *int) {
	calls := 0
	return func() (uintptr, syscall.Errno) {
		e := errnos[calls]
		calls++
		return fd, e
	}, &calls
}

func TestLoadProgWithRetry_SuccessFirstTry(t *testing.T) {
	retriesBefore := metrics.ProgLoadEAGAINRetries()
	exhaustedBefore := metrics.ProgLoadEAGAINExhausted()

	load, calls := fakeLoader(7, []syscall.Errno{0})
	fd, errno := loadProgWithRetry(load)

	assert.Equal(t, uintptr(7), fd)
	assert.Equal(t, syscall.Errno(0), errno)
	assert.Equal(t, 1, *calls, "should not retry on success")
	assert.Equal(t, retriesBefore, metrics.ProgLoadEAGAINRetries())
	assert.Equal(t, exhaustedBefore, metrics.ProgLoadEAGAINExhausted())
}

func TestLoadProgWithRetry_RecoversAfterEAGAIN(t *testing.T) {
	retriesBefore := metrics.ProgLoadEAGAINRetries()
	exhaustedBefore := metrics.ProgLoadEAGAINExhausted()

	// EAGAIN twice, then success on the third attempt.
	load, calls := fakeLoader(9, []syscall.Errno{unix.EAGAIN, unix.EAGAIN, 0})
	fd, errno := loadProgWithRetry(load)

	assert.Equal(t, uintptr(9), fd)
	assert.Equal(t, syscall.Errno(0), errno)
	assert.Equal(t, 3, *calls)
	assert.Equal(t, retriesBefore+2, metrics.ProgLoadEAGAINRetries(), "two retries recorded")
	assert.Equal(t, exhaustedBefore, metrics.ProgLoadEAGAINExhausted(), "no exhaustion on recovery")
}

func TestLoadProgWithRetry_ExhaustsAllAttempts(t *testing.T) {
	retriesBefore := metrics.ProgLoadEAGAINRetries()
	exhaustedBefore := metrics.ProgLoadEAGAINExhausted()

	// EAGAIN on every attempt.
	errnos := make([]syscall.Errno, maxProgLoadAttempts)
	for i := range errnos {
		errnos[i] = unix.EAGAIN
	}
	load, calls := fakeLoader(0, errnos)
	_, errno := loadProgWithRetry(load)

	assert.Equal(t, unix.EAGAIN, errno, "final errno surfaces to caller")
	assert.Equal(t, maxProgLoadAttempts, *calls, "tries exactly maxProgLoadAttempts times")
	// maxProgLoadAttempts-1 retries, then 1 exhaustion.
	assert.Equal(t, retriesBefore+uint64(maxProgLoadAttempts-1), metrics.ProgLoadEAGAINRetries())
	assert.Equal(t, exhaustedBefore+1, metrics.ProgLoadEAGAINExhausted())
}

func TestLoadProgWithRetry_NonEAGAINErrorNotRetried(t *testing.T) {
	retriesBefore := metrics.ProgLoadEAGAINRetries()
	exhaustedBefore := metrics.ProgLoadEAGAINExhausted()

	// A non-EAGAIN error (e.g. EPERM from the JIT path) must not be retried.
	load, calls := fakeLoader(0, []syscall.Errno{unix.EPERM})
	_, errno := loadProgWithRetry(load)

	assert.Equal(t, unix.EPERM, errno)
	assert.Equal(t, 1, *calls, "non-EAGAIN errors are returned immediately")
	assert.Equal(t, retriesBefore, metrics.ProgLoadEAGAINRetries())
	assert.Equal(t, exhaustedBefore, metrics.ProgLoadEAGAINExhausted())
}
