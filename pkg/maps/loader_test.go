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

package maps

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// Map operations wrap the syscall errno, so callers can match it with
// errors.Is. An invalid FD fails with EBADF, or EPERM without CAP_BPF.
func TestMapOpsWrapErrno(t *testing.T) {
	m := &BpfMap{MapFD: 0xffff}
	key, value := uint32(0), uint64(0)
	k, v := uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&value))

	for name, op := range map[string]func() error{
		"UpdateMapEntry": func() error { return m.UpdateMapEntry(k, v) },
		"DeleteMapEntry": func() error { return m.DeleteMapEntry(k) },
		"GetMapEntry":    func() error { return m.GetMapEntry(k, v) },
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
