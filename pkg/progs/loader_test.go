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

package progs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestVerifierLogString verifies the log is returned up to the first NUL.
func TestVerifierLogString(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{
			name: "message then NUL padding",
			in:   append([]byte("permission denied"), make([]byte, 1024)...),
			want: "permission denied",
		},
		{
			name: "no NUL (whole buffer is message)",
			in:   []byte("full message no terminator"),
			want: "full message no terminator",
		},
		{
			name: "leading NUL yields empty string",
			in:   []byte{0, 'x', 'y'},
			want: "",
		},
		{
			name: "empty buffer",
			in:   []byte{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifierLogString(tt.in)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestVerifierLogStringDoesNotCopyPadding ensures only the prefix is returned,
// not the large NUL padding, when the buffer is mostly empty.
func TestVerifierLogStringDoesNotCopyPadding(t *testing.T) {
	const msg = "BPF program is too large"
	buf := append([]byte(msg), make([]byte, 16*1024*1024)...) // 16 MiB of padding

	got := verifierLogString(buf)

	assert.Equal(t, msg, got)
	assert.Equal(t, len(msg), len(got),
		"returned string must be the prefix only, not the full padded buffer")
	assert.False(t, strings.ContainsRune(got, 0), "result must not contain NUL bytes")
}
