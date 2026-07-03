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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLogs(t *testing.T) {
	verifierOutput := "0: R1=ctx(off=0,imm=0) R10=fp0\nprocessed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n"

	buf := make([]byte, 1024*1024)
	copy(buf, verifierOutput)

	logs := parseLogs(buf)
	assert.Equal(t, []string{
		"0: R1=ctx(off=0,imm=0) R10=fp0",
		"processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0",
		"",
	}, logs)

	// A buffer completely filled by the verifier (no NUL terminator) is kept whole.
	full := []byte("line1\nline2")
	assert.Equal(t, []string{"line1", "line2"}, parseLogs(full))

	// An untouched buffer yields no log content.
	assert.Equal(t, []string{""}, parseLogs(make([]byte, 4096)))

	assert.Equal(t, []string{""}, parseLogs(nil))
}
