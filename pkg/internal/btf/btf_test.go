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
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// btfBuilder assembles a raw BTF blob for tests.
type btfBuilder struct {
	types []byte
	strs  []byte
	// strBase is added to every string offset, for split BTF.
	strBase uint32
}

func newBuilder(strBase uint32) *btfBuilder {
	b := &btfBuilder{strBase: strBase}
	if strBase == 0 {
		b.strs = []byte{0} // offset 0 is the empty string in base BTF
	}
	return b
}

func (b *btfBuilder) str(s string) uint32 {
	off := b.strBase + uint32(len(b.strs))
	b.strs = append(append(b.strs, s...), 0)
	return off
}

// typ appends a btf_type followed by extra trailing bytes.
func (b *btfBuilder) typ(nameOff uint32, kind uint32, vlen uint32, sizeOrType uint32, extra int) {
	var t [btfTypeSize]byte
	binary.LittleEndian.PutUint32(t[0:], nameOff)
	binary.LittleEndian.PutUint32(t[4:], kind<<24|vlen) // btf_type.info
	binary.LittleEndian.PutUint32(t[8:], sizeOrType)
	b.types = append(b.types, t[:]...)
	b.types = append(b.types, make([]byte, extra)...)
}

func (b *btfBuilder) bytes() []byte {
	hdr := make([]byte, btfHeaderSize)
	binary.LittleEndian.PutUint16(hdr[0:], btfMagic)
	hdr[2] = 1                                                    // version
	binary.LittleEndian.PutUint32(hdr[4:], btfHeaderSize)         // hdr_len
	binary.LittleEndian.PutUint32(hdr[8:], 0)                     // type_off
	binary.LittleEndian.PutUint32(hdr[12:], uint32(len(b.types))) // type_len
	binary.LittleEndian.PutUint32(hdr[16:], uint32(len(b.types))) // str_off: strings follow types
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(b.strs)))  // str_len
	return append(append(hdr, b.types...), b.strs...)
}

// buildBase builds base BTF with one type of each trailing-data shape. The
// last argument of each typ call is the trailing size trailingSize expects
// for that kind.
func buildBase(t *testing.T) (*btfSpec, []byte) {
	b := newBuilder(0)
	intName := b.str("int")
	b.typ(intName, kindInt, 0, 4, 4)                  // [1] int
	b.typ(0, kindFuncProto, 2, 1, 2*8)                // [2] int (*)(a, b)
	b.typ(b.str("vmlinux_kfunc"), kindFunc, 0, 2, 0)  // [3]
	b.typ(b.str("s"), kindStruct, 3, 12, 3*12)        // [4]
	b.typ(b.str("e"), kindEnum64, 2, 8, 2*12)         // [5]
	b.typ(b.str("shared_name"), kindTypedef, 0, 1, 0) // [6]
	b.typ(b.str("dup"), kindFunc, 0, 2, 0)            // [7]
	b.typ(b.str("tag"), kindDeclTag, 0, 7, 4)         // [8]
	raw := b.bytes()
	spec, err := parseBase(raw)
	require.NoError(t, err)
	return spec, raw
}

func TestParseBase(t *testing.T) {
	spec, _ := buildBase(t)
	assert.Equal(t, uint32(8), spec.nrTypes)

	id, err := spec.findFunc("vmlinux_kfunc")
	require.NoError(t, err)
	assert.Equal(t, uint32(3), id)

	id, err = spec.findFunc("dup")
	require.NoError(t, err)
	assert.Equal(t, uint32(7), id)

	// A typedef is not a func.
	_, err = spec.findFunc("shared_name")
	assert.True(t, errors.Is(err, errNotFound))
}

func TestParseSplit(t *testing.T) {
	base, baseRaw := buildBase(t)
	baseStrLen := binary.LittleEndian.Uint32(baseRaw[20:])

	b := newBuilder(baseStrLen)
	b.typ(0, kindFuncProto, 1, 1, 8)                     // [9]
	b.typ(b.str("bpf_skb_ct_lookup"), kindFunc, 0, 9, 0) // [10]
	b.typ(b.str("bpf_ct_release"), kindFunc, 0, 9, 0)    // [11]
	// A module func whose name pahole deduped against a base string.
	b.typ(baseStrOff(t, base, "shared_name"), kindFunc, 0, 9, 0) // [12]

	mod, err := parseSplit(b.bytes(), base)
	require.NoError(t, err)
	assert.Equal(t, uint32(9), mod.firstTypeID)

	for name, want := range map[string]uint32{"bpf_skb_ct_lookup": 10, "bpf_ct_release": 11, "shared_name": 12} {
		id, err := mod.findFunc(name)
		require.NoError(t, err, name)
		assert.Equal(t, want, id, name)
	}

	// The module spec does not index the base's funcs.
	_, err = mod.findFunc("vmlinux_kfunc")
	assert.True(t, errors.Is(err, errNotFound))
}

// baseStrOff returns the offset of name in a base spec's string section.
func baseStrOff(t *testing.T, s *btfSpec, name string) uint32 {
	for off := 0; off < len(s.strs); {
		str, ok := cString(s.strs, uint32(off))
		require.True(t, ok)
		if str == name {
			return uint32(off)
		}
		off += len(str) + 1
	}
	t.Fatalf("string %q not in base", name)
	return 0
}

// TestParseWideVlen checks that a vlen above 16 bits (kernel 7.2+ BTF) is
// read in full, so the IDs of the types after it stay correct.
func TestParseWideVlen(t *testing.T) {
	const vlen = 0x10001
	b := newBuilder(0)
	b.typ(b.str("big"), kindStruct, vlen, 8, vlen*12) // [1]
	b.typ(b.str("after_big"), kindFunc, 0, 0, 0)      // [2]
	spec, err := parseBase(b.bytes())
	require.NoError(t, err)
	assert.Equal(t, uint32(2), spec.nrTypes)
	id, err := spec.findFunc("after_big")
	require.NoError(t, err)
	assert.Equal(t, uint32(2), id)
}

func TestParseErrors(t *testing.T) {
	_, err := parseBase([]byte{1, 2, 3})
	assert.Error(t, err)

	_, err = parseSplit(nil, nil)
	assert.Error(t, err)

	b := newBuilder(0)
	b.typ(b.str("x"), kindFunc, 0, 0, 0)
	raw := b.bytes()

	bad := append([]byte(nil), raw...)
	binary.LittleEndian.PutUint16(bad[0:], 0x9FeB)
	_, err = parseBase(bad)
	assert.ErrorContains(t, err, "magic")

	bad = append([]byte(nil), raw...)
	binary.LittleEndian.PutUint32(bad[12:], uint32(len(raw))) // type_len past the end
	_, err = parseBase(bad)
	assert.ErrorContains(t, err, "out of bounds")

	b = newBuilder(0)
	b.typ(b.str("x"), 31, 0, 0, 0) // unknown kind
	_, err = parseBase(b.bytes())
	assert.ErrorContains(t, err, "unsupported BTF kind")

	b = newBuilder(0)
	b.typ(b.str("s"), kindStruct, 2, 0, 12) // claims 2 members, has 1
	_, err = parseBase(b.bytes())
	assert.ErrorContains(t, err, "truncated")
}
