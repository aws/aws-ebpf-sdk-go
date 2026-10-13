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

// Package btf resolves kfunc names to BTF IDs against the running kernel
// (KernelKfuncResolver). Internally it uses a minimal, read-only BTF parser
// that understands just enough of the format (include/uapi/linux/btf.h) to
// walk the type section and find a BTF_KIND_FUNC by name. The parser handles
// both base BTF (vmlinux) and split BTF (kernel modules), where type IDs and
// string offsets continue from the base.
package btf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// btfMagic is BTF_MAGIC from include/uapi/linux/btf.h. It is stored in
	// the producer's byte order, so little-endian BTF reads back as 0xeB9F
	// and big-endian BTF as 0x9FeB.
	btfMagic = 0xeB9F
	// btfHeaderSize is sizeof(struct btf_header): magic (2), version (1),
	// flags (1), hdr_len (4), type_off (4), type_len (4), str_off (4),
	// str_len (4).
	btfHeaderSize = 24
	// btfTypeSize is sizeof(struct btf_type): name_off (4), info (4) and
	// size/type (4). Kind-specific data follows it (see trailingSize).
	btfTypeSize = 12
)

// BTF kinds (BTF_KIND_*), from include/uapi/linux/btf.h. The iota order
// matches the kernel's numbering, so the list must not be reordered.
const (
	kindUnknown = iota
	kindInt
	kindPtr
	kindArray
	kindStruct
	kindUnion
	kindEnum
	kindFwd
	kindTypedef
	kindVolatile
	kindConst
	kindRestrict
	kindFunc
	kindFuncProto
	kindVar
	kindDatasec
	kindFloat
	kindDeclTag
	kindTypeTag
	kindEnum64
)

// errNotFound is returned when no BTF_KIND_FUNC with the requested name exists.
var errNotFound = errors.New("not found")

// btfSpec is a parsed BTF blob. Only the information needed for name lookups of
// functions is kept.
type btfSpec struct {
	base *btfSpec
	strs []byte
	// firstTypeID is the ID of the first type in this blob: 1 for base BTF
	// (ID 0 is the implicit void type), base.firstTypeID+base.nrTypes for split
	// BTF.
	firstTypeID uint32
	nrTypes     uint32
	// strOff is the string offset at which this blob's own strings start: 0
	// for base BTF, the base's total string length for split BTF.
	strOff uint32
	strLen uint32
	// funcs maps a BTF_KIND_FUNC name to its type ID. Only this blob's own
	// types are indexed; findFunc does not search the base.
	funcs map[string]uint32
}

// parseBase parses base BTF, such as /sys/kernel/btf/vmlinux.
func parseBase(raw []byte) (*btfSpec, error) {
	return parse(raw, nil)
}

// parseSplit parses split BTF, such as /sys/kernel/btf/<module>, on top of
// its base.
func parseSplit(raw []byte, base *btfSpec) (*btfSpec, error) {
	if base == nil {
		return nil, errors.New("split BTF requires a base")
	}
	return parse(raw, base)
}

// findFunc returns the type ID of the BTF_KIND_FUNC called name.
func (s *btfSpec) findFunc(name string) (uint32, error) {
	id, ok := s.funcs[name]
	if !ok {
		return 0, fmt.Errorf("func %q: %w", name, errNotFound)
	}
	return id, nil
}

func parse(raw []byte, base *btfSpec) (*btfSpec, error) {
	if len(raw) < btfHeaderSize {
		return nil, fmt.Errorf("BTF blob too short (%d bytes)", len(raw))
	}
	// BTF is in the producer's byte order. Kernel BTF is native-endian and the
	// SDK only targets little-endian hosts (x86_64, arm64).
	le := binary.LittleEndian
	if magic := le.Uint16(raw[0:2]); magic != btfMagic {
		return nil, fmt.Errorf("bad BTF magic 0x%x (only little-endian BTF is supported)", magic)
	}
	// struct btf_header fields; type_off and str_off are relative to the end
	// of the header (hdr_len), not to the start of the blob.
	hdrLen := le.Uint32(raw[4:8])
	typeOff := le.Uint32(raw[8:12])
	typeLen := le.Uint32(raw[12:16])
	strOff := le.Uint32(raw[16:20])
	strLen := le.Uint32(raw[20:24])

	typesStart := uint64(hdrLen) + uint64(typeOff)
	typesEnd := typesStart + uint64(typeLen)
	strStart := uint64(hdrLen) + uint64(strOff)
	strEnd := strStart + uint64(strLen)
	if hdrLen < btfHeaderSize || typesEnd > uint64(len(raw)) || strEnd > uint64(len(raw)) {
		return nil, fmt.Errorf("BTF header out of bounds (hdr_len %d, types %d+%d, strings %d+%d, blob %d)",
			hdrLen, typeOff, typeLen, strOff, strLen, len(raw))
	}
	types := raw[typesStart:typesEnd]
	strs := raw[strStart:strEnd]

	s := &btfSpec{base: base, strs: strs, firstTypeID: 1, strLen: strLen, funcs: make(map[string]uint32)}
	if base != nil {
		s.firstTypeID = base.firstTypeID + base.nrTypes
		s.strOff = base.strOff + base.strLen
	}

	id := s.firstTypeID
	for off := 0; off < len(types); id++ {
		if len(types)-off < btfTypeSize {
			return nil, fmt.Errorf("truncated BTF type %d at offset %d", id, off)
		}
		nameOff := le.Uint32(types[off:])
		// btf_type.info: bits 0-23 are vlen (the number of trailing
		// members/params/values), bits 24-30 are the kind and bit 31 is
		// kind_flag (BTF_INFO_KIND and BTF_INFO_VLEN in btf.h). Kernels
		// before 7.2 use only bits 0-15 and 24-28 and leave the rest zero,
		// so the wider masks read their BTF the same way.
		info := le.Uint32(types[off+4:])
		kind := (info >> 24) & 0x7f
		vlen := int(info & 0xffffff)

		extra, err := trailingSize(kind, vlen)
		if err != nil {
			return nil, fmt.Errorf("BTF type %d: %w", id, err)
		}
		if kind == kindFunc {
			// In split BTF a name may live in the base's string section
			// (pahole dedups split strings against the base).
			if name, ok := s.name(nameOff); ok && name != "" {
				if _, dup := s.funcs[name]; !dup {
					s.funcs[name] = id
				}
			}
		}
		off += btfTypeSize + extra
		if off > len(types) {
			return nil, fmt.Errorf("truncated BTF type %d", id)
		}
	}
	s.nrTypes = id - s.firstTypeID
	return s, nil
}

// name returns the string at offset off, following the chain of base specs
// the same way the kernel does (btf_str_by_offset in kernel/bpf/btf.c).
func (s *btfSpec) name(off uint32) (string, bool) {
	for s != nil && off < s.strOff {
		s = s.base
	}
	if s == nil {
		return "", false
	}
	return cString(s.strs, off-s.strOff)
}

// trailingSize returns the number of bytes that follow struct btf_type for the
// given kind. The sizes are those of the kind-specific structs in btf.h.
func trailingSize(kind uint32, vlen int) (int, error) {
	switch kind {
	case kindPtr, kindFwd, kindTypedef, kindVolatile, kindConst, kindRestrict,
		kindFunc, kindFloat, kindTypeTag:
		return 0, nil
	case kindInt, kindVar, kindDeclTag:
		// A u32 of int encoding, struct btf_var or struct btf_decl_tag.
		return 4, nil
	case kindArray:
		// struct btf_array: type, index_type, nelems.
		return 12, nil
	case kindStruct, kindUnion, kindDatasec, kindEnum64:
		// vlen x struct btf_member, btf_var_secinfo or btf_enum64 (12 bytes
		// each).
		return vlen * 12, nil
	case kindEnum, kindFuncProto:
		// vlen x struct btf_enum or btf_param (8 bytes each).
		return vlen * 8, nil
	default:
		return 0, fmt.Errorf("unsupported BTF kind %d", kind)
	}
}

func cString(strs []byte, off uint32) (string, bool) {
	if uint64(off) >= uint64(len(strs)) {
		return "", false
	}
	end := bytes.IndexByte(strs[off:], 0)
	if end < 0 {
		return "", false
	}
	return string(strs[off : off+uint32(end)]), true
}
