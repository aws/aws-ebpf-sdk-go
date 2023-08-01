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

package events

import (
	"encoding/binary"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ringbufHeaderSize = binary.Size(ringbufHeader{})

// ringbufHeader from 'struct bpf_ringbuf_hdr' in kernel/bpf/ringbuf.c
type ringbufHeader struct {
	Len   uint32
	PgOff uint32
}

func memcpy(dst, src unsafe.Pointer, count uintptr) {
	for i := uintptr(0); i < count; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(src) + i))
		*(*byte)(unsafe.Pointer(uintptr(dst) + i)) = b
	}
}

type RingBuffer struct {
	Consumerpos     unsafe.Pointer
	Consumer        []byte
	Producerpos     unsafe.Pointer
	Producer        []byte
	Mask            uint64
	RingBufferMapFD int
	Data            unsafe.Pointer
}

func (r *RingBuffer) getConsumerPosition() uint64 {
	return atomic.LoadUint64((*uint64)(r.Consumerpos))
}

func (r *RingBuffer) setConsumerPosition(newConsumerPosition uint64) {
	atomic.StoreUint64((*uint64)(r.Consumerpos), newConsumerPosition)
}

func (r *RingBuffer) getProducerPosition() uint64 {
	return atomic.LoadUint64((*uint64)(r.Producerpos))

}

func (r *RingBuffer) ParseRingData(consumerPosition uint64) *RingData {
	updateConsumerPosition := (uintptr(consumerPosition) & uintptr(r.Mask))
	data := (*int32)(unsafe.Pointer(uintptr(r.Data) + updateConsumerPosition))

	// Single record will have [header,payload] and header maintains [len, pgoff]
	// len field in the header, is the u32 data len but kernel overloads this field with busy and discard bit
	// BPF_RINGBUF_BUSY_BIT		= (1U << 31)
	// BPF_RINGBUF_DISCARD_BIT	= (1U << 30) [Ref kernel bpf.h]
	// If busy bit is set we skip read i.e, not update consumer position and re-read during next poll
	// if Discard bit is set we just update consumer position but not read the record.
	// We fetch 32 bits value from the data pointer which is the start of the record.
	entryLen := atomic.LoadInt32(data)

	// entryLen now is the "len" in ringbuf Header struct.
	// But this is overloaded with busy and discard bit so skip it to get actual data/record length
	strippedDataLen := ((uint32(entryLen) << 2) >> 2)

	// recordLen will include actual data/record length + header length
	recordLen := (strippedDataLen + uint32(ringbufHeaderSize))

	// round up recordLen to nearest 8-byte alignment which will be the offset for next record start position
	// ref to __bpf_ringbuf_reserve
	// https://github.com/torvalds/linux/blob/master/kernel/bpf/ringbuf.c#L418
	roundedEntryLen := (recordLen + 7) &^ 7

	ringdata := &RingData{
		Data:      data,
		Len:       uint32(entryLen),
		DataLen:   uint32(strippedDataLen),
		RecordLen: uint32(roundedEntryLen),
	}

	// Check if busy bit is set
	if (ringdata.Len & unix.BPF_RINGBUF_BUSY_BIT) != 0 {
		ringdata.BusyRecord = true
	}

	// Check if record has to be discarded
	if (ringdata.Len & unix.BPF_RINGBUF_DISCARD_BIT) != 0 {
		ringdata.DiscardRecord = true
	}
	return ringdata
}

type RingData struct {
	Data          *int32
	Len           uint32
	DataLen       uint32
	RecordLen     uint32
	BusyRecord    bool
	DiscardRecord bool
}

func (rd *RingData) parseSample() []byte {
	readableSample := unsafe.Pointer(uintptr(unsafe.Pointer(rd.Data)) + uintptr(ringbufHeaderSize))
	dataBuf := make([]byte, int(rd.DataLen))
	memcpy(unsafe.Pointer(&dataBuf[0]), readableSample, uintptr(rd.DataLen))
	return dataBuf
}
