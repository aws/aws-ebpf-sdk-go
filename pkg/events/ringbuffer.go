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

	//Get the len which is uint32 in header struct
	dataLen := atomic.LoadInt32(data)

	// Data len in a record is in ringbufHeader.
	// But the len has busy and discard bit so skip it
	strippedDataLen := ((uint32(dataLen) << 2) >> 2)

	// Entire record len = data length + header length
	recordLen := (strippedDataLen + uint32(ringbufHeaderSize))

	//round up recordLen to nearest 8-byte alignment
	roundedDataLen := (recordLen + 7) &^ 7

	ringdata := &RingData{
		Data:      data,
		Len:       uint32(dataLen),
		DataLen:   uint32(strippedDataLen),
		RecordLen: uint32(roundedDataLen),
	}

	//Update if busy bit is set
	if (ringdata.Len & unix.BPF_RINGBUF_BUSY_BIT) != 0 {
		ringdata.BusyRecord = true
	}

	//Update if record has to be discarded
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
