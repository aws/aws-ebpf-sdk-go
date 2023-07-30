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

type Ring struct {
	Consumerpos     unsafe.Pointer
	Consumer        []byte
	Producerpos     unsafe.Pointer
	Producer        []byte
	Mask            uint64
	RingBufferMapFD int
	Data            unsafe.Pointer
}

func (r *Ring) getConsumerPosition() uint64 {
	return atomic.LoadUint64((*uint64)(r.Consumerpos))
}

func (r *Ring) setConsumerPosition(newConsumerPosition uint64) {
	atomic.StoreUint64((*uint64)(r.Consumerpos), newConsumerPosition)
}

func (r *Ring) getProducerPosition() uint64 {
	return atomic.LoadUint64((*uint64)(r.Producerpos))

}

func (r *Ring) ParseRingData(consumerPosition uint64) *RingData {
	updateConsumerPosition := (uintptr(consumerPosition) & uintptr(r.Mask))
	data := (*int32)(unsafe.Pointer(uintptr(r.Data) + updateConsumerPosition))

	//Get the len which is uint32 in header struct
	headerLen := atomic.LoadInt32(data)

	// Len in ringbufHeader has busy and discard bit so skip it
	dataLen := (((uint32(headerLen) << 2) >> 2) + uint32(ringbufHeaderSize))
	//round up dataLen to nearest 8-byte alignment
	roundedDataLen := (dataLen + 7) &^ 7

	ringdata := &RingData{
		Data:      data,
		HeaderLen: uint32(headerLen),
		DataLen:   uint32(roundedDataLen),
	}
	return ringdata
}

type RingData struct {
	Data      *int32
	HeaderLen uint32
	DataLen   uint32
}

func (rd *RingData) isBusy() bool {
	return (rd.HeaderLen & unix.BPF_RINGBUF_BUSY_BIT) != 0
}

func (rd *RingData) isDiscard() bool {
	return (rd.HeaderLen & unix.BPF_RINGBUF_DISCARD_BIT) != 0
}

func (rd *RingData) parseSample() []byte {
	readableSample := unsafe.Pointer(uintptr(unsafe.Pointer(rd.Data)) + uintptr(ringbufHeaderSize))
	dataBuf := make([]byte, int(rd.DataLen))
	memcpy(unsafe.Pointer(&dataBuf[0]), readableSample, uintptr(rd.DataLen))
	return dataBuf
}
