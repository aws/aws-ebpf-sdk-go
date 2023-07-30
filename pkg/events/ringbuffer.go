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
	"fmt"
	"os"
	"sync"
	"syscall"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	poller "github.com/aws/aws-ebpf-sdk-go/pkg/events/poll"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

type RingBuffer struct {
	Rings                []*Ring
	PageSize             int
	RingCnt              int
	stopRingBufferChan   chan struct{}
	updateRingBufferChan chan *Ring
	eventsStopChannel    chan struct{}
	wg                   sync.WaitGroup
	eventsDataChannel    chan []byte

	epoller *poller.EventPoller
}

func InitRingBuffer(mapFD int) (<-chan []byte, error) {
	if mapFD == -1 {
		return nil, fmt.Errorf("invalid map FD")
	}
	mapInfo, err := ebpf_maps.GetBPFmapInfo(mapFD)
	if err != nil {
		return nil, fmt.Errorf("failed to map info")
	}
	log.Infof("Got map FD %d", mapFD)
	if mapInfo.Type != constdef.BPF_MAP_TYPE_RINGBUF.Index() {
		return nil, fmt.Errorf("unsupported map type, should be - BPF_MAP_TYPE_RINGBUF")
	}

	rb := &RingBuffer{
		PageSize: os.Getpagesize(),
		RingCnt:  0,
	}

	epoll, err := poller.NewEventPoller()
	if err != nil {
		return nil, fmt.Errorf("failed to create epoll instance: %s", err)
	}
	rb.epoller = epoll

	eventsChan, err := rb.SetupRingBuffer(mapFD, mapInfo.MaxEntries)
	if err != nil {
		rb.CleanupRingBuffer()
		return nil, fmt.Errorf("failed to add ring buffer: %s", err)
	}
	log.Infof("Ringbuffer setup done")
	return eventsChan, nil
}

func (rb *RingBuffer) SetupRingBuffer(mapFD int, maxEntries uint32) (<-chan []byte, error) {
	ring := &Ring{
		RingBufferMapFD: mapFD,
		Mask:            uint64(maxEntries - 1),
	}

	// [Consumer page - 4k][Producer page - 4k][Data section - twice the size of max entries]
	// Refer kernel code, twice the size of max entries will help in boundary scenarios
	// https://github.com/torvalds/linux/blob/master/kernel/bpf/ringbuf.c#L125

	tmp, err := unix.Mmap(mapFD, 0, rb.PageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("failed to create Mmap for consumer -> %d: %s", mapFD, err)
	}

	ring.Consumerpos = unsafe.Pointer(&tmp[0])
	ring.Consumer = tmp

	mmap_sz := uint32(rb.PageSize) + 2*maxEntries
	tmp, err = unix.Mmap(mapFD, int64(rb.PageSize), int(mmap_sz), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		unix.Munmap(tmp)
		return nil, fmt.Errorf("failed to create Mmap for producer -> %d: %s", mapFD, err)
	}

	ring.Producerpos = unsafe.Pointer(&tmp[0])
	ring.Producer = tmp
	ring.Data = unsafe.Pointer(uintptr(unsafe.Pointer(&tmp[0])) + uintptr(rb.PageSize))

	err = rb.epoller.AddEpollCtl(mapFD, rb.RingCnt)
	if err != nil {
		unix.Munmap(tmp)
		return nil, fmt.Errorf("failed to Epoll event: %s", err)
	}

	rb.Rings = append(rb.Rings, ring)
	rb.RingCnt++

	//Start channels read
	rb.eventsStopChannel = make(chan struct{})
	rb.eventsDataChannel = make(chan []byte)

	rb.wg.Add(1)
	go rb.reconcileEventsDataChannel()
	return rb.eventsDataChannel, nil
}

func (rb *RingBuffer) CleanupRingBuffer() {

	for i := 0; i < rb.RingCnt; i++ {
		_ = unix.Munmap(rb.Rings[i].Producer)
		_ = unix.Munmap(rb.Rings[i].Consumer)
		rb.Rings[i].Producerpos = nil
		rb.Rings[i].Consumerpos = nil
	}

	if rb.epoller.GetEpollFD() >= 0 {
		_ = syscall.Close(rb.epoller.GetEpollFD())
	}
	rb.epoller = nil
	rb.Rings = nil
	return
}

func (rb *RingBuffer) reconcileEventsDataChannel() {

	pollerCh := rb.epoller.EpollStart()
	defer func() {
		rb.wg.Done()
	}()

	for {
		select {
		case bufferPtr, ok := <-pollerCh:

			if !ok {
				return
			}
			rb.ReadRingBuffer(rb.Rings[bufferPtr])

		case <-rb.eventsStopChannel:
			return
		}
	}
}

// Similar to libbpf poll ring
func (rb *RingBuffer) ReadRingBuffer(eventRing *Ring) {
	readDone := true
	consPosition := eventRing.getConsumerPosition()
	for !readDone {
		readDone = rb.parseBuffer(consPosition, eventRing)
	}
}

func (rb *RingBuffer) parseBuffer(consumerPosition uint64, eventRing *Ring) bool {
	readDone := true
	producerPosition := eventRing.getProducerPosition()
	for consumerPosition < producerPosition {

		// Get the header - Data points to the DataPage which will be offset by consumerPosition
		ringdata := eventRing.ParseRingData(consumerPosition)

		// Check if busy then skip, Might not be committed yet
		// There are 2 steps -> reserve and then commit/discard
		if ringdata.isBusy() {
			readDone = true
			break
		}

		readDone = false

		// Update the position irrespective of discard or commit of data
		consumerPosition += uint64(ringdata.DataLen)

		//Pick the data only if committed
		if !ringdata.isDiscard() {
			rb.eventsDataChannel <- ringdata.parseSample()
		}
		eventRing.setConsumerPosition(consumerPosition)
	}
	return readDone
}
