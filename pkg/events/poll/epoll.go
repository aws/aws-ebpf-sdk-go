package poll

import (
	"fmt"
	"sync"

	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

type EventPoller struct {
	fds        []uint32
	epollFd    int
	wg         sync.WaitGroup
	epollEvent []unix.EpollEvent
	bufferCnt  int

	stopEventPollerChan   chan struct{}
	updateEventPollerChan chan int
}

func NewEventPoller() (*EventPoller, error) {
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("Failed to create epoll instance: %s", err)
	}
	e := &EventPoller{
		epollFd: epollFD,
	}
	return e, nil
}

func (e *EventPoller) GetEpollFD() int {
	return e.epollFd
}

func (e *EventPoller) AddEpollCtl(mapFD, eventFD int) error {
	epollEvent := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(eventFD),
	}

	err := unix.EpollCtl(e.epollFd, unix.EPOLL_CTL_ADD, mapFD, &epollEvent)
	if err != nil {
		return fmt.Errorf("Failed to Epoll event: %s", err)
	}
	e.epollEvent = append(e.epollEvent, epollEvent)
	return nil
}

func (e *EventPoller) EpollStart() <-chan int {

	e.stopEventPollerChan = make(chan struct{})
	e.updateEventPollerChan = make(chan int)
	e.wg.Add(1)
	go e.eventsPoller()

	return e.updateEventPollerChan
}

func (e *EventPoller) eventsPoller() {
	defer e.wg.Done()
	for {
		select {
		case <-e.stopEventPollerChan:
			return
		default:
			break
		}
		numEvents := e.poll(e.epollEvent[:e.bufferCnt])
		for _, event := range e.epollEvent[:numEvents] {
			select {
			case e.updateEventPollerChan <- int(event.Fd):

			case <-e.stopEventPollerChan:
				return
			}
		}
	}
}

func (e *EventPoller) poll(events []unix.EpollEvent) int {

	timeoutMs := 150
	n, err := unix.EpollWait(e.epollFd, events, timeoutMs)
	if err != nil {
		return 0
	}
	return n
}
