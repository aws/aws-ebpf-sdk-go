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

package kprobe

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

type BpfKprobe interface {
	KprobeAttach() error
	KretprobeAttach() error
	KprobeDetach() error
	KretprobeDetach() error
}

var _ BpfKprobe = &bpfKprobe{}

type bpfKprobe struct {
	progFD    int
	eventName string
	funcName  string
	perfFD    int
}

func New(fd int, eName, fName string) BpfKprobe {
	return &bpfKprobe{
		progFD:    fd,
		eventName: eName,
		funcName:  fName,
	}

}

func (k *bpfKprobe) SetPerfFD(perfFD int) {
	k.perfFD = perfFD
}

func (k *bpfKprobe) GetPerfFD() int {
	return k.perfFD
}

/*
p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]  : Set a probe
r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]  : Set a return probe
-:[GRP/]EVENT
*/
func (k *bpfKprobe) KprobeAttach() error {

	if k.progFD <= 0 {
		log.Errorf("invalid BPF prog FD %d", k.progFD)
		return fmt.Errorf("Invalid BPF prog FD %d", k.progFD)

	}

	// if event is nil, we pick funcName
	if len(k.eventName) == 0 {
		k.eventName = k.funcName
	}

	// Register the Kprobe event
	file, err := os.OpenFile(constdef.KPROBE_SYS_EVENTS, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		log.Errorf("error opening kprobe_events file: %v", err)
		return err
	}
	defer file.Close()

	eventString := fmt.Sprintf("p:kprobes/%s %s", k.eventName, k.funcName)
	_, err = file.WriteString(eventString)
	if err != nil {
		log.Errorf("error writing to kprobe_events file: %v", err)
		return err
	}

	//Get the Kprobe ID
	kprobeIDpath := fmt.Sprintf("%s/%s/id", constdef.KPROBE_SYS_DEBUG, k.eventName)
	data, err := os.ReadFile(kprobeIDpath)
	if err != nil {
		log.Errorf("unable to read the kprobeID: %v", err)
		return err
	}
	id := strings.TrimSpace(string(data))
	eventID, err := strconv.Atoi(id)
	if err != nil {
		log.Errorf("invalid ID during parsing: %s - %w", id, err)
		return err
	}

	log.Infof("Got eventID %d", eventID)

	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Sample: 1,
		Wakeup: 1,
		Config: uint64(eventID),
	}
	attr.Size = uint32(unsafe.Sizeof(attr))

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		log.Errorf("failed to open perf event %v", err)
		return err
	}

	log.Infof("Attach bpf program to perf event Prog FD %d Event FD %d", k.progFD, fd)

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_SET_BPF)), uintptr(k.progFD)); err != 0 {
		log.Errorf("error attaching bpf program to perf event: %v", err)
		return err
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		log.Errorf("error enabling perf event: %v", err)
		return err
	}

	k.SetPerfFD(fd)

	log.Infof("KPROBE Attach done!!! %d", fd)

	return nil

}

/*
	p[:[GRP/]EVENT] [MOD:]SYM[+offs]|MEMADDR [FETCHARGS]  : Set a probe
	r[MAXACTIVE][:[GRP/]EVENT] [MOD:]SYM[+0] [FETCHARGS]  : Set a return probe
	-:[GRP/]EVENT

MAXACTIVE      : Maximum number of instances of the specified function that

	can be probed simultaneously, or 0 for the default value
	as defined in Documentation/kprobes.txt section 1.3.1.
*/
func (k *bpfKprobe) KretprobeAttach() error {

	if k.progFD <= 0 {
		log.Infof("invalid BPF prog FD %d", k.progFD)
		return fmt.Errorf("Invalid BPF prog FD %d", k.progFD)

	}
	// if event is nil, we pick funcName
	if len(k.eventName) == 0 {
		k.eventName = k.funcName
	}

	// Register the Kprobe event
	file, err := os.OpenFile(constdef.KPROBE_SYS_EVENTS, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		log.Errorf("error opening kprobe_events file: %v", err)
		return err
	}
	defer file.Close()

	eventString := fmt.Sprintf("r4096:kretprobes/%s %s", k.eventName, k.funcName)
	_, err = file.WriteString(eventString)
	if err != nil {
		log.Errorf("error writing to kprobe_events file: %v", err)
		return err
	}

	//Get the Kprobe ID
	kprobeIDpath := fmt.Sprintf("%s/%s/id", constdef.KRETPROBE_SYS_DEBUG, k.eventName)
	data, err := os.ReadFile(kprobeIDpath)
	if err != nil {
		log.Errorf("unable to read the kretprobeID: %v", err)
		return err
	}
	id := strings.TrimSpace(string(data))
	eventID, err := strconv.Atoi(id)
	if err != nil {
		log.Errorf("invalid ID during parsing: %s - %w", id, err)
		return err
	}

	log.Infof("Got eventID %d", eventID)

	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Sample: 1,
		Wakeup: 1,
		Config: uint64(eventID),
	}
	attr.Size = uint32(unsafe.Sizeof(attr))

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		log.Errorf("failed to open perf event %v", err)
		return err
	}

	log.Infof("Attach bpf program to perf event Prog FD %d Event FD %d", k.progFD, fd)

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_SET_BPF)), uintptr(k.progFD)); err != 0 {
		log.Errorf("error attaching bpf program to perf event: %v", err)
		return err
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		log.Errorf("error enabling perf event: %v", err)
		return err
	}

	k.SetPerfFD(fd)

	log.Infof("KRETPROBE Attach done!!! %d", fd)
	return nil

}

func probeDetach(eventName string, perfFD int, kretProbe bool) error {
	log.Infof("Calling Detach on %s", eventName)

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(perfFD)), uintptr(uint(unix.PERF_EVENT_IOC_DISABLE)), 0); err != 0 {
		log.Errorf("error enabling perf event: %v", err)
		return err
	}
	unix.Close(perfFD)

	eventEnable := constdef.KPROBE_SYS_DEBUG + "/" + eventName + "/enable"
	if kretProbe {
		eventEnable = constdef.KRETPROBE_SYS_DEBUG + "/" + eventName + "/enable"
	}

	setEnable := []byte("0")

	err := ioutil.WriteFile(eventEnable, setEnable, os.ModePerm)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(constdef.KPROBE_SYS_EVENTS, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		log.Errorf("cannot open probe events: %v", err)
		return err
	}
	defer file.Close()

	eventString := fmt.Sprintf("-:%s\n", eventName)
	if _, err = file.WriteString(eventString); err != nil {
		pathErr, ok := err.(*os.PathError)
		if ok && pathErr.Err == syscall.ENOENT {
			log.Infof("File is already cleanedup, maybe some other process?")
			return nil
		}
		log.Errorf("cannot update the probe events %v", err)
		return err
	}
	log.Infof("probe Detach done!!!")
	return nil
}

func (k *bpfKprobe) KprobeDetach() error {
	log.Infof("Calling Kprobe Detach on %s", k.eventName)
	return probeDetach(k.eventName, k.perfFD, false)
}

func (k *bpfKprobe) KretprobeDetach() error {
	log.Infof("Calling Kretprobe Detach on %s", k.eventName)
	return probeDetach(k.eventName, k.perfFD, true)
}
