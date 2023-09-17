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
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"golang.org/x/sys/unix"
)

// for kernel limitations
const maxEventNameLen = 64

// used for rand string generation rand string
const charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

/*
 * Trace event name must comply with the following naming convension:
 *   1. non-empty
 *   2. must not be start with number
 *   3. all characters must be alphanumeric or underscore
 */
var vaildEventNamePat = regexp.MustCompile("^[a-zA-Z_][0-9a-zA-Z_]*$")
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

func New(fd int, fName string) BpfKprobe {
	return &bpfKprobe{
		progFD:   fd,
		funcName: fName,
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

	if !vaildEventNamePat.MatchString(k.funcName) {
		return fmt.Errorf("symbol %s must be alphanumeric or underscore", k.funcName)
	}

	eName, err := genRandomGroup("__goebpf", 8)
	if err != nil {
		return fmt.Errorf("generate Event name: %s", err)
	}
	k.eventName = eName

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
		fmt.Printf("writing writing!!! %s\n", err)
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

// genRandomGroup() generates a string for use as a tracefs group name
// Returns an error if the output doesn't comply with the following rule:
//  1. The naming convention
//  2. the length of the group name must be 63 characters or less
func genRandomGroup(prefix string, n int) (string, error) {
	if !vaildEventNamePat.MatchString(prefix) {
		return "", fmt.Errorf("prefix: %s must be start with alphanumeric or underscore", prefix)
	}

	buff := make([]byte, n)
	if _, err := rand.Read(buff); err != nil {
		return "", fmt.Errorf("failed to read rand bytes: %s", err)
	}

	str := make([]byte, n)
	for _, v := range buff {
		c := charSet[int(v)%len(charSet)]
		str = append(str, c)
	}

	grp := fmt.Sprintf("%s_%s", prefix, string(str))
	if len(grp) > maxEventNameLen-1 {
		return "", fmt.Errorf("group name: %s must be 63 chars or less", grp)
	}

	return grp, nil
}
