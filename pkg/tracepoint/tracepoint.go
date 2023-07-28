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

package tracepoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

func TracepointAttach(progFD int, subSystem, eventName string) error {

	if progFD <= 0 {
		log.Infof("Invalid BPF prog FD %d", progFD)
		return fmt.Errorf("invalid BPF prog FD %d", progFD)

	}

	if len(subSystem) == 0 || len(eventName) == 0 {
		return fmt.Errorf("invalid Arguement")
	}

	//Get the TP ID
	tracepointIDpath := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", subSystem, eventName)
	data, err := os.ReadFile(tracepointIDpath)
	if err != nil {
		log.Errorf("unable to read the tracepointID: %v", err)
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

	log.Infof("Attach bpf program to perf event Prog FD %d Event FD %d", progFD, fd)

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_SET_BPF)), uintptr(progFD)); err != 0 {
		log.Errorf("error attaching bpf program to perf event: %v", err)
		return err
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(int(fd)), uintptr(uint(unix.PERF_EVENT_IOC_ENABLE)), 0); err != 0 {
		log.Errorf("error enabling perf event: %v", err)
		return err
	}

	log.Infof("Attach done!!! %d", fd)
	return nil
}
