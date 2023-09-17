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
	"os"
	"regexp"
	"testing"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	mock_ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	mock_ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs/mocks"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	DUMMY_PROG_NAME = "test"
)

type testMocks struct {
	path       string
	ctrl       *gomock.Controller
	ebpf_progs *mock_ebpf_progs.MockBpfProgAPIs
	ebpf_maps  *mock_ebpf_maps.MockBpfMapAPIs
}

func setup(t *testing.T, testPath string) *testMocks {
	ctrl := gomock.NewController(t)
	return &testMocks{
		path:       testPath,
		ctrl:       ctrl,
		ebpf_progs: mock_ebpf_progs.NewMockBpfProgAPIs(ctrl),
		ebpf_maps:  mock_ebpf_maps.NewMockBpfMapAPIs(ctrl),
	}
}

func TestTCKprobeAttachDetach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	m := setup(t, "../../test-data/test-kprobe.bpf.elf")
	defer m.ctrl.Finish()

	utils.Mount_bpf_fs()
	defer utils.Unmount_bpf_fs()

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	bpfSDKclient := elfparser.New()
	progInfo, _, err := bpfSDKclient.LoadBpfFile(m.path, DUMMY_PROG_NAME)
	if err != nil {
		assert.NoError(t, err)
	}
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_NAME + "_oom_kill"

	progFD := progInfo[pinPath].Program.ProgFD
	funcName := "oom_kill_process"

	kprobeClient := New(progFD, funcName)
	if err := kprobeClient.KprobeAttach(); err != nil {
		assert.NoError(t, err)
	}

	if err := kprobeClient.KprobeDetach(); err != nil {
		assert.NoError(t, err)
	}
}

func TestTCKretprobeAttachDetach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	m := setup(t, "../../test-data/test-kprobe.bpf.elf")
	defer m.ctrl.Finish()

	utils.Mount_bpf_fs()
	defer utils.Unmount_bpf_fs()

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	bpfSDKclient := elfparser.New()
	progInfo, _, err := bpfSDKclient.LoadBpfFile(m.path, DUMMY_PROG_NAME)
	if err != nil {
		assert.NoError(t, err)
	}
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_NAME + "_oom_kill"

	progFD := progInfo[pinPath].Program.ProgFD
	funcName := "oom_kill_process"

	kprobeClient := New(progFD, funcName)
	if err := kprobeClient.KretprobeAttach(); err != nil {
		assert.NoError(t, err)
	}

	if err := kprobeClient.KretprobeDetach(); err != nil {
		assert.NoError(t, err)
	}
}

func TestKprobeGroupName(t *testing.T) {
	grp, err := genRandomGroup("test", 10)
	if err != nil {
		assert.NoError(t, err)
	}
	assert.Regexp(t, regexp.MustCompile("test_[a-zA-Z1-9]{10}"), grp)

	_, err = genRandomGroup("1234", 10)
	assert.Error(t, err)
}
