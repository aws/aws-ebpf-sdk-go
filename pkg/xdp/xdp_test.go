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

package xdp

import (
	"errors"
	"os"
	"testing"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	mock_ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	mock_ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs/mocks"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	DUMMY_PROG_PREFIX = "test"
	DUMMY_PROG_NAME   = "xdp_test_prog"
)

type testMocks struct {
	path       string
	ctrl       *gomock.Controller
	ebpf_progs *mock_ebpf_progs.MockBpfProgAPIs
	ebpf_maps  *mock_ebpf_maps.MockBpfMapAPIs
	xdpClient  BpfXdp
}

func setup(t *testing.T, testPath string, interfaceName string) *testMocks {
	ctrl := gomock.NewController(t)
	return &testMocks{
		path:       testPath,
		ctrl:       ctrl,
		ebpf_progs: mock_ebpf_progs.NewMockBpfProgAPIs(ctrl),
		ebpf_maps:  mock_ebpf_maps.NewMockBpfMapAPIs(ctrl),
		xdpClient:  New(interfaceName),
	}
}

func setupTest(interfaceNames []string, t *testing.T) {
	utils.Mount_bpf_fs()
	for _, interfaceName := range interfaceNames {
		linkAttr := netlink.LinkAttrs{Name: interfaceName}
		linkIFB := netlink.Ifb{}
		linkIFB.LinkAttrs = linkAttr
		if err := netlink.LinkAdd(&linkIFB); err != nil {
			assert.NoError(t, err)
		}
	}
}

func teardownTest(interfaceNames []string, t *testing.T, ignoreDelErr bool) {
	utils.Unmount_bpf_fs()
	//Cleanup link
	for _, interfaceName := range interfaceNames {
		linkAttr := netlink.LinkAttrs{Name: interfaceName}
		linkIFB := netlink.Ifb{}
		linkIFB.LinkAttrs = linkAttr
		if err := netlink.LinkDel(&linkIFB); err != nil && !ignoreDelErr {
			assert.NoError(t, err)
		}
	}
}

func deleteLinks(interfaceNames []string, t *testing.T) {
	//Cleanup link
	for _, interfaceName := range interfaceNames {
		linkAttr := netlink.LinkAttrs{Name: interfaceName}
		linkIFB := netlink.Ifb{}
		linkIFB.LinkAttrs = linkAttr
		if err := netlink.LinkDel(&linkIFB); err != nil {
			assert.NoError(t, err)
		}
	}
}

func TestTCXdpAttachDetach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	interfaceName := "foo1"

	m := setup(t, "../../test-data/xdp.bpf.elf", interfaceName)
	defer m.ctrl.Finish()

	var interfaceNames []string
	interfaceNames = append(interfaceNames, interfaceName)
	setupTest(interfaceNames, t)
	defer teardownTest(interfaceNames, t, false)

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	bpfSDKclient := elfparser.New()
	progInfo, _, err := bpfSDKclient.LoadBpfFile(m.path, DUMMY_PROG_PREFIX)
	if err != nil {
		assert.NoError(t, err)
	}
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_PREFIX + "_" + DUMMY_PROG_NAME

	progFD := progInfo[pinPath].Program.ProgFD
	if err := m.xdpClient.XDPAttach(progFD); err != nil {
		assert.NoError(t, err)
	}

	if err := m.xdpClient.XDPDetach(); err != nil {
		assert.NoError(t, err)
	}
}

func TestNetLinkAPIs(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges to create network interfaces and attach BPF programs.")
	}

	netLinktests := []struct {
		name          string
		interfaceName string
		overrideName  bool
		overrideProg  bool
		skipAttach    bool
		want          []int
		wantErr       error
	}{
		{
			name:          "Failed Link By Name",
			interfaceName: "foo2",
			want:          nil,
			overrideName:  true,
			wantErr:       errors.New("Link not found"),
		},
		{
			name:          "Invalid Program",
			interfaceName: "foo3",
			want:          nil,
			overrideProg:  true,
			wantErr:       errors.New("invalid argument"),
		},
		{
			name:          "Detach without attach Program",
			interfaceName: "foo4",
			want:          nil,
			skipAttach:    true,
			wantErr:       nil,
		},
	}

	for _, tt := range netLinktests {
		t.Run(tt.name, func(t *testing.T) {
			m := setup(t, "../../test-data/xdp.bpf.elf", tt.interfaceName)
			defer m.ctrl.Finish()

			var interfaceNames []string
			interfaceNames = append(interfaceNames, tt.interfaceName)

			setupTest(interfaceNames, t)
			defer teardownTest(interfaceNames, t, tt.overrideName)

			m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

			bpfSDKclient := elfparser.New()
			progInfo, _, err := bpfSDKclient.LoadBpfFile(m.path, DUMMY_PROG_PREFIX)
			if err != nil {
				assert.NoError(t, err)
			}

			if tt.overrideName {
				deleteLinks(interfaceNames, t)
			}

			pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_PREFIX + "_" + DUMMY_PROG_NAME

			progFD := progInfo[pinPath].Program.ProgFD

			if tt.overrideProg {
				progFD = 0
			}
			if !tt.skipAttach {
				err = m.xdpClient.XDPAttach(progFD)
				if tt.wantErr != nil {
					assert.EqualError(t, err, tt.wantErr.Error())
				} else {
					assert.NoError(t, err)
				}
			}

			if tt.skipAttach {
				err = m.xdpClient.XDPDetach()
				if tt.wantErr != nil {
					assert.EqualError(t, err, tt.wantErr.Error())
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}
