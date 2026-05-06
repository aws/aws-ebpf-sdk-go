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

package tc

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	mock_ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	mock_ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const (
	DUMMY_PROG_NAME = "test"
)

type testMocks struct {
	path       string
	ctrl       *gomock.Controller
	ebpf_progs *mock_ebpf_progs.MockBpfProgAPIs
	ebpf_maps  *mock_ebpf_maps.MockBpfMapAPIs
	tcClient   BpfTc
}

func setup(t *testing.T, testPath string, interfacePrefix []string) *testMocks {
	ctrl := gomock.NewController(t)
	return &testMocks{
		path:       testPath,
		ctrl:       ctrl,
		ebpf_progs: mock_ebpf_progs.NewMockBpfProgAPIs(ctrl),
		ebpf_maps:  mock_ebpf_maps.NewMockBpfMapAPIs(ctrl),
		tcClient:   New(interfacePrefix),
	}
}

func mount_bpf_fs() error {
	fmt.Println("Let's mount BPF FS")
	err := syscall.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "mode=0700")
	if err != nil {
		fmt.Println("error mounting bpffs")
	}
	return err
}

func unmount_bpf_fs() error {
	fmt.Println("Let's unmount BPF FS")
	err := syscall.Unmount("/sys/fs/bpf", 0)
	if err != nil {
		fmt.Println("error unmounting bpffs")
	}
	return err
}

func setupTest(interfaceNames []string, t *testing.T) {
	mount_bpf_fs()
	for _, interfaceName := range interfaceNames {
		linkAttr := netlink.LinkAttrs{Name: interfaceName}
		linkIFB := netlink.Ifb{}
		linkIFB.LinkAttrs = linkAttr
		if err := netlink.LinkAdd(&linkIFB); err != nil {
			assert.NoError(t, err)
		}
	}
}

func teardownTest(interfaceNames []string, t *testing.T) {
	unmount_bpf_fs()
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

func TestMismatchedPrefixName(t *testing.T) {
	m := setup(t, "../../test-data/tc.bpf.elf", []string{"eni", "vlan"})
	defer m.ctrl.Finish()

	tests := []struct {
		name          string
		interfaceName string
		wantErr       error
	}{
		{
			name:          "Test Matched Prefix",
			interfaceName: "eni1",
			wantErr:       nil,
		},
		{
			name:          "Test Mismatched Prefix",
			interfaceName: "fni1",
			wantErr:       errors.New("Mismatched initialized prefix name and passed interface name"),
		},
		{
			name:          "Test Mismatched Prefix",
			interfaceName: "vlan1",
			wantErr:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := mismatchedInterfacePrefix(tt.interfaceName, []string{"eni", "vlan"})
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTCIngressAttachDetach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	m := setup(t, "../../test-data/tc.bpf.elf", []string{"f"})
	defer m.ctrl.Finish()

	interfaceName := "foo"

	var interfaceNames []string
	interfaceNames = append(interfaceNames, interfaceName)
	setupTest(interfaceNames, t)
	defer teardownTest(interfaceNames, t)

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
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_NAME + "_handle_ingress"

	progFD := progInfo[pinPath].Program.ProgFD
	if err := m.tcClient.TCIngressAttach(interfaceName, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}

	if err := m.tcClient.TCIngressDetach(interfaceName); err != nil {
		assert.NoError(t, err)
	}
}

func TestTCEgressAttachDetach(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	m := setup(t, "../../test-data/tc.bpf.elf", []string{"f"})
	defer m.ctrl.Finish()

	interfaceName := "foo"

	var interfaceNames []string
	interfaceNames = append(interfaceNames, interfaceName)

	setupTest(interfaceNames, t)
	defer teardownTest(interfaceNames, t)

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
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_NAME + "_handle_ingress"

	progFD := progInfo[pinPath].Program.ProgFD
	if err := m.tcClient.TCEgressAttach(interfaceName, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}

	if err := m.tcClient.TCEgressDetach(interfaceName); err != nil {
		assert.NoError(t, err)
	}
}

func TestQdiscCleanup(t *testing.T) {

	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	m := setup(t, "../../test-data/tc.bpf.elf", []string{"eni", "vlan"})
	defer m.ctrl.Finish()

	interfaceName1 := "eni1"
	interfaceName2 := "eni2"
	interfaceName3 := "vlan1"

	var interfaceNames []string
	interfaceNames = append(interfaceNames, interfaceName1, interfaceName2, interfaceName3)

	setupTest(interfaceNames, t)
	defer teardownTest(interfaceNames, t)

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
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_NAME + "_handle_ingress"

	progFD := progInfo[pinPath].Program.ProgFD
	if err := m.tcClient.TCEgressAttach(interfaceName1, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}

	if err := m.tcClient.TCIngressAttach(interfaceName2, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}

	if err := m.tcClient.CleanupQdiscs(true, true); err != nil {
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
		want          []int
		wantErr       error
	}{
		{
			name:          "Failed Link By Name",
			interfaceName: "eni1",
			want:          nil,
			overrideName:  true,
			wantErr:       errors.New("Link not found"),
		},
		{
			name:          "Failed to add filter",
			interfaceName: "eni1",
			overrideName:  false,
			want:          nil,
			wantErr:       errors.New("invalid argument"),
		},
	}

	for _, tt := range netLinktests {
		t.Run(tt.name, func(t *testing.T) {
			m := setup(t, "../../test-data/tc.bpf.elf", []string{"eni", "vlan"})
			defer m.ctrl.Finish()

			var interfaceNames []string
			interfaceNames = append(interfaceNames, tt.interfaceName)

			setupTest(interfaceNames, t)
			defer teardownTest(interfaceNames, t)

			m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

			bpfSDKclient := elfparser.New()
			_, _, err := bpfSDKclient.LoadBpfFile(m.path, DUMMY_PROG_NAME)
			if err != nil {
				assert.NoError(t, err)
			}

			intfName := tt.interfaceName
			if tt.overrideName {
				intfName = intfName + "10"
			}
			err = m.tcClient.TCEgressAttach(intfName, -1, "test")
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}
			err = m.tcClient.TCIngressAttach(intfName, -1, "test")
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
