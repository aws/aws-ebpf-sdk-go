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

	bpfSDKclient := elfparser.New(elfparser.Config{})
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

	bpfSDKclient := elfparser.New(elfparser.Config{})
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

	bpfSDKclient := elfparser.New(elfparser.Config{})
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

// countFiltersAtHook returns the number of BPF filters installed on the given
// host-perspective TC hook (netlink.HANDLE_MIN_INGRESS or HANDLE_MIN_EGRESS)
// that carry the SDK's default filter handle.
func countFiltersAtHook(t *testing.T, interfaceName string, filterParent uint32) int {
	intf, err := netlink.LinkByName(interfaceName)
	assert.NoError(t, err)

	filters, err := netlink.FilterList(intf, filterParent)
	assert.NoError(t, err)

	count := 0
	for _, filter := range filters {
		if filter.Attrs().Handle == uint32(constdef.DEFAULT_BPF_FILTER_HANDLE) {
			count++
		}
	}
	return count
}

// TestQdiscCleanupDirection verifies that CleanupQdiscs detaches the correct
// host-perspective TC hook for a given pod direction. TC hooks are named from
// the host's perspective, so a pod-ingress program lives on the host tc-egress
// hook and a pod-egress program lives on the host tc-ingress hook.
//
// After CleanupQdiscs(podIngressCleanup=true, podEgressCleanup=false), the
// tc-egress hook (pod ingress) must be empty while the tc-ingress hook (pod
// egress) must still hold its filter. The pre-fix implementation detached the
// wrong hook, so this asserts the direction, not merely the absence of errors.
func TestQdiscCleanupDirection(t *testing.T) {

	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	m := setup(t, "../../test-data/tc.bpf.elf", []string{"eni", "vlan"})
	defer m.ctrl.Finish()

	interfaceName := "eni1"

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

	bpfSDKclient := elfparser.New(elfparser.Config{})
	progInfo, _, err := bpfSDKclient.LoadBpfFile(m.path, DUMMY_PROG_NAME)
	if err != nil {
		assert.NoError(t, err)
	}
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_NAME + "_handle_ingress"
	progFD := progInfo[pinPath].Program.ProgFD

	// Pod ingress program -> host tc-egress hook (HANDLE_MIN_EGRESS).
	if err := m.tcClient.TCEgressAttach(interfaceName, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}
	// Pod egress program -> host tc-ingress hook (HANDLE_MIN_INGRESS).
	if err := m.tcClient.TCIngressAttach(interfaceName, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}

	// Both hooks should hold a filter before cleanup.
	assert.Equal(t, 1, countFiltersAtHook(t, interfaceName, uint32(netlink.HANDLE_MIN_EGRESS)),
		"tc-egress hook (pod ingress) should hold a filter before cleanup")
	assert.Equal(t, 1, countFiltersAtHook(t, interfaceName, uint32(netlink.HANDLE_MIN_INGRESS)),
		"tc-ingress hook (pod egress) should hold a filter before cleanup")

	// Clean up pod ingress only.
	if err := m.tcClient.CleanupQdiscs(true, false); err != nil {
		assert.NoError(t, err)
	}

	// Pod ingress lives on the tc-egress hook -> must now be empty.
	assert.Equal(t, 0, countFiltersAtHook(t, interfaceName, uint32(netlink.HANDLE_MIN_EGRESS)),
		"tc-egress hook (pod ingress) should be empty after CleanupQdiscs(true, false)")
	// Pod egress lives on the tc-ingress hook -> must still hold its filter.
	assert.Equal(t, 1, countFiltersAtHook(t, interfaceName, uint32(netlink.HANDLE_MIN_INGRESS)),
		"tc-ingress hook (pod egress) should still hold its filter after CleanupQdiscs(true, false)")
}

// TestGetAllAttachedProgIdsDirection verifies that GetAllAttachedProgIds reports
// each pod direction from the host hook its program is actually attached to.
// A pod-ingress program lives on the host tc-egress hook and a pod-egress
// program lives on the host tc-ingress hook, so the first returned map
// (pod ingress) must reflect what TCEgressAttach attached and the second
// (pod egress) must reflect what TCIngressAttach attached.
//
// eni1 gets only a pod-ingress program (host egress hook); eni2 gets only a
// pod-egress program (host ingress hook). The returned maps must not be swapped.
func TestGetAllAttachedProgIdsDirection(t *testing.T) {

	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}

	m := setup(t, "../../test-data/tc.bpf.elf", []string{"eni", "vlan"})
	defer m.ctrl.Finish()

	podIngressIface := "eni1"
	podEgressIface := "eni2"

	interfaceNames := []string{podIngressIface, podEgressIface}

	setupTest(interfaceNames, t)
	defer teardownTest(interfaceNames, t)

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	bpfSDKclient := elfparser.New(elfparser.Config{})
	progInfo, _, err := bpfSDKclient.LoadBpfFile(m.path, DUMMY_PROG_NAME)
	if err != nil {
		assert.NoError(t, err)
	}
	pinPath := constdef.PROG_BPF_FS + DUMMY_PROG_NAME + "_handle_ingress"
	progFD := progInfo[pinPath].Program.ProgFD

	// Pod ingress program on eni1 -> host tc-egress hook.
	if err := m.tcClient.TCEgressAttach(podIngressIface, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}
	// Pod egress program on eni2 -> host tc-ingress hook.
	if err := m.tcClient.TCIngressAttach(podEgressIface, progFD, DUMMY_PROG_NAME); err != nil {
		assert.NoError(t, err)
	}

	podIngressProgIds, podEgressProgIds, err := m.tcClient.GetAllAttachedProgIds()
	assert.NoError(t, err)

	// eni1 (pod ingress on host egress hook) must appear in the pod-ingress map,
	// not the pod-egress map.
	_, inPodIngress := podIngressProgIds[podIngressIface]
	_, inPodEgress := podEgressProgIds[podIngressIface]
	assert.True(t, inPodIngress, "eni1 pod-ingress program should be reported in the pod-ingress map")
	assert.False(t, inPodEgress, "eni1 pod-ingress program must not be reported in the pod-egress map")

	// eni2 (pod egress on host ingress hook) must appear in the pod-egress map,
	// not the pod-ingress map.
	_, inPodEgress2 := podEgressProgIds[podEgressIface]
	_, inPodIngress2 := podIngressProgIds[podEgressIface]
	assert.True(t, inPodEgress2, "eni2 pod-egress program should be reported in the pod-egress map")
	assert.False(t, inPodIngress2, "eni2 pod-egress program must not be reported in the pod-ingress map")
}

func TestNetLinkAPIs(t *testing.T) {

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
			m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

			bpfSDKclient := elfparser.New(elfparser.Config{})
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
