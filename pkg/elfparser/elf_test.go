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

package elfparser

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	mock_ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	mock_ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs/mocks"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var testNamespacedMaps = []string{
	"ingress_map", "egress_map", "ingress_pod_state_map",
	"egress_pod_state_map", "cp_ingress_map", "cp_egress_map", "ipcache_map",
}

var (
	MAP_SECTION_INDEX = 8
	MAP_TYPE_1        = int(constdef.BPF_MAP_TYPE_LRU_HASH.Index())
	MAP_KEY_SIZE_1    = 16
	MAP_VALUE_SIZE_1  = 4
	MAP_ENTRIES_1     = 65536
	MAP_FLAGS_1       = 0
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

func TestLoad(t *testing.T) {
	progtests := []struct {
		name        string
		elfFileName string
		wantMap     int
		wantProg    int
	}{
		{
			name:        "Test Load ELF",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			wantMap:     3,
			wantProg:    3,
		},
		{
			name:        "Test Load ELF without reloc",
			elfFileName: "../../test-data/tc.bpf.elf",
			wantMap:     0,
			wantProg:    1,
		},
		{
			name:        "Missing prog data",
			elfFileName: "../../test-data/test.map.bpf.elf",
			wantMap:     1,
			wantProg:    0,
		},
		{
			name:        "Test Load ELF with subprograms",
			elfFileName: "../../test-data/tc.subprog.bpf.elf",
			wantMap:     1,
			wantProg:    1,
		},
		{
			name:        "Test Load ELF with chained subprograms",
			elfFileName: "../../test-data/tc.subprog_chain.bpf.elf",
			wantMap:     1,
			wantProg:    1,
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes()
			m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)
			loadedProgs, loadedMaps, err := elfLoader.doLoadELF(BpfCustomData{})
			assert.NoError(t, err)
			assert.Equal(t, tt.wantProg, len(loadedProgs))
			assert.Equal(t, tt.wantMap, len(loadedMaps))
		})
	}
}

func TestParseSection(t *testing.T) {

	tests := []struct {
		name        string
		elfFileName string
		want        []string
		wantErr     error
	}{
		{
			name:        "Test license section",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        []string{"GPL\u0000"},
		},
		{
			name:        "Missing license section",
			elfFileName: "../../test-data/test_license.bpf.elf",
			want:        []string{},
			wantErr:     errors.New("license missing in elf file"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotLicense []string
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				gotLicense = append(gotLicense, elfLoader.license)
				assert.Equal(t, tt.want, gotLicense)
			}
		})
	}

	maptests := []struct {
		name        string
		elfFileName string
		want        int
		wantErr     error
	}{
		{
			name:        "Test map section",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			//Assumption is mapindex is always 8 based on elf data we are using. This can be any non-zero.
			want: MAP_SECTION_INDEX,
		},
		{
			name:        "Missing map section",
			elfFileName: "../../test-data/tc.bpf.elf",
			want:        0,
			wantErr:     nil,
		},
	}

	for _, tt := range maptests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				gotMapIndex := elfLoader.mapSectionIndex
				assert.Equal(t, tt.want, gotMapIndex)
			}
		})
	}

	texttests := []struct {
		name            string
		elfFileName     string
		wantTextSection bool
		wantTextRelo    bool
	}{
		{
			name:            "Empty .text section in regular ELF",
			elfFileName:     "../../test-data/tc.ingress.bpf.elf",
			wantTextSection: true,  // clang always emits a .text section
			wantTextRelo:    false, // but no .rel.text for regular ELFs
		},
		{
			name:            "Has .text section with subprograms",
			elfFileName:     "../../test-data/tc.subprog.bpf.elf",
			wantTextSection: true,
			wantTextRelo:    true, // has .rel.text for map relocation in subprogram
		},
	}

	for _, tt := range texttests {
		t.Run(tt.name, func(t *testing.T) {
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			assert.NoError(t, err)

			if tt.wantTextSection {
				assert.NotNil(t, elfLoader.textSection)
				assert.NotEqual(t, -1, elfLoader.textSectionIndex)
			} else {
				assert.Nil(t, elfLoader.textSection)
				assert.Equal(t, -1, elfLoader.textSectionIndex)
			}

			if tt.wantTextRelo {
				assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)])
			}
		})
	}

	progtests := []struct {
		name        string
		elfFileName string
		want        []string
		wantErr     error
	}{
		{
			name:        "Test prog section",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        []string{"tc_cls", "kprobe/nf_ct_delete", "tracepoint/sched/sched_process_fork"},
		},
		{
			// The elf file has supported and non-supported progs so we skip non-supported.
			name:        "Test unsupported prog section",
			elfFileName: "../../test-data/tc.bpf.elf",
			want:        []string{"tc_cls"},
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {
			var gotProgNames []string
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				gotProgSections := elfLoader.progSectionMap
				for _, progEntry := range gotProgSections {
					gotProgNames = append(gotProgNames, progEntry.progSection.Name)
				}
				sort.Strings(tt.want)
				sort.Strings(gotProgNames)
				assert.Equal(t, tt.want, gotProgNames)
			}
		})
	}

	reloctests := []struct {
		name        string
		elfFileName string
		expectList  []string
		want        int
		wantErr     error
	}{
		{
			name:        "Test reloc flow",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			expectList:  []string{"kprobe", "tc_cls", "tracepoint", "xdp"},
			want:        2,
			wantErr:     nil,
		},
		{
			name:        "Validate elf file without reloc requirement",
			elfFileName: "../../test-data/tc.bpf.elf",
			expectList:  []string{"kprobe", "tc_cls", "tracepoint", "xdp"},
			want:        0,
			wantErr:     nil,
		},
	}

	for _, tt := range reloctests {
		t.Run(tt.name, func(t *testing.T) {
			var gotSupportedType []string
			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for _, r := range elfLoader.reloSectionMap {
					if contains(tt.expectList, r.Name) {
						gotSupportedType = append(gotSupportedType, r.Name)
					}
				}
				assert.Equal(t, tt.want, len(gotSupportedType))
			}
		})
	}
}

func contains(expectedList []string, expectedStr string) bool {
	for _, str := range expectedList {
		if strings.Contains(expectedStr, str) {
			return true
		}
	}
	return false
}

func TestParseMap(t *testing.T) {
	maptests := []struct {
		name        string
		elfFileName string
		want        int
		wantErr     error
	}{
		{
			name:        "Missing map section",
			elfFileName: "../../test-data/tc.bpf.elf",
			want:        0,
			wantErr:     nil,
		},
		{
			name:        "Test map data",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        3,
			wantErr:     nil,
		},
	}

	for _, tt := range maptests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			assert.NoError(t, err)
			mapData, err := elfLoader.parseMap(BpfCustomData{})
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				mapCount := len(mapData)
				assert.Equal(t, tt.want, mapCount)
			}
		})
	}

	mapcontentstests := []struct {
		name        string
		elfFileName string
		invalidate  bool
		want        []int
		wantErr     error
	}{
		{
			name:        "Test map contents",
			elfFileName: "../../test-data/test.map.bpf.elf",
			invalidate:  false,
			want:        []int{MAP_TYPE_1, MAP_KEY_SIZE_1, MAP_VALUE_SIZE_1, MAP_ENTRIES_1, MAP_FLAGS_1},
			wantErr:     nil,
		},
		{
			name:        "Invalid map contents",
			elfFileName: "../../test-data/test.map.bpf.elf",
			invalidate:  true,
			want:        nil,
			wantErr:     errors.New("missing data in map section"),
		},
	}

	for _, tt := range mapcontentstests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			var parsedMapData []int
			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			assert.NoError(t, err)
			if tt.invalidate {
				var dummySection elf.Section = elf.Section{}
				copiedMapSection := *(elfLoader.mapSection)
				copiedMapSection.SectionHeader = dummySection.SectionHeader
				elfLoader.mapSection = &copiedMapSection
			}
			mapData, err := elfLoader.parseMap(BpfCustomData{})
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				for _, data := range mapData {
					parsedMapData = append(parsedMapData, int(data.Type))
					parsedMapData = append(parsedMapData, int(data.KeySize))
					parsedMapData = append(parsedMapData, int(data.ValueSize))
					parsedMapData = append(parsedMapData, int(data.MaxEntries))
					parsedMapData = append(parsedMapData, int(data.Flags))
				}
				assert.Equal(t, tt.want, parsedMapData)
			}
		})
	}

}

func TestParseProg(t *testing.T) {
	progtests := []struct {
		name           string
		elfFileName    string
		want           int
		invalidate     bool
		invalidateRelo bool
		wantErr        error
	}{
		{
			name:        "Missing prog section",
			elfFileName: "../../test-data/test.map.bpf.elf",
			want:        0,
			wantErr:     nil,
		},
		{
			name:        "Test prog data",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			want:        3,
			wantErr:     nil,
		},
		{
			name:        "Test prog data with subprograms",
			elfFileName: "../../test-data/tc.subprog.bpf.elf",
			want:        1,
			wantErr:     nil,
		},
		{
			name:        "Missing prog data",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			invalidate:  true,
			wantErr:     errors.New("missing data in prog section"),
		},
		{
			name:           "Missing relo data",
			elfFileName:    "../../test-data/tc.ingress.bpf.elf",
			invalidateRelo: true,
			wantErr:        errors.New("failed to apply relocation: unable to parse relocation entries...."),
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()
			f, _ := os.Open(m.path)
			defer f.Close()

			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

			err = elfLoader.parseSection()
			assert.NoError(t, err)

			mapData, err := elfLoader.parseMap(BpfCustomData{})
			assert.NoError(t, err)

			m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
			m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

			loadedMapData, err := elfLoader.loadMap(mapData)
			assert.NoError(t, err)

			if tt.invalidate {
				for progIndex, progEntry := range elfLoader.progSectionMap {
					var dummySection elf.Section = elf.Section{}
					copiedprogSection := *(progEntry.progSection)
					copiedprogSection.SectionHeader = dummySection.SectionHeader
					progEntry.progSection = &copiedprogSection
					elfLoader.progSectionMap[progIndex] = progEntry
				}
			}

			if tt.invalidateRelo {
				for progIndex, reloSection := range elfLoader.reloSectionMap {
					var dummySection elf.Section = elf.Section{}
					copiedreloSection := *(reloSection)
					copiedreloSection.SectionHeader = dummySection.SectionHeader
					reloSection = &copiedreloSection
					elfLoader.reloSectionMap[progIndex] = reloSection
				}
			}

			parsedProgData, err := elfLoader.parseProg(loadedMapData)

			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				progCount := len(parsedProgData)
				assert.Equal(t, tt.want, progCount)
			}
		})
	}

}

func TestRecovery(t *testing.T) {

	utils.Mount_bpf_fs()
	defer utils.Unmount_bpf_fs()

	progtests := []struct {
		name          string
		elfFileName   string
		wantMap       int
		wantProg      int
		recoverGlobal bool
		forceUnMount  bool
		wantErr       error
	}{
		{
			name:          "Recover Global maps",
			elfFileName:   "../../test-data/test.map.bpf.elf",
			wantMap:       1,
			recoverGlobal: true,
			wantErr:       nil,
		},
		{
			name:        "Recover BPF data",
			elfFileName: "../../test-data/recoverydata.bpf.elf",
			wantProg:    3,
			wantErr:     nil,
		},
	}

	for _, tt := range progtests {
		t.Run(tt.name, func(t *testing.T) {

			m := setup(t, tt.elfFileName)
			defer m.ctrl.Finish()

			bpfSDKclient := New(Config{NamespacedMaps: testNamespacedMaps})

			if tt.recoverGlobal {
				_, _, err := bpfSDKclient.LoadBpfFile(m.path, "global")
				if err != nil {
					assert.NoError(t, err)
				}
				recoveredMaps, err := bpfSDKclient.RecoverGlobalMaps()
				if tt.wantErr != nil {
					assert.EqualError(t, err, tt.wantErr.Error())
				} else {
					assert.Equal(t, tt.wantMap, len(recoveredMaps))
				}
			} else {
				_, _, err := bpfSDKclient.LoadBpfFile(m.path, "test")
				if err != nil {
					assert.NoError(t, err)
				}

				recoveredData, err := bpfSDKclient.RecoverAllBpfProgramsAndMaps()
				if tt.wantErr != nil {
					assert.EqualError(t, err, tt.wantErr.Error())
				} else {
					assert.Equal(t, tt.wantProg, len(recoveredData))
				}
			}
		})
	}
}

func TestGetMapNameFromBPFPinPath(t *testing.T) {
	type args struct {
		pinPath string
	}

	tests := []struct {
		name string
		args args
		want [2]string
	}{
		{
			name: "Ingress Map Pinpath",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_ingress_map",
			},
			want: [2]string{"ingress_map", "hello-udp-748dc8d996-default"},
		},
		{
			name: "Egress Map Pinpath",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_egress_map",
			},
			want: [2]string{"egress_map", "hello-udp-748dc8d996-default"},
		},
	}
	client := New(Config{NamespacedMaps: testNamespacedMaps}).(*bpfSDKClient)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got1, got2 := client.GetMapNameFromBPFPinPath(tt.args.pinPath)
			assert.Equal(t, tt.want[0], got1)
			assert.Equal(t, tt.want[1], got2)
		})
	}
}

func TestMapGlobal(t *testing.T) {
	type args struct {
		pinPath string
	}

	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Ingress Map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_ingress_map",
			},
			want: false,
		},
		{
			name: "Egress Map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_egress_map",
			},
			want: false,
		},
		{
			name: "Global",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/test_global",
			},
			want: true,
		},
	}
	client := New(Config{NamespacedMaps: testNamespacedMaps}).(*bpfSDKClient)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.IsMapGlobal(tt.args.pinPath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMapClassifier(t *testing.T) {
	mc := mapClassifier{
		namespacedMaps: map[string]struct{}{
			"ingress_map": {},
			"egress_map":  {},
		},
	}

	assert.True(t, mc.isNamespacedMap("ingress_map"))
	assert.False(t, mc.isNamespacedMap("policy_events"))

	name, ns := mc.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/pod-abc-default_ingress_map")
	assert.Equal(t, "ingress_map", name)
	assert.Equal(t, "pod-abc-default", ns)

	name, ns = mc.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/global_policy_events")
	assert.Equal(t, "policy_events", name)
	assert.Equal(t, "policy_events", ns)

	assert.False(t, mc.IsMapGlobal("/sys/fs/bpf/globals/aws/maps/pod-abc-default_ingress_map"))
	assert.True(t, mc.IsMapGlobal("/sys/fs/bpf/globals/aws/maps/global_policy_events"))

	empty := mapClassifier{namespacedMaps: map[string]struct{}{}}
	assert.True(t, empty.IsMapGlobal("/sys/fs/bpf/globals/aws/maps/pod-abc-default_ingress_map"))
}

func TestProgType(t *testing.T) {

	tests := []struct {
		name     string
		progType string
		want     bool
	}{
		{
			name:     "XDP",
			progType: "xdp",
			want:     true,
		},
		{
			name:     "TC",
			progType: "tc_cls",
			want:     true,
		},
		{
			name:     "Invalid prod",
			progType: "tcc_cls",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProgTypeSupported(tt.progType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadMap(t *testing.T) {
	tests := []struct {
		name       string
		pinType    uint32
		mapFD      uint32
		mapInfo    ebpf_maps.BpfMapInfo
		wantMapID  uint32
		wantErr    bool
		getInfoErr error
		pinPath    string
	}{
		{
			name:      "Successful retrieval of map info",
			pinType:   constdef.PIN_NONE.Index(),
			mapFD:     10,
			mapInfo:   ebpf_maps.BpfMapInfo{Id: 12345},
			wantMapID: 12345,
			wantErr:   false,
		},
		{
			name:       "Map retrieval error",
			pinType:    constdef.PIN_NONE.Index(),
			mapFD:      20,
			getInfoErr: fmt.Errorf("failed to get map info"),
			wantErr:    true,
		},
		{
			name:      "Pinned map retrieval from path",
			pinType:   constdef.PIN_GLOBAL_NS.Index(),
			mapFD:     30,
			mapInfo:   ebpf_maps.BpfMapInfo{Id: 54321},
			wantMapID: 54321,
			wantErr:   false,
			pinPath:   "/sys/fs/bpf/globals/aws/maps/test_map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockBpfMapAPI := mock_ebpf_maps.NewMockBpfMapAPIs(ctrl)
			mockBpfProgAPI := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)

			// Mock CreateBPFMap to return a BpfMap with MapFD set to tt.mapFD
			mockBpfMapAPI.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: tt.mapFD}, nil).AnyTimes()

			// Mock GetBPFmapInfo or GetMapFromPinPath based on the pin type and error expectation
			if tt.getInfoErr != nil {
				mockBpfMapAPI.EXPECT().GetBPFmapInfo(tt.mapFD).Return(ebpf_maps.BpfMapInfo{}, tt.getInfoErr)
			} else if tt.pinType == constdef.PIN_NONE.Index() {
				mockBpfMapAPI.EXPECT().GetBPFmapInfo(tt.mapFD).Return(tt.mapInfo, nil)
			} else {
				mockBpfMapAPI.EXPECT().GetMapFromPinPath(tt.pinPath).Return(tt.mapInfo, nil)
			}

			// Set up the loader and the map input
			elfLoader := &elfLoader{
				bpfMapApi:  mockBpfMapAPI,
				bpfProgApi: mockBpfProgAPI,
			}
			parsedMapData := []ebpf_maps.CreateEBPFMapInput{
				{
					Name:       "test_map",
					PinOptions: &ebpf_maps.BpfMapPinOptions{Type: tt.pinType, PinPath: tt.pinPath},
				},
			}

			loadedMaps, err := elfLoader.loadMap(parsedMapData)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if loadedMap, exists := loadedMaps["test_map"]; exists {
					assert.Equal(t, tt.wantMapID, loadedMap.MapID)
				} else {
					t.Errorf("Expected map 'test_map' to be loaded")
				}
			}
		})
	}
}

func TestSubprogramParseProg(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

	err = elfLoader.parseSection()
	assert.NoError(t, err)

	assert.NotNil(t, elfLoader.textSection)
	assert.NotEqual(t, -1, elfLoader.textSectionIndex)
	assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)])

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(mapData))

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(loadedMaps))

	parsedProgData, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsedProgData))

	textData, err := elfLoader.textSection.Data()
	assert.NoError(t, err)
	textSize := len(textData)
	assert.Greater(t, textSize, 0, ".text section should have data")

	// ProgData must be the tc_cls section with .text subprograms appended.
	for _, progInput := range parsedProgData {
		assert.Equal(t, "tc_cls", progInput.ProgType)

		var tcProgSize int
		for idx, entry := range elfLoader.progSectionMap {
			if entry.progType == "tc_cls" {
				sec := elfLoader.progSectionMap[idx]
				secData, _ := sec.progSection.Data()
				tcProgSize = len(secData)
				break
			}
		}
		assert.Greater(t, len(progInput.ProgData), tcProgSize,
			"Program data should include appended .text subprogram data")
		assert.Equal(t, tcProgSize+textSize, len(progInput.ProgData),
			"Program data should be tc_cls section + .text section")
	}
}

// TestChainedSubprogramParseProg tests BPF programs with chained subprogram calls:
// handle_ingress (tc_cls) -> lookup_conntrack (.text) -> do_lookup (.text)
// This verifies that .text-internal calls (resolved by clang at compile time)
// remain valid after .text is appended to the program section.
func TestChainedSubprogramParseProg(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog_chain.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

	err = elfLoader.parseSection()
	assert.NoError(t, err)

	assert.NotNil(t, elfLoader.textSection)
	assert.NotEqual(t, -1, elfLoader.textSectionIndex)
	assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)])

	textData, err := elfLoader.textSection.Data()
	assert.NoError(t, err)
	textInsns := len(textData) / bpfInsDefSize
	assert.Greater(t, textInsns, 2, ".text should contain multiple subprograms")

	symbols, err := elfFile.Symbols()
	assert.NoError(t, err)
	textFuncs := map[string]elf.Symbol{}
	for _, sym := range symbols {
		if int(sym.Section) == elfLoader.textSectionIndex && elf.ST_TYPE(sym.Info) == elf.STT_FUNC {
			textFuncs[sym.Name] = sym
		}
	}
	assert.Contains(t, textFuncs, "lookup_conntrack")
	assert.Contains(t, textFuncs, "do_lookup")

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(mapData))

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	parsedProgData, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsedProgData))

	// Exactly one entry program (handle_ingress); pull it out of the map.
	var progInput ebpf_progs.CreateEBPFProgInput
	for _, p := range parsedProgData {
		progInput = p
	}
	assert.Equal(t, "tc_cls", progInput.ProgType)

	var tcProgSize int
	for idx, entry := range elfLoader.progSectionMap {
		if entry.progType == "tc_cls" {
			secData, _ := elfLoader.progSectionMap[idx].progSection.Data()
			tcProgSize = len(secData)
			break
		}
	}
	textSize := len(textData)

	assert.Equal(t, tcProgSize+textSize, len(progInput.ProgData),
		"Program data should be tc_cls section + .text section")

	// Verify the BPF_CALL from tc_cls to lookup_conntrack has correct relocation.
	// Scan for the BPF_CALL instruction in the tc_cls section rather than
	// assuming a fixed offset, since clang may reorder instructions.
	callInsnOffset := -1
	for off := 0; off < tcProgSize; off += bpfInsDefSize {
		if progInput.ProgData[off] == (unix.BPF_JMP|unix.BPF_CALL) && progInput.ProgData[off+1]>>4 == 1 {
			callInsnOffset = off
			break
		}
	}
	assert.NotEqual(t, -1, callInsnOffset, "tc_cls should contain a BPF_PSEUDO_CALL instruction")

	tcInsnCount := tcProgSize / bpfInsDefSize
	lookupOffset := textFuncs["lookup_conntrack"].Value
	expectedTargetInsn := tcInsnCount + int(lookupOffset)/bpfInsDefSize
	expectedImm := int32(expectedTargetInsn - callInsnOffset/bpfInsDefSize - 1)
	actualImm := int32(binary.LittleEndian.Uint32(progInput.ProgData[callInsnOffset+4 : callInsnOffset+8]))
	assert.Equal(t, expectedImm, actualImm,
		"BPF_CALL Imm should point to lookup_conntrack in appended .text")

	// Verify .text-internal call: lookup_conntrack -> do_lookup
	// Scan for the BPF_PSEUDO_CALL within lookup_conntrack's range in the combined data.
	lookupStart := tcProgSize + int(lookupOffset)
	lookupEnd := tcProgSize + textSize
	chainCallOffset := -1
	for off := lookupStart; off < lookupEnd; off += bpfInsDefSize {
		if progInput.ProgData[off] == (unix.BPF_JMP|unix.BPF_CALL) && progInput.ProgData[off+1]>>4 == 1 {
			chainCallOffset = off
			break
		}
	}
	assert.NotEqual(t, -1, chainCallOffset, "lookup_conntrack should contain a BPF_PSEUDO_CALL to do_lookup")

	// The Imm for the .text-internal call should be the relative offset to do_lookup
	doLookupOffset := textFuncs["do_lookup"].Value
	chainCallInsnIdx := (chainCallOffset - tcProgSize) / bpfInsDefSize
	doLookupInsnIdx := int(doLookupOffset) / bpfInsDefSize
	expectedChainImm := int32(doLookupInsnIdx - chainCallInsnIdx - 1)
	actualChainImm := int32(binary.LittleEndian.Uint32(progInput.ProgData[chainCallOffset+4 : chainCallOffset+8]))
	assert.Equal(t, expectedChainImm, actualChainImm,
		"Chained BPF_CALL Imm should point from lookup_conntrack to do_lookup within .text")

	// Verify the map FD relocation was applied INSIDE the appended .text.
	// lookup_conntrack does a bpf_map_lookup_elem on aws_conntrack_map, which
	// compiles to a BPF_LD_IMM_DW (0x18) whose 64-bit immediate must be
	// patched with the map FD (5, from the CreateBPFMap mock above). Find
	// that instruction within the .text region of the combined program data
	// and assert the FD landed in its immediate.
	const bpfLdImmDW = byte(unix.BPF_LD | unix.BPF_IMM | unix.BPF_DW)
	mapLoadOffset := -1
	for off := tcProgSize; off+16 <= len(progInput.ProgData); off += bpfInsDefSize {
		if progInput.ProgData[off] == bpfLdImmDW {
			mapLoadOffset = off
			break
		}
	}
	assert.NotEqual(t, -1, mapLoadOffset, ".text should contain a BPF_LD_IMM_DW map load")
	mapFD := int32(binary.LittleEndian.Uint32(progInput.ProgData[mapLoadOffset+4 : mapLoadOffset+8]))
	assert.Equal(t, int32(5), mapFD,
		"map FD should be patched into the BPF_LD_IMM_DW immediate inside .text")
}

// TestMultiProgramOneSectionParseProg guards against a regression where two
// GLOBAL programs share a single ELF section. Each program is its own
// STT_FUNC symbol with a distinct offset and size within the section; the
// loader must slice each program by its own symbol size. Loading from a
// program's start to the end of the whole section would make the first
// program swallow the bytes of the second.
func TestMultiProgramOneSectionParseProg(t *testing.T) {
	m := setup(t, "../../test-data/tc.multi_prog_one_section.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if !assert.NoError(t, err, "open test ELF") {
		return
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

	err = elfLoader.parseSection()
	assert.NoError(t, err)

	// Both programs live in the same section, so there is exactly one prog
	// section entry.
	assert.Equal(t, 1, len(elfLoader.progSectionMap))

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(mapData))

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 7}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	// Gather the two GLOBAL program symbols and their individual sizes.
	symbols, err := elfFile.Symbols()
	assert.NoError(t, err)
	progSyms := map[string]elf.Symbol{}
	for _, sym := range symbols {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && elf.ST_BIND(sym.Info) == elf.STB_GLOBAL {
			if int(sym.Section) == int(elfLoader.textSectionIndex) {
				continue
			}
			progSyms[sym.Name] = sym
		}
	}
	assert.Contains(t, progSyms, "prog_first")
	assert.Contains(t, progSyms, "prog_second")

	parsedProgData, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(parsedProgData))

	// Each program's bytecode must be exactly its own symbol size -- not the
	// whole section, and not bleeding into the other program.
	byName := map[string]ebpf_progs.CreateEBPFProgInput{}
	for _, p := range parsedProgData {
		// Pin path is suffixed with the program (symbol) name.
		for name := range progSyms {
			if strings.HasSuffix(p.PinPath, name) {
				byName[name] = p
			}
		}
	}
	assert.Contains(t, byName, "prog_first")
	assert.Contains(t, byName, "prog_second")

	for name, sym := range progSyms {
		assert.Equal(t, int(sym.Size), len(byName[name].ProgData),
			"%s: program data must equal its own symbol size, not the whole section", name)
	}
}

// TestMultiProgramOneSectionWithSubprogRejected verifies the loader hard-errors
// on the unsupported layout: multiple GLOBAL programs sharing one section that
// also uses .text subprograms. BPF-to-BPF call offsets are relocated relative
// to the whole program section, which does not match the per-program trimmed
// bytecode the loader builds, so loading must fail loudly rather than emit
// wrong call offsets.
func TestMultiProgramOneSectionWithSubprogRejected(t *testing.T) {
	m := setup(t, "../../test-data/tc.multi_prog_one_section_subprog.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if !assert.NoError(t, err, "open test ELF") {
		return
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

	err = elfLoader.parseSection()
	assert.NoError(t, err)

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 7}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	// parseProg must reject this layout instead of producing programs with
	// incorrect BPF-to-BPF call offsets.
	_, err = elfLoader.parseProg(loadedMaps)
	assert.Error(t, err, "shared-section + .text layout must be rejected")
}

// TestMultiSubprogramWithDistinctSubprogsRejected documents a known limitation:
// an ELF with multiple entry programs (separate program sections) that each
// call a different .text subprogram is not supported. The loader appends the
// entire combined .text to every program, so each program would carry
// subprograms it never calls and the kernel verifier rejects the load with
// "unreachable insn". Until per-program call-graph extraction is implemented,
// the loader must reject this layout rather than emit bytecode the kernel will
// refuse.
func TestMultiSubprogramWithDistinctSubprogsRejected(t *testing.T) {
	m := setup(t, "../../test-data/tc.multi_subprog.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if !assert.NoError(t, err, "open test ELF") {
		return
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

	assert.NoError(t, elfLoader.parseSection())

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)

	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 7}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	// More than one entry program + .text subprograms -> must be rejected.
	_, err = elfLoader.parseProg(loadedMaps)
	assert.Error(t, err, "multiple entry programs with .text subprograms must be rejected")
}

// TestTextOnlyMapAssociation guards the fix where getRelocatedTextSection must
// report maps referenced ONLY from within a .text subprogram as associated with
// the owning program. The fixture's textonly_map is used solely inside the
// __noinline subprogram (it appears in .rel.text, never in the entry program's
// .reltc_cls), so the program's AssociatedMaps name table is built entirely
// from the .text relocation pass. Before the fix, getRelocatedTextSection
// patched the FD but discarded the name, leaving AssociatedMaps empty and
// breaking callers that resolve maps by name.
func TestTextOnlyMapAssociation(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog_textonly_map.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if !assert.NoError(t, err, "open test ELF") {
		return
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

	assert.NoError(t, elfLoader.parseSection())
	assert.NotNil(t, elfLoader.textSection)
	assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)])

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(mapData))

	const textonlyFD, textonlyID = 5, 100
	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: textonlyFD}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: textonlyID}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	// textonly_map is PIN_GLOBAL_NS, so loadMap resolves its ID via the pin path.
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: textonlyID}, nil).AnyTimes()

	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	parsedProgData, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsedProgData))

	// The map is referenced only from .text, yet it MUST appear in the
	// program's associated-map name table (keyed by map ID).
	for _, progInput := range parsedProgData {
		assert.Contains(t, progInput.AssociatedMaps, textonlyID,
			"textonly_map (ID %d) must be associated with the prog even though it is referenced only from .text", textonlyID)
		assert.Equal(t, "textonly_map", progInput.AssociatedMaps[textonlyID],
			"associated map name should be textonly_map")
	}
}

// TestSubprogramNoMapRelocation covers a .text subprogram that references no
// maps: clang emits a non-empty .text but no .rel.text section. This exercises
// the "No .rel.text relocation section found" path in getRelocatedTextSection,
// where .text must still be read and appended to the program with no map
// relocations applied.
func TestSubprogramNoMapRelocation(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog_nomap.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if !assert.NoError(t, err, "open test ELF") {
		return
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", nil)

	assert.NoError(t, elfLoader.parseSection())
	assert.NotNil(t, elfLoader.textSection)
	// .text exists with subprogram code but there is no .rel.text section.
	assert.Nil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)],
		"fixture should have no .rel.text section")

	textData, err := elfLoader.textSection.Data()
	assert.NoError(t, err)
	textSize := len(textData)
	assert.Greater(t, textSize, 0, ".text should contain the subprogram")

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	assert.Equal(t, 0, len(mapData))
	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	parsedProgData, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsedProgData))

	// The subprogram must still be appended even though no .rel.text exists.
	for _, progInput := range parsedProgData {
		var tcProgSize int
		for idx, entry := range elfLoader.progSectionMap {
			if entry.progType == "tc_cls" {
				d, _ := elfLoader.progSectionMap[idx].progSection.Data()
				tcProgSize = len(d)
				break
			}
		}
		assert.Equal(t, tcProgSize+textSize, len(progInput.ProgData),
			"program data should be tc_cls section + appended .text (no relocation)")
	}
}

// TestSubprogramGlobalMapRelocation covers a map referenced only from inside a
// .text subprogram and resolved via the sdkCache (the `sdkCache.Get` branch of
// getRelocatedTextSection), NOT via the per-program loadedMaps argument. This is
// the production scenario for a shared global map that was created by an earlier
// LoadBpfFile call (global maps persist in sdkCache across loads) and is then
// referenced by a later-loaded program's subprogram. We model it by seeding the
// sdkCache and passing parseProg an empty loadedMaps, so the only way to resolve
// the map FD inside .text is the cache.
func TestSubprogramGlobalMapRelocation(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog_globalmap.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if !assert.NoError(t, err, "open test ELF") {
		return
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "", nil)

	assert.NoError(t, elfLoader.parseSection())
	assert.NotNil(t, elfLoader.reloSectionMap[uint32(elfLoader.textSectionIndex)],
		".text should have a .rel.text map relocation")

	// Seed the global cache as if this map were created by a previous load.
	const globalFD = 4242
	sdkCache.Set("global_subprog_map", globalFD)
	defer sdkCache.Delete("global_subprog_map")

	// Pass an EMPTY loadedMaps so the .text relocation cannot resolve the map
	// from loadedMaps[name]; it must fall through to the sdkCache branch.
	parsedProgData, err := elfLoader.parseProg(map[string]ebpf_maps.BpfMap{})
	assert.NoError(t, err)
	assert.Equal(t, 1, len(parsedProgData))

	// The global map FD (from sdkCache) must be patched into the
	// BPF_LD_IMM_DW inside the appended .text.
	const bpfLdImmDW = byte(unix.BPF_LD | unix.BPF_IMM | unix.BPF_DW)
	for _, progInput := range parsedProgData {
		var tcProgSize int
		for idx, entry := range elfLoader.progSectionMap {
			if entry.progType == "tc_cls" {
				d, _ := elfLoader.progSectionMap[idx].progSection.Data()
				tcProgSize = len(d)
				break
			}
		}
		mapLoadOffset := -1
		for off := tcProgSize; off+16 <= len(progInput.ProgData); off += bpfInsDefSize {
			if progInput.ProgData[off] == bpfLdImmDW {
				mapLoadOffset = off
				break
			}
		}
		assert.NotEqual(t, -1, mapLoadOffset, ".text should contain a BPF_LD_IMM_DW map load")
		gotFD := int32(binary.LittleEndian.Uint32(progInput.ProgData[mapLoadOffset+4 : mapLoadOffset+8]))
		assert.Equal(t, int32(globalFD), gotFD,
			"global map FD (from sdkCache) should be patched into the .text map load")
	}
}

// TestSubprogramRealKernelLoad loads the .text subprogram fixtures into the
// REAL kernel (no mocks): it creates the maps, applies .text relocations, and
// the kernel verifier must accept the assembled bytecode. This is the strongest
// guard for the .text feature -- the parse-level tests assert byte/metadata
// transforms, but only a real load proves the relocated program actually
// verifies and that prog->map association (built from the kernel FD query)
// includes maps referenced only from .text. Requires root; skipped otherwise.
func TestSubprogramRealKernelLoad(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps and load programs into the kernel")
	}
	assert.NoError(t, utils.Mount_bpf_fs())
	defer utils.Unmount_bpf_fs()

	tests := []struct {
		name        string
		elf         string
		pinPrefix   string
		wantProgs   int
		wantMaps    int
		wantMapName string // a map that must appear in the loaded prog's Maps
	}{
		{
			name:        "single subprogram with map in .text",
			elf:         "../../test-data/tc.subprog.bpf.elf",
			pinPrefix:   "rk_subprog",
			wantProgs:   1,
			wantMaps:    1,
			wantMapName: "aws_conntrack_map",
		},
		{
			name:        "chained subprograms",
			elf:         "../../test-data/tc.subprog_chain.bpf.elf",
			pinPrefix:   "rk_chain",
			wantProgs:   1,
			wantMaps:    1,
			wantMapName: "aws_conntrack_map",
		},
		{
			name:        "map referenced only from .text subprogram",
			elf:         "../../test-data/tc.subprog_textonly_map.bpf.elf",
			pinPrefix:   "rk_textonly",
			wantProgs:   1,
			wantMaps:    1,
			wantMapName: "textonly_map",
		},
		{
			name:      "subprogram with no map relocation",
			elf:       "../../test-data/tc.subprog_nomap.bpf.elf",
			pinPrefix: "rk_nomap",
			wantProgs: 1,
			wantMaps:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := New(Config{NamespacedMaps: testNamespacedMaps})
			progs, maps, err := client.LoadBpfFile(tt.elf, tt.pinPrefix)
			// Best-effort cleanup of the pins this load created.
			defer func() {
				for p := range progs {
					_ = os.Remove(p)
				}
				for _, mp := range maps {
					if mp.MapMetaData.PinOptions != nil {
						_ = os.Remove(mp.MapMetaData.PinOptions.PinPath)
					}
				}
			}()

			assert.NoError(t, err, "real-kernel load (verifier must accept relocated .text)")
			assert.Equal(t, tt.wantProgs, len(progs), "loaded program count")
			assert.Equal(t, tt.wantMaps, len(maps), "loaded map count")

			if tt.wantMapName != "" {
				// The map (including one referenced only from .text) must be
				// associated with the loaded program via the kernel FD query.
				found := false
				for _, d := range progs {
					if _, ok := d.Maps[tt.wantMapName]; ok {
						found = true
					}
				}
				assert.True(t, found,
					"map %q must be associated with the loaded program", tt.wantMapName)
			}
		})
	}
}
