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

var testGlobalMaps = []string{"aws_conntrack_map", "policy_events"}

const testGlobalPinPrefix = "global"

// testClassifier builds the pin-path classifier the SDK would normally receive
// from its caller via Config.
func testClassifier() mapClassifier {
	nsSet := make(map[string]struct{}, len(testNamespacedMaps))
	for _, m := range testNamespacedMaps {
		nsSet[m] = struct{}{}
	}
	globalSet := make(map[string]struct{}, len(testGlobalMaps))
	for _, m := range testGlobalMaps {
		globalSet[m] = struct{}{}
	}
	return mapClassifier{
		namespacedMaps:  nsSet,
		globalMaps:      globalSet,
		globalPinPrefix: testGlobalPinPrefix,
	}
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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())
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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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

			bpfSDKclient := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix})

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
				// Pin with a "<podName>@<namespace>" identifier, matching the
				// format the agent uses. Legacy "-" identifiers produce pins the
				// recovery path deliberately skips as unparseable.
				_, _, err := bpfSDKclient.LoadBpfFile(m.path, "test@default")
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

func closeBpfDataFDs(t *testing.T, programs map[string]BpfData, maps map[string]ebpf_maps.BpfMap) {
	t.Helper()

	fds := make(map[int]struct{})
	for _, data := range programs {
		if data.Program.ProgFD > 0 {
			fds[data.Program.ProgFD] = struct{}{}
		}
		for _, bpfMap := range data.Maps {
			if bpfMap.MapFD > 0 {
				fds[int(bpfMap.MapFD)] = struct{}{}
			}
		}
	}
	for _, bpfMap := range maps {
		if bpfMap.MapFD > 0 {
			fds[int(bpfMap.MapFD)] = struct{}{}
		}
	}
	for fd := range fds {
		assert.NoError(t, unix.Close(fd))
	}
}

func clearTestGlobalMapCache() {
	for _, mapName := range testGlobalMaps {
		sdkCache.Delete(mapName)
	}
}

func TestRecoverAllBpfProgramsAndMapsReturnsPartialResults(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and recover BPF objects")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	// Prevent global-map FDs cached by another real-kernel test from changing
	// which FD source this recovery exercises.
	clearTestGlobalMapCache()
	defer clearTestGlobalMapCache()

	client := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})

	// These BPF pins deliberately use the unsupported legacy filename format
	// and sort before the valid pins below. Recovery must report them but
	// continue walking and recover all later entries.
	malformedPrograms, malformedMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"aaa-legacy",
	)
	if !assert.NoError(t, err) {
		return
	}
	closeBpfDataFDs(t, malformedPrograms, malformedMaps)

	validPrograms, validMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"zzz@default",
	)
	if !assert.NoError(t, err) {
		return
	}
	closeBpfDataFDs(t, validPrograms, validMaps)

	recovered, err := client.RecoverAllBpfProgramsAndMaps()
	defer closeBpfDataFDs(t, recovered, nil)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "partial recovery")
	assert.Contains(t, err.Error(), "aaa-legacy")
	assert.Equal(t, len(validPrograms), len(recovered))

	for pinPath, expected := range validPrograms {
		actual, ok := recovered[pinPath]
		if !assert.True(t, ok, "valid program %s should be recovered", pinPath) {
			continue
		}
		assert.NotZero(t, actual.Program.ProgFD)
		assert.Equal(t, len(expected.Maps), len(actual.Maps))
		for mapName := range expected.Maps {
			recoveredMap, ok := actual.Maps[mapName]
			assert.True(t, ok, "map %s for program %s should be recovered", mapName, pinPath)
			if ok {
				assert.NotZero(t, recoveredMap.MapFD)
			}
		}
	}

	for pinPath := range malformedPrograms {
		assert.NotContains(t, recovered, pinPath)
	}
}

// TestRecoverAllBpfProgramsAndMapsRecoversAllWorkloads exercises the all-success
// path: when every pin on the node is valid and parseable, recovery must return
// each workload's program together with all of its maps and a nil error. The
// existing partial-recovery tests only cover the failure branches, so this
// guards against the continue-and-aggregate logic spuriously reporting partial
// recovery (or dropping a workload) when nothing actually failed.
func TestRecoverAllBpfProgramsAndMapsRecoversAllWorkloads(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and recover BPF objects")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	clearTestGlobalMapCache()
	defer clearTestGlobalMapCache()

	client := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})

	// Two distinct workloads pinned with the "<podName>@<namespace>" identifier
	// the agent uses. One pod name contains a dot converted to an underscore,
	// which is the exact regression this PR fixes: the parser must still key the
	// maps and programs under the correct identifier so both workloads recover.
	firstPrograms, firstMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"app_a@default",
	)
	if !assert.NoError(t, err) {
		return
	}
	closeBpfDataFDs(t, firstPrograms, firstMaps)

	secondPrograms, secondMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"app-b@kube-system",
	)
	if !assert.NoError(t, err) {
		return
	}
	closeBpfDataFDs(t, secondPrograms, secondMaps)

	recovered, err := client.RecoverAllBpfProgramsAndMaps()
	defer closeBpfDataFDs(t, recovered, nil)

	// Everything was valid, so recovery must succeed cleanly - no partial error.
	assert.NoError(t, err)
	assert.Equal(t, len(firstPrograms)+len(secondPrograms), len(recovered))

	for _, loaded := range []map[string]BpfData{firstPrograms, secondPrograms} {
		for pinPath, expected := range loaded {
			actual, ok := recovered[pinPath]
			if !assert.True(t, ok, "program %s should be recovered", pinPath) {
				continue
			}
			// A fresh FD must be handed back for every recovered program...
			assert.NotZero(t, actual.Program.ProgFD)
			// ...and every associated map, keyed by the same name, with a live FD.
			assert.Equal(t, len(expected.Maps), len(actual.Maps))
			for mapName := range expected.Maps {
				recoveredMap, ok := actual.Maps[mapName]
				if assert.True(t, ok, "map %s for program %s should be recovered", mapName, pinPath) {
					assert.NotZero(t, recoveredMap.MapFD)
				}
			}
		}
	}
}

// TestRecoverAllBpfProgramsAndMapsWrapsErrPartialRecovery asserts the partial
// failure is reported through the exported ErrPartialRecovery sentinel so
// callers can distinguish "recovered some, skipped some" from a total failure
// with errors.Is rather than by matching on the error string.
func TestRecoverAllBpfProgramsAndMapsWrapsErrPartialRecovery(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and recover BPF objects")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	clearTestGlobalMapCache()
	defer clearTestGlobalMapCache()

	client := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})

	// A legacy "-"-format pin is unparseable by the "@"-anchored parser, so
	// recovery skips it and records a partial-recovery error while still
	// recovering the valid workload below.
	legacyPrograms, legacyMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"legacy-format",
	)
	if !assert.NoError(t, err) {
		return
	}
	closeBpfDataFDs(t, legacyPrograms, legacyMaps)

	validPrograms, validMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"valid@default",
	)
	if !assert.NoError(t, err) {
		return
	}
	closeBpfDataFDs(t, validPrograms, validMaps)

	recovered, err := client.RecoverAllBpfProgramsAndMaps()
	defer closeBpfDataFDs(t, recovered, nil)

	// The valid workload is still returned alongside the error...
	assert.Equal(t, len(validPrograms), len(recovered))
	// ...and the error is the exported sentinel, matchable with errors.Is.
	if assert.Error(t, err) {
		assert.True(t, errors.Is(err, ErrPartialRecovery),
			"partial recovery must wrap ErrPartialRecovery, got %v", err)
	}
}

// TestRecoverAllBpfProgramsAndMapsSkipsUnparseableProgPin covers the program-walk
// analog of the map-walk legacy-skip: a program pinned with the unsupported
// legacy "-" identifier has no "@", so GetProgIdentifierFromBPFPinPath returns an
// empty namespace and the pin must be skipped (recorded as partial recovery)
// rather than registered under a truncated identifier. The existing tests only
// exercise the map-side legacy skip and the missing-map drop, not a program pin
// the parser cannot classify.
func TestRecoverAllBpfProgramsAndMapsSkipsUnparseableProgPin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and recover BPF objects")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	clearTestGlobalMapCache()
	defer clearTestGlobalMapCache()

	client := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})

	// "legacy-format" has no "@", so every program pinned from it
	// ("legacy-format_handle_ingress", etc.) is unparseable to the "@"-anchored
	// prog parser and must be skipped.
	legacyPrograms, legacyMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"legacy-format",
	)
	if !assert.NoError(t, err) {
		return
	}
	closeBpfDataFDs(t, legacyPrograms, legacyMaps)

	recovered, err := client.RecoverAllBpfProgramsAndMaps()
	defer closeBpfDataFDs(t, recovered, nil)

	if assert.Error(t, err) {
		assert.True(t, errors.Is(err, ErrPartialRecovery),
			"skipped prog pins must surface as ErrPartialRecovery, got %v", err)
		assert.Contains(t, err.Error(), "unrecognized pin format")
	}
	// None of the unparseable program pins may be recovered.
	for pinPath := range legacyPrograms {
		assert.NotContains(t, recovered, pinPath)
	}
}

// TestRecoverAllBpfProgramsAndMapsDoesNotLeakFDs verifies the deferred FD
// reconciliation: map FDs opened during the map walk that are not carried out in
// a returned program (because that program was dropped) must be closed before
// the function returns. FD leaks in this path were raised repeatedly in review,
// so this asserts the process-wide open-FD count does not grow across a recovery
// that drops a workload.
func TestRecoverAllBpfProgramsAndMapsDoesNotLeakFDs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and recover BPF objects")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	clearTestGlobalMapCache()
	defer clearTestGlobalMapCache()

	client := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})

	loadedPrograms, loadedMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"leaktest@default",
	)
	if !assert.NoError(t, err) {
		return
	}

	// Remove the map pin so recovery opens a fresh FD for the map during the map
	// walk, then drops the program that references it during the prog walk. The
	// only handle to that map FD is the one recovery opened, so the deferred
	// cleanup is the sole thing that can close it.
	missingMapPin := constdef.MAP_BPF_FS + "leaktest@default_ingress_map"
	if !assert.NoError(t, os.Remove(missingMapPin)) {
		closeBpfDataFDs(t, loadedPrograms, loadedMaps)
		return
	}
	closeBpfDataFDs(t, loadedPrograms, loadedMaps)

	before := openFDCount(t)

	recovered, err := client.RecoverAllBpfProgramsAndMaps()
	defer closeBpfDataFDs(t, recovered, nil)
	assert.Error(t, err) // partial: the program referencing the removed map is dropped

	after := openFDCount(t)

	// Account only for FDs the caller now owns (returned programs + their maps).
	// Any growth beyond those is a leaked handle the deferred cleanup missed.
	owned := 0
	for _, data := range recovered {
		if data.Program.ProgFD > 0 {
			owned++
		}
		for _, m := range data.Maps {
			if m.MapFD > 0 {
				owned++
			}
		}
	}
	assert.LessOrEqual(t, after, before+owned,
		"recovery leaked FDs: before=%d after=%d owned-by-result=%d", before, after, owned)
}

// openFDCount returns the number of file descriptors currently open by this
// process by counting entries in /proc/self/fd.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if !assert.NoError(t, err) {
		return 0
	}
	return len(entries)
}

func TestRecoverAllBpfProgramsAndMapsDropsProgramWithMissingMap(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and recover BPF objects")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	clearTestGlobalMapCache()
	defer clearTestGlobalMapCache()

	client := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})

	loadedPrograms, loadedMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"partial@default",
	)
	if !assert.NoError(t, err) {
		return
	}

	// A pinned program retains its kernel reference to a map after the map pin
	// is removed. Recovery can therefore still inspect handle_ingress and learn
	// its map ID, but cannot recover that map from the map pin directory.
	missingMapPin := constdef.MAP_BPF_FS + "partial@default_ingress_map"
	if !assert.NoError(t, os.Remove(missingMapPin)) {
		closeBpfDataFDs(t, loadedPrograms, loadedMaps)
		return
	}
	closeBpfDataFDs(t, loadedPrograms, loadedMaps)

	recovered, err := client.RecoverAllBpfProgramsAndMaps()
	defer closeBpfDataFDs(t, recovered, nil)

	missingProgramPin := constdef.PROG_BPF_FS + "partial@default_handle_ingress"
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "partial recovery")
		assert.Contains(t, err.Error(), missingProgramPin)
		assert.Contains(t, err.Error(), "no recovered maps for partial@default")
	}
	assert.NotContains(t, recovered, missingProgramPin)
	assert.Equal(t, len(loadedPrograms)-1, len(recovered))

	for pinPath, expected := range loadedPrograms {
		if pinPath == missingProgramPin {
			continue
		}
		actual, ok := recovered[pinPath]
		if !assert.True(t, ok, "program %s without the missing map should be recovered", pinPath) {
			continue
		}
		assert.NotZero(t, actual.Program.ProgFD)
		assert.Equal(t, len(expected.Maps), len(actual.Maps))
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
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@default_ingress_map",
			},
			want: [2]string{"ingress_map", "hello-udp-748dc8d996@default"},
		},
		{
			name: "Egress Map Pinpath",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@default_egress_map",
			},
			want: [2]string{"egress_map", "hello-udp-748dc8d996@default"},
		},
		{
			// Multi-segment map name: the boundary is the first "_" after the "@",
			// so the whole "ingress_pod_state_map" must come back intact.
			name: "Multi segment map name",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@default_ingress_pod_state_map",
			},
			want: [2]string{"ingress_pod_state_map", "hello-udp-748dc8d996@default"},
		},
		{
			name: "Cluster policy map name",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@default_cp_egress_map",
			},
			want: [2]string{"cp_egress_map", "hello-udp-748dc8d996@default"},
		},
		{
			// Pod names containing dots become underscores in the identifier, so
			// the identifier itself contains underscores. Splitting on the FIRST
			// underscore would truncate it - this is the regression case.
			name: "Pod identifier containing underscores",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/my-app-1_2_3-abc1234-up-2026_01_0001@default_cp_egress_map",
			},
			want: [2]string{"cp_egress_map", "my-app-1_2_3-abc1234-up-2026_01_0001@default"},
		},
		{
			name: "Global conntrack map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map",
			},
			want: [2]string{"aws_conntrack_map", "aws_conntrack_map"},
		},
		{
			name: "Global policy events map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/global_policy_events",
			},
			want: [2]string{"policy_events", "policy_events"},
		},
		{
			// A namespace literally named "global" must not be mistaken for a
			// global pin: the "@" branch matches first.
			name: "Namespace named global",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@global_ingress_map",
			},
			want: [2]string{"ingress_map", "hello-udp-748dc8d996@global"},
		},
		{
			// Pre-"@" pin the one-shot legacy migration did not rename. It cannot
			// be split unambiguously, so neither value is returned and the caller
			// skips it rather than registering a truncated identifier.
			name: "Legacy pin format is not guessed at",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_ingress_map",
			},
			want: [2]string{"", ""},
		},
		{
			// Legacy pin whose namespace happens to be "global" must also not be
			// mistaken for a global pin - the prefix comparison is exact.
			name: "Legacy pin with namespace named global",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-global_ingress_map",
			},
			want: [2]string{"", ""},
		},
		{
			// A pod named "global.abc" yields the identifier "global_abc@<ns>", so
			// an unmigrated legacy pin for it starts with "global_". It must not be
			// accepted as a global pin: the remainder is not a configured global map
			// name.
			name: "Legacy pin for a pod named global.abc",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/global_abc-default_ingress_map",
			},
			want: [2]string{"", ""},
		},
		{
			// Same pod, migrated: the "@" branch handles it and the identifier keeps
			// its underscore.
			name: "Migrated pin for a pod named global.abc",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/global_abc@default_ingress_map",
			},
			want: [2]string{"ingress_map", "global_abc@default"},
		},
		{
			name: "No separator at all",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/garbage",
			},
			want: [2]string{"", ""},
		},
	}
	client := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix}).(*bpfSDKClient)
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
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@default_ingress_map",
			},
			want: false,
		},
		{
			name: "Egress Map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@default_egress_map",
			},
			want: false,
		},
		{
			name: "Global conntrack map",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/global_aws_conntrack_map",
			},
			want: true,
		},
		{
			// An unparseable pin is neither namespaced nor global. It must not be
			// reported as global, or RecoverGlobalMaps would pick it up and cache
			// it under an empty name.
			name: "Unparseable pin is not global",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996-default_ingress_map",
			},
			want: false,
		},
	}
	client := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix}).(*bpfSDKClient)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.IsMapGlobal(tt.args.pinPath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetProgIdentifierFromBPFPinPath(t *testing.T) {
	tests := []struct {
		name           string
		pinPath        string
		wantIdentifier string
		wantProgName   string
		wantGlobal     bool
	}{
		{
			name:           "Ingress prog",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996@default_handle_ingress",
			wantIdentifier: "hello-udp-748dc8d996@default",
			wantProgName:   "handle_ingress",
		},
		{
			name:           "Egress prog",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996@default_handle_egress",
			wantIdentifier: "hello-udp-748dc8d996@default",
			wantProgName:   "handle_egress",
		},
		{
			// The regression case: an identifier containing underscores, from a pod
			// name that contained dots.
			name:           "Pod identifier containing underscores",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/my-app-1_2_3-abc1234-up-2026_01_0001@default_handle_ingress",
			wantIdentifier: "my-app-1_2_3-abc1234-up-2026_01_0001@default",
			wantProgName:   "handle_ingress",
		},
		{
			// A pod named "global.abcd" yields the identifier "global_abcd@<ns>",
			// which starts with the global pin prefix but is a real pod. The "@"
			// disambiguates it from a node-wide pin.
			name:           "Pod whose name starts with global prefix is still a pod",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/global_abcd@default_handle_ingress",
			wantIdentifier: "global_abcd@default",
			wantProgName:   "handle_ingress",
		},
		{
			// Legacy format with underscores in the identifier (from dot conversion)
			// and the old "-" separator. Must not be parsed as the new "@" format.
			name:    "Legacy format with underscores in identifier",
			pinPath: "/sys/fs/bpf/globals/aws/programs/ylinux_app-75f4596489-k8s-omega-aws--nonprod-omega--test_handle_ingress",
		},
		{
			name:         "Global prog is reported as global",
			pinPath:      "/sys/fs/bpf/globals/aws/programs/global_handle_events",
			wantProgName: "handle_events",
			wantGlobal:   true,
		},
		{
			name:           "Namespace named global is not a global prog",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996@global_handle_ingress",
			wantIdentifier: "hello-udp-748dc8d996@global",
			wantProgName:   "handle_ingress",
		},
		{
			name:    "Legacy pin format is not guessed at",
			pinPath: "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_ingress",
		},
		{
			// Must not panic: the old implementation indexed [1] after splitting
			// into at most two parts.
			name:    "No separator at all",
			pinPath: "/sys/fs/bpf/globals/aws/programs/garbage",
		},
		{
			// Unexpected path depth should still parse correctly (only the
			// basename matters).
			name:           "Unexpected path depth",
			pinPath:        "/tmp/hello-udp-748dc8d996@default_handle_ingress",
			wantIdentifier: "hello-udp-748dc8d996@default",
			wantProgName:   "handle_ingress",
		},
		{
			// An unrecognized suffix that doesn't match handle_ingress or
			// handle_egress. The function still parses it — it doesn't validate
			// the prog name, just splits on the format boundary.
			name:           "Unrecognized prog name suffix still parsed",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996@default_handle_unknown",
			wantIdentifier: "hello-udp-748dc8d996@default",
			wantProgName:   "handle_unknown",
		},
	}

	client := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix}).(*bpfSDKClient)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIdentifier, gotProgName, gotGlobal := client.GetProgIdentifierFromBPFPinPath(tt.pinPath)
			assert.Equal(t, tt.wantIdentifier, gotIdentifier)
			assert.Equal(t, tt.wantProgName, gotProgName)
			assert.Equal(t, tt.wantGlobal, gotGlobal)
		})
	}
}

func TestMapClassifier(t *testing.T) {
	mc := testClassifier()

	assert.True(t, mc.isNamespacedMap("ingress_map"))
	assert.False(t, mc.isNamespacedMap("policy_events"))
	assert.True(t, mc.isGlobalMap("policy_events"))
	assert.False(t, mc.isGlobalMap("ingress_map"))

	// Per-pod pins use the "<podName>@<namespace>_<mapName>" format.
	name, ns := mc.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/pod-abc@default_ingress_map")
	assert.Equal(t, "ingress_map", name)
	assert.Equal(t, "pod-abc@default", ns)

	// Global pins are "<globalPinPrefix>_<mapName>" with a configured global map name.
	name, ns = mc.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/global_policy_events")
	assert.Equal(t, "policy_events", name)
	assert.Equal(t, "policy_events", ns)

	assert.False(t, mc.IsMapGlobal("/sys/fs/bpf/globals/aws/maps/pod-abc@default_ingress_map"))
	assert.True(t, mc.IsMapGlobal("/sys/fs/bpf/globals/aws/maps/global_policy_events"))

	// A classifier with no configured global maps reports nothing as global:
	// IsMapGlobal is a positive check against the configured global map names,
	// so unrecognized pins are never treated as global.
	empty := mapClassifier{namespacedMaps: map[string]struct{}{}}
	assert.False(t, empty.IsMapGlobal("/sys/fs/bpf/globals/aws/maps/pod-abc@default_ingress_map"))
	assert.False(t, empty.IsMapGlobal("/sys/fs/bpf/globals/aws/maps/global_policy_events"))
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

func TestLoadProgReturnsUnderlyingError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	loadErr := errors.New("verifier rejected program")
	mockBpfProgAPI := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)
	mockBpfProgAPI.EXPECT().LoadProg(gomock.Any()).Return(-1, loadErr)

	elfLoader := &elfLoader{
		bpfProgApi: mockBpfProgAPI,
	}
	loadedProgData := map[string]ebpf_progs.CreateEBPFProgInput{
		"/sys/fs/bpf/globals/aws/programs/test_prog": {
			ProgType:   "tc_cls",
			ProgData:   make([]byte, bpfInsDefSize),
			PinPath:    "/sys/fs/bpf/globals/aws/programs/test_prog",
			InsDefSize: bpfInsDefSize,
		},
	}

	_, err := elfLoader.loadProg(loadedProgData, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, loadErr)
}

func TestSubprogramParseProg(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog.bpf.elf")
	defer m.ctrl.Finish()
	f, _ := os.Open(m.path)
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())

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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "", testClassifier())

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
			client := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix})
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

// TestSubprogramInCustomSectionRejected verifies a call to a subprogram outside
// .text (custom-section __noinline) is rejected rather than mis-relocated.
func TestSubprogramInCustomSectionRejected(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog_badsection.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if !assert.NoError(t, err, "open test ELF") {
		return
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", testClassifier())
	assert.NoError(t, elfLoader.parseSection())

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().PinMap(gomock.Any(), gomock.Any()).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	_, err = elfLoader.parseProg(loadedMaps)
	assert.Error(t, err, "call to a subprogram outside .text must be rejected")
}
