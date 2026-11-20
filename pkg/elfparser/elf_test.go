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
	"time"

	"github.com/aws/aws-ebpf-sdk-go/pkg/internal/btf"
	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	mock_ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	mock_ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs/mocks"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

var testNamespacedMaps = []string{
	"ingress_map", "egress_map", "ingress_pod_state_map",
	"egress_pod_state_map", "cp_ingress_map", "cp_egress_map", "ipcache_map",
}

var testGlobalMaps = []string{"aws_conntrack_map", "policy_events"}

const testGlobalPinPrefix = "global"

// setOf builds the set form of a Config map-name list, the way New does.
func setOf(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return set
}

// testClassifier builds the pin-path classifier the SDK would normally receive
// from its caller via Config.
func testClassifier() mapClassifier {
	return mapClassifier{
		namespacedMaps:  setOf(testNamespacedMaps),
		globalMaps:      setOf(testGlobalMaps),
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
			// -1: loadProg closes this FD, and a zero value would close stdin.
			m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).Return(ebpf_progs.BpfProgInfo{}, -1, nil).AnyTimes()
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
		globalMaps    []string
		wantMap       int
		wantProg      int
		recoverGlobal bool
		forceUnMount  bool
		wantErr       error
	}{
		{
			name:        "Recover Global maps",
			elfFileName: "../../test-data/test.map.bpf.elf",
			// This fixture pins exactly one global map, aws_conntrack_map.
			// RecoverGlobalMaps requires the configured set to be recovered in
			// full, so Config must describe what this ELF actually pins -
			// declaring the full testGlobalMaps here would (correctly) be
			// reported as a partial recovery. See
			// TestRecoverGlobalMapsRejectsPartialSet.
			globalMaps:    []string{"aws_conntrack_map"},
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

			globalMaps := testGlobalMaps
			if tt.globalMaps != nil {
				globalMaps = tt.globalMaps
			}
			bpfSDKclient, err := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: globalMaps, GlobalPinPrefix: testGlobalPinPrefix})
			require.NoError(t, err)

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

// TestRecoverGlobalMapsRejectsPartialSet covers the all-or-nothing contract on
// RecoverGlobalMaps. The fixture pins only aws_conntrack_map while Config
// declares policy_events too, so the walk succeeds on every pin it finds yet
// still recovers an incomplete set.
//
// The rollback is the real subject: recovering aws_conntrack_map opens an FD and
// publishes it to the process-global sdkCache, which the load path reads when
// relocating a program against a global map. If the error returned here left
// that entry behind, a caller reacting to the failure by recreating global state
// would silently bind its new programs to the FD from the attempt that failed.
func TestRecoverGlobalMapsRejectsPartialSet(t *testing.T) {
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

	// testGlobalMaps declares aws_conntrack_map AND policy_events; this ELF
	// pins only the former.
	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

	_, loadedMaps, err := client.LoadBpfFile("../../test-data/test.map.bpf.elf", "global")
	require.NoError(t, err)

	// LoadBpfFile itself caches the global map it created, so drop that entry
	// first: otherwise the assertion below cannot tell the load's cache entry
	// from one the failed recovery left behind.
	closeBpfDataFDs(t, nil, loadedMaps)
	clearTestGlobalMapCache()

	before := openFDCount(t)

	recovered, err := client.RecoverGlobalMaps()

	// Incomplete set => fatal, with no partial result handed back.
	require.Error(t, err)
	assert.Nil(t, recovered, "a partial global map set must not be returned")
	assert.Contains(t, err.Error(), "policy_events", "the error should name the missing map")

	// Rollback: the FD opened for aws_conntrack_map must be closed...
	after := openFDCount(t)
	assert.LessOrEqual(t, after, before,
		"failed global recovery leaked FDs: before=%d after=%d", before, after)

	// ...and its sdkCache entry removed, so a subsequent load cannot resolve a
	// global map through the abandoned attempt.
	for _, mapName := range testGlobalMaps {
		_, cached := sdkCache.Get(mapName)
		assert.False(t, cached, "sdkCache must not retain %q after a failed global recovery", mapName)
	}
}

// TestRecoverGlobalMapsRecoversCompleteSet is the positive counterpart: with
// Config describing exactly what the fixture pins, the same walk succeeds and
// the global map stays cached for the load path to use.
func TestRecoverGlobalMapsRecoversCompleteSet(t *testing.T) {
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

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      []string{"aws_conntrack_map"},
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

	_, loadedMaps, err := client.LoadBpfFile("../../test-data/test.map.bpf.elf", "global")
	require.NoError(t, err)
	closeBpfDataFDs(t, nil, loadedMaps)
	clearTestGlobalMapCache()

	recovered, err := client.RecoverGlobalMaps()
	require.NoError(t, err)
	assert.Len(t, recovered, 1)
	defer closeBpfDataFDs(t, nil, recovered)

	cachedFD, cached := sdkCache.Get("aws_conntrack_map")
	assert.True(t, cached, "a successful recovery must leave the global map cached")
	assert.Greater(t, cachedFD, 0)
}

func TestRecoverGlobalMapsWithMissingMapDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to mount bpffs")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	if _, err := os.Stat(constdef.MAP_BPF_FS); err == nil {
		t.Skip("test requires a fresh bpffs mount with no maps directory")
	} else if !os.IsNotExist(err) {
		require.NoError(t, err)
	}

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

	recovered, err := client.RecoverGlobalMaps()
	require.NoError(t, err)
	assert.Empty(t, recovered)
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

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

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

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

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

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

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

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

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

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

	loadedPrograms, loadedMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		"leaktest@default",
	)
	if !assert.NoError(t, err) {
		return
	}

	// Leave the namespaced map pin in place and remove the PROGRAM pin that
	// references it. The map walk then opens a fresh FD for ingress_map (it is
	// namespaced, so it is not skipped as a global), but no recovered program
	// references that map ID, so nothing in the returned data owns the FD and
	// the deferred reconciliation in RecoverAllBpfProgramsAndMaps is the only
	// thing that can close it.
	//
	// Removing the map pin instead would NOT exercise that defer: the map walk
	// never sees a removed pin, so it never opens an FD, mapIDsToFDs stays
	// empty, and the cleanup loop iterates zero times.
	missingProgPin := constdef.PROG_BPF_FS + "leaktest@default_handle_ingress"
	if !assert.NoError(t, os.Remove(missingProgPin)) {
		closeBpfDataFDs(t, loadedPrograms, loadedMaps)
		return
	}
	closeBpfDataFDs(t, loadedPrograms, loadedMaps)

	before := openFDCount(t)

	recovered, err := client.RecoverAllBpfProgramsAndMaps()
	defer closeBpfDataFDs(t, recovered, nil)
	// Every surviving pin recovers cleanly - the removed program pin is simply
	// absent from the walk, which is not a per-pin failure.
	assert.NoError(t, err)
	assert.NotContains(t, recovered, missingProgPin)

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
	// Exact bound, no slack: the ingress_map FD that recovery opened is owned by
	// nothing in the result, so if the deferred cleanup is removed this grows by
	// exactly one and the assertion fails.
	assert.LessOrEqual(t, after, before+owned,
		"recovery leaked FDs: before=%d after=%d owned-by-result=%d", before, after, owned)
}

// openFDCount returns the number of file descriptors currently open by this
// process by counting entries in /proc/self/fd. It fails the test rather than
// returning a sentinel, because a 0 here would make a before/after comparison
// pass vacuously.
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
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

	client, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

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

func TestGetAllBpfProgramsAndMapsOmitsMissingMapID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load and list BPF objects")
	}
	if !assert.NoError(t, utils.Mount_bpf_fs()) {
		return
	}
	defer func() {
		assert.NoError(t, utils.Unmount_bpf_fs())
	}()

	clearTestGlobalMapCache()
	defer clearTestGlobalMapCache()

	// Load two fixtures under the same workload identifier so mapPodSelector
	// still contains the workload after the ingress_map pin is removed.
	namespacedMaps := append([]string(nil), testNamespacedMaps...)
	namespacedMaps = append(namespacedMaps, "test_events")
	client, err := New(Config{
		NamespacedMaps:  namespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)

	const workload = "partial-listing@default"
	loadedPrograms, loadedMaps, err := client.LoadBpfFile(
		"../../test-data/recoverydata.bpf.elf",
		workload,
	)
	if !assert.NoError(t, err) {
		return
	}

	supportPrograms, supportMaps, err := client.LoadBpfFile(
		"../../test-data/ring_buffer.bpf.elf",
		workload,
	)
	if !assert.NoError(t, err) {
		closeBpfDataFDs(t, loadedPrograms, loadedMaps)
		return
	}

	missingMap, ok := loadedMaps["ingress_map"]
	if !assert.True(t, ok, "fixture should load ingress_map") {
		closeBpfDataFDs(t, loadedPrograms, loadedMaps)
		closeBpfDataFDs(t, supportPrograms, supportMaps)
		return
	}
	missingMapPin := constdef.MAP_BPF_FS + workload + "_ingress_map"
	if !assert.NoError(t, os.Remove(missingMapPin)) {
		closeBpfDataFDs(t, loadedPrograms, loadedMaps)
		closeBpfDataFDs(t, supportPrograms, supportMaps)
		return
	}
	closeBpfDataFDs(t, loadedPrograms, loadedMaps)
	closeBpfDataFDs(t, supportPrograms, supportMaps)

	listed, err := client.GetAllBpfProgramsAndMaps()
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), fmt.Sprintf("map ID %d", missingMap.MapID))
	}

	missingMapProgramPin := constdef.PROG_BPF_FS + workload + "_handle_ingress"
	missingMapProgram, ok := listed[missingMapProgramPin]
	if assert.True(t, ok, "program should remain listed when one associated map pin is missing") {
		assert.NotContains(t, missingMapProgram.Maps, "",
			"an unresolved map ID must not be inserted under an empty name")
		assert.NotContains(t, missingMapProgram.Maps, "ingress_map")
	}

	// The second fixture's map proves the workload map table existed; the bug
	// only appears when that table exists but lacks the specific map ID above.
	supportProgramPin := constdef.PROG_BPF_FS + workload + "_conn_insert"
	if supportProgram, ok := listed[supportProgramPin]; assert.True(t, ok) {
		assert.Contains(t, supportProgram.Maps, "test_events")
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
		{
			// Both separators present but no pod name. Splitting would yield the
			// identifier "@default", under which recovery would register a real
			// map - the wrong-key outcome the "@" anchoring exists to prevent.
			name: "Empty pod name",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/@default_ingress_map",
			},
			want: [2]string{"", ""},
		},
		{
			// Empty namespace: the identifier would be "pod@".
			name: "Empty namespace",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@_ingress_map",
			},
			want: [2]string{"", ""},
		},
		{
			// Trailing "_" with nothing after it: strings.Cut reports ok, but the
			// map name is empty, so the map would be registered under "".
			name: "Empty map name",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/hello-udp-748dc8d996@default_",
			},
			want: [2]string{"", ""},
		},
		{
			// Neither a pod name nor a namespace.
			name: "Empty pod name and namespace",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/@_ingress_map",
			},
			want: [2]string{"", ""},
		},
	}
	clientIface, err := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix})
	require.NoError(t, err)
	client := clientIface.(*bpfSDKClient)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got1, got2, err := client.GetMapNameFromBPFPinPath(tt.args.pinPath)
			assert.Equal(t, tt.want[0], got1)
			assert.Equal(t, tt.want[1], got2)
			// The error and the empty return must always agree: an empty map
			// name means unparseable, and unparseable means a non-nil error.
			if tt.want[0] == "" {
				assert.Error(t, err, "an unparseable pin must report why")
			} else {
				assert.NoError(t, err)
			}
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
		{
			// Carries the global prefix, but the map name is in neither
			// configured list. This is the row that distinguishes the positive
			// check (is the name in GlobalMaps?) from the old negative one (is
			// the name absent from NamespacedMaps?) - under the latter this
			// would be reported global.
			name: "Global prefix with an unconfigured map name is not global",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/global_unknown_map",
			},
			want: false,
		},
		{
			// Documents a pre-existing wart rather than asserting desired
			// behaviour: classification consults only the map name and discards
			// the pod identifier, so a per-pod pin whose map name happens to be
			// a configured global name is reported global. Upstream behaves the
			// same way. Pinned here so the next change to the classification has
			// to decide about it deliberately.
			name: "Per-pod pin with a global map name is reported global (identifier is ignored)",
			args: args{
				pinPath: "/sys/fs/bpf/globals/aws/maps/pod-abc@default_policy_events",
			},
			want: true,
		},
	}
	clientIface, err := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix})
	require.NoError(t, err)
	client := clientIface.(*bpfSDKClient)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The same two steps RecoverGlobalMaps performs: parse the pin
			// filename once, then classify by the resulting map name.
			mapName, _, err := client.GetMapNameFromBPFPinPath(tt.args.pinPath)
			if tt.want {
				require.NoError(t, err, "a pin classified global must parse")
			}
			assert.Equal(t, tt.want, err == nil && client.isGlobalMap(mapName))
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
			name:           "Legacy pin format is not guessed at",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996-default_handle_ingress",
			wantIdentifier: "",
			wantProgName:   "",
			wantGlobal:     false,
		},
		{
			// Must not panic: the old implementation indexed [1] after splitting
			// into at most two parts.
			name:           "No separator at all",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/garbage",
			wantIdentifier: "",
			wantProgName:   "",
			wantGlobal:     false,
		},
		{
			// "@" present but no "_" after it: there is no prog name to split
			// off, so the dedicated early return fires rather than the pin
			// falling through to the global branch.
			name:           "Identifier with no prog name after the namespace",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996@default",
			wantIdentifier: "",
			wantProgName:   "",
			wantGlobal:     false,
		},
		{
			// The known limitation documented on GetProgIdentifierFromBPFPinPath:
			// a legacy (pre-"@") pin for a pod whose name begins with the global
			// prefix has no "@" and a first segment equal to the prefix, so it is
			// classified global and skipped rather than recovered. Pinned here so
			// the behaviour is visible rather than merely described in a comment -
			// the same pod's MAP pin returns ("","") and is reported through
			// ErrPartialRecovery, while this one is only logged.
			name:           "Legacy pin for a pod named global.foo is classified global",
			pinPath:        "/sys/fs/bpf/globals/aws/programs/global_foo-default_handle_ingress",
			wantIdentifier: "",
			wantProgName:   "foo-default_handle_ingress",
			wantGlobal:     true,
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
		{
			// Both separators present but no pod name. The identifier would be
			// "@default", under which recovery would key a real program.
			name:    "Empty pod name",
			pinPath: "/sys/fs/bpf/globals/aws/programs/@default_handle_ingress",
		},
		{
			// Empty namespace: the identifier would be "hello-udp-748dc8d996@".
			name:    "Empty namespace",
			pinPath: "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996@_handle_ingress",
		},
		{
			// Trailing "_": strings.Cut reports ok but the prog name is empty.
			name:    "Empty prog name",
			pinPath: "/sys/fs/bpf/globals/aws/programs/hello-udp-748dc8d996@default_",
		},
		{
			// A bare "<globalPinPrefix>_" has no prog name, so it is reported as
			// unrecognized rather than as a global prog with an empty name.
			name:    "Global prefix with empty prog name is not global",
			pinPath: "/sys/fs/bpf/globals/aws/programs/global_",
		},
	}

	clientIface, err := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix})
	require.NoError(t, err)
	client := clientIface.(*bpfSDKClient)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIdentifier, gotProgName, gotGlobal, err := client.GetProgIdentifierFromBPFPinPath(tt.pinPath)
			assert.Equal(t, tt.wantIdentifier, gotIdentifier)
			assert.Equal(t, tt.wantProgName, gotProgName)
			assert.Equal(t, tt.wantGlobal, gotGlobal)
			// A pin that yields neither an identifier nor a global prog name is
			// unparseable, and must say why.
			if tt.wantIdentifier == "" && !tt.wantGlobal {
				assert.Error(t, err, "an unparseable pin must report why")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestNewRejectsInvalidConfig pins the Config validation New performs. Both
// rejected shapes are configurations that cannot classify the pins they
// describe, and whose only other symptom is unrecovered workloads after a
// restart - so the constructor is the last place they can be caught cheaply.
func TestNewRejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			// The documented Config invariant: exactly one list per map name.
			// An overlapping name is classified global by isGlobalMap, so the
			// map's per-pod pins are never recovered.
			name: "map in both NamespacedMaps and GlobalMaps",
			cfg: Config{
				NamespacedMaps:  []string{"ingress_map", "policy_events"},
				GlobalMaps:      []string{"policy_events"},
				GlobalPinPrefix: testGlobalPinPrefix,
			},
			wantErr: `"policy_events" is in both`,
		},
		{
			// A global pin is matched as "<prefix>_<mapName>", so declaring
			// global maps without a prefix declares maps that can never match.
			name: "GlobalMaps set with no GlobalPinPrefix",
			cfg: Config{
				NamespacedMaps: testNamespacedMaps,
				GlobalMaps:     testGlobalMaps,
			},
			wantErr: "GlobalPinPrefix is empty",
		},
		{
			name: "fully configured",
			cfg: Config{
				NamespacedMaps:  testNamespacedMaps,
				GlobalMaps:      testGlobalMaps,
				GlobalPinPrefix: testGlobalPinPrefix,
			},
		},
		{
			// An empty Config is valid: a caller that pins no global maps has
			// nothing to classify as global. The kprobe, tc and xdp tests
			// construct the SDK this way, so this must not become an error.
			name: "empty config",
			cfg:  Config{},
		},
		{
			// A prefix with no global map names is not a contradiction - the
			// prefix simply never matches, because the exact-name check fails.
			// Only the reverse combination is rejected.
			name: "GlobalPinPrefix set with no GlobalMaps",
			cfg: Config{
				NamespacedMaps:  testNamespacedMaps,
				GlobalPinPrefix: testGlobalPinPrefix,
			},
		},
		{
			name: "namespaced maps only",
			cfg:  Config{NamespacedMaps: testNamespacedMaps},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.cfg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				// A rejected Config must not also hand back a usable client:
				// a caller that ignores the error would otherwise run on a
				// configuration the SDK has already declared unworkable.
				assert.Nil(t, client)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, client)
		})
	}
}

// TestNewBuildsClassifierFromConfig checks that an accepted Config is actually
// carried into the classifier, so validation passing does not mask a Config
// that was parsed into the wrong fields.
func TestNewBuildsClassifierFromConfig(t *testing.T) {
	clientIface, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)
	mc := clientIface.(*bpfSDKClient).mapClassifier

	assert.Equal(t, testGlobalPinPrefix, mc.globalPinPrefix)
	assert.Equal(t, setOf(testNamespacedMaps), mc.namespacedMaps)
	assert.Equal(t, setOf(testGlobalMaps), mc.globalMaps)

	// Spot-check both axes through the exported behaviour rather than only the
	// field contents.
	assert.True(t, mc.isGlobalMap("policy_events"))
	assert.False(t, mc.isGlobalMap("ingress_map"))
	assert.True(t, mc.isNamespacedMap("ingress_map"))
	assert.False(t, mc.isNamespacedMap("policy_events"))
}

func TestMapClassifier(t *testing.T) {
	// Build the classifier the way New does, rather than hand-assembling the
	// sets, so this test keeps testing the SDK instead of its own fixture.
	mcIface, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalMaps:      testGlobalMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)
	mc := mcIface.(*bpfSDKClient).mapClassifier

	// Per-pod pins use the "<podName>@<namespace>_<mapName>" format.
	name, ns, err := mc.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/pod-abc@default_ingress_map")
	assert.NoError(t, err)
	assert.Equal(t, "ingress_map", name)
	assert.Equal(t, "pod-abc@default", ns)

	// Global pins are "<globalPinPrefix>_<mapName>" with a configured global map name.
	name, ns, err = mc.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/global_policy_events")
	assert.NoError(t, err)
	assert.Equal(t, "policy_events", name)
	assert.Equal(t, "policy_events", ns)

	// An "@" with no "_" after it has no map name to split off, so the pin is
	// unparseable rather than being handed to the global branch.
	name, ns, err = mc.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/pod-abc@default")
	assert.Empty(t, name, "a pin with no map name after the namespace must not parse")
	assert.Empty(t, ns)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "no map name after the namespace",
			"the error should name the specific defect, not just 'unparseable'")
	}

	// Config fields are consumed independently: an unset GlobalPinPrefix alone
	// is enough to stop a "global_"-prefixed pin from parsing. New now rejects
	// that combination outright (see TestNewRejectsInvalidConfig), so the
	// classifier is built directly here - the point of this case is the parser
	// behaviour the rejection exists to prevent, which must stay pinned
	// independently of the constructor's validation.
	noPrefix := mapClassifier{
		namespacedMaps:  setOf(testNamespacedMaps),
		globalMaps:      setOf(testGlobalMaps),
		globalPinPrefix: "",
	}
	name, _, err = noPrefix.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/global_policy_events")
	assert.Empty(t, name, "global pin must not parse when GlobalPinPrefix is unset")
	assert.Error(t, err)
	// The empty name an unparseable pin yields must not classify as global.
	assert.False(t, noPrefix.isGlobalMap(name))

	// And with the prefix set but no global map names configured, the pin
	// parses no further either - a distinct cause from the case above.
	noGlobalsIface, err := New(Config{
		NamespacedMaps:  testNamespacedMaps,
		GlobalPinPrefix: testGlobalPinPrefix,
	})
	require.NoError(t, err)
	noGlobals := noGlobalsIface.(*bpfSDKClient).mapClassifier
	name, _, err = noGlobals.GetMapNameFromBPFPinPath("/sys/fs/bpf/globals/aws/maps/global_policy_events")
	assert.Empty(t, name, "global pin must not parse when GlobalMaps is empty")
	assert.Error(t, err)
	assert.False(t, noGlobals.isGlobalMap(name))
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
			client, err := New(Config{NamespacedMaps: testNamespacedMaps, GlobalMaps: testGlobalMaps, GlobalPinPrefix: testGlobalPinPrefix})
			require.NoError(t, err)
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

type fakeKfuncResolver struct {
	kfuncs map[string]btf.Kfunc
	err    error
	calls  [][]string
}

func (f *fakeKfuncResolver) ResolveKfuncs(names []string) (map[string]btf.Kfunc, error) {
	f.calls = append(f.calls, append([]string(nil), names...))
	if f.err != nil {
		return nil, f.err
	}
	out := make(map[string]btf.Kfunc)
	for _, n := range names {
		kf, ok := f.kfuncs[n]
		if !ok {
			return nil, fmt.Errorf("kfunc %q not found in kernel BTF", n)
		}
		out[n] = kf
	}
	return out, nil
}

func parseKfuncELF(t *testing.T, path string, resolver btf.KfuncResolver) (map[string]ebpf_progs.CreateEBPFProgInput, error) {
	m := setup(t, path)
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if err != nil {
		t.Fatalf("open test ELF: %v", err)
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", mapClassifier{})
	elfLoader.kfuncResolver = resolver
	assert.NoError(t, elfLoader.parseSection())

	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	return elfLoader.parseProg(loadedMaps)
}

type callInsn struct {
	srcReg uint8
	off    int16
	imm    int32
}

func callInsns(prog []byte) []callInsn {
	var calls []callInsn
	for i := 0; i+bpfInsDefSize <= len(prog); i += bpfInsDefSize {
		if prog[i] != (unix.BPF_JMP | unix.BPF_CALL) {
			continue
		}
		calls = append(calls, callInsn{
			srcReg: prog[i+1] >> 4, // high 4 bits of byte 1
			off:    int16(binary.LittleEndian.Uint16(prog[i+2:])),
			imm:    int32(binary.LittleEndian.Uint32(prog[i+4:])),
		})
	}
	return calls
}

// TestKfuncRelocation verifies that calls to extern __ksym functions from the
// program section are rewritten into BPF_PSEUDO_KFUNC_CALLs and that module
// kfuncs get an fd_array slot.
func TestKfuncRelocation(t *testing.T) {
	// Arbitrary values from the fake resolver; the test checks that they end up
	// in fd_array and in the rewritten insns' imm.
	const modFD = 42
	ids := map[string]int32{"bpf_skb_ct_lookup": 1001, "bpf_ct_change_timeout": 1002, "bpf_ct_release": 1003}

	tests := []struct {
		name        string
		module      string
		moduleFD    int
		wantOff     int16
		wantFDArray []int32
	}{
		{name: "module kfuncs", module: "nf_conntrack", moduleFD: modFD, wantOff: 1, wantFDArray: []int32{0, modFD}},
		// 0 is a valid fd, so it must not be mistaken for vmlinux.
		{name: "module kfuncs with fd 0", module: "nf_conntrack", moduleFD: 0, wantOff: 1, wantFDArray: []int32{0, 0}},
		{name: "vmlinux kfuncs", wantOff: 0, wantFDArray: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeKfuncResolver{kfuncs: map[string]btf.Kfunc{}}
			for name, id := range ids {
				resolver.kfuncs[name] = btf.Kfunc{BTFID: uint32(id), Module: tt.module, ModuleBTFFD: tt.moduleFD}
			}

			progs, err := parseKfuncELF(t, "../../test-data/tc.kfunc.bpf.elf", resolver)
			if !assert.NoError(t, err) {
				return
			}
			assert.Len(t, resolver.calls, 1, "kfuncs must be resolved in a single batch")
			if len(resolver.calls) == 1 {
				assert.ElementsMatch(t, []string{"bpf_skb_ct_lookup", "bpf_ct_change_timeout", "bpf_ct_release"}, resolver.calls[0])
			}
			assert.Len(t, progs, 1)

			for _, prog := range progs {
				assert.Equal(t, tt.wantFDArray, prog.FDArray)

				wantImms := map[int32]bool{1001: true, 1002: true, 1003: true}
				kfuncCalls, subprogCalls := 0, 0
				for _, c := range callInsns(prog.ProgData) {
					switch c.srcReg {
					case bpfPseudoKfuncCall:
						kfuncCalls++
						assert.True(t, wantImms[c.imm], "unexpected kfunc BTF ID %d", c.imm)
						assert.Equal(t, tt.wantOff, c.off)
					case bpfPseudoCall:
						subprogCalls++
					}
				}
				// handle_kfunc: lookup + release; inlined shorten(): lookup +
				// change_timeout + release.
				assert.Equal(t, 5, kfuncCalls)
				assert.Equal(t, 0, subprogCalls)
			}
		})
	}
}

func TestKfuncResolutionFailure(t *testing.T) {
	_, err := parseKfuncELF(t, "../../test-data/tc.kfunc.bpf.elf", &fakeKfuncResolver{err: errors.New("vmlinux BTF not found")})
	assert.ErrorContains(t, err, "failed to resolve kfuncs: vmlinux BTF not found")

	_, err = parseKfuncELF(t, "../../test-data/tc.kfunc.bpf.elf", &fakeKfuncResolver{kfuncs: map[string]btf.Kfunc{
		"bpf_skb_ct_lookup": {BTFID: 1}, "bpf_ct_release": {BTFID: 2},
	}})
	assert.ErrorContains(t, err, `kfunc "bpf_ct_change_timeout" not found`)
}

// TestKfuncFromSubprogramRejected verifies that a kfunc call from a .text
// subprogram fails with a clear error instead of producing a program the
// verifier rejects.
func TestKfuncFromSubprogramRejected(t *testing.T) {
	resolver := &fakeKfuncResolver{kfuncs: map[string]btf.Kfunc{}}
	for i, name := range []string{"bpf_skb_ct_lookup", "bpf_ct_change_timeout", "bpf_ct_release"} {
		resolver.kfuncs[name] = btf.Kfunc{BTFID: uint32(1001 + i)}
	}
	_, err := parseKfuncELF(t, "../../test-data/tc.kfunc_subprog.bpf.elf", resolver)
	assert.ErrorContains(t, err, "is called from a subprogram, which is not supported")
}

// TestNoKfuncsSkipsResolver verifies ELFs without kfunc calls never touch the
// kernel BTF, don't parse their relocations an extra time and load without an
// fd_array.
func TestNoKfuncsSkipsResolver(t *testing.T) {
	m := setup(t, "../../test-data/tc.subprog.bpf.elf")
	defer m.ctrl.Finish()
	f, err := os.Open(m.path)
	if err != nil {
		t.Fatalf("open test ELF: %v", err)
	}
	defer f.Close()

	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", mapClassifier{})
	resolver := &fakeKfuncResolver{err: errors.New("must not be called")}
	elfLoader.kfuncResolver = resolver
	assert.NoError(t, elfLoader.parseSection())
	mapData, err := elfLoader.parseMap(BpfCustomData{})
	assert.NoError(t, err)
	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	loadedMaps, err := elfLoader.loadMap(mapData)
	assert.NoError(t, err)

	progs, err := elfLoader.parseProg(loadedMaps)
	assert.NoError(t, err)
	assert.Empty(t, resolver.calls)
	assert.Nil(t, elfLoader.progRelocs, "relocations must only be parsed by the relocation pass")
	for _, prog := range progs {
		assert.Empty(t, prog.FDArray)
	}
}

func TestIsKfuncSymbol(t *testing.T) {
	info := func(bind elf.SymBind, typ elf.SymType) uint8 { return elf.ST_INFO(bind, typ) }
	tests := []struct {
		name string
		sym  elf.Symbol
		want bool
	}{
		{"undefined global notype", elf.Symbol{Name: "bpf_ct_release", Section: elf.SHN_UNDEF, Info: info(elf.STB_GLOBAL, elf.STT_NOTYPE)}, true},
		{"undefined weak func", elf.Symbol{Name: "k", Section: elf.SHN_UNDEF, Info: info(elf.STB_WEAK, elf.STT_FUNC)}, true},
		{"defined .text section symbol", elf.Symbol{Name: ".text", Section: 2, Info: info(elf.STB_LOCAL, elf.STT_SECTION)}, false},
		{"undefined local", elf.Symbol{Name: "k", Section: elf.SHN_UNDEF, Info: info(elf.STB_LOCAL, elf.STT_NOTYPE)}, false},
		{"undefined object", elf.Symbol{Name: "k", Section: elf.SHN_UNDEF, Info: info(elf.STB_GLOBAL, elf.STT_OBJECT)}, false},
		{"unnamed", elf.Symbol{Section: elf.SHN_UNDEF, Info: info(elf.STB_GLOBAL, elf.STT_NOTYPE)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isKfuncSymbol(tt.sym))
		})
	}
}

// recordReleases replaces releaseObject and returns the objects released. It
// also drops the global maps the test's loads cache.
func recordReleases(t *testing.T) *[]createdObject {
	t.Helper()
	t.Cleanup(func() {
		sdkCache.Delete("aws_conntrack_map")
		sdkCache.Delete("policy_events")
		sdkCache.Delete("ingress_map")
	})
	var released []createdObject
	orig := releaseObject
	t.Cleanup(func() { releaseObject = orig })
	releaseObject = func(obj createdObject) { released = append(released, obj) }
	return &released
}

// TestLoadFailureReleasesCreatedObjects fails each step of a load of
// tc.ingress.bpf.elf (3 maps, 3 programs) and checks the maps and programs
// created before the failure are released. ingress_map is namespaced; the
// global maps stay once they are cached.
func TestLoadFailureReleasesCreatedObjects(t *testing.T) {
	const ingressMapFD, conntrackMapFD, eventsMapFD = 101, 102, 103
	mapPins := map[int]string{
		ingressMapFD:   constdef.MAP_BPF_FS + "test_ingress_map",
		conntrackMapFD: constdef.MAP_BPF_FS + "test_aws_conntrack_map",
	}
	mapFDs := map[string]uint32{"ingress_map": ingressMapFD, "aws_conntrack_map": conntrackMapFD, "policy_events": eventsMapFD}
	errInjected := errors.New("injected")

	tests := []struct {
		name string
		// failAt names the call that fails; n is which call of it (1-based).
		failAt string
		n      int
		// wantMaps are the map FDs released; wantProgs is how many programs are.
		wantMaps  []int
		wantProgs int
		// prefix and namespaced override the loader's pin prefix and classifier.
		prefix     string
		namespaced map[string]struct{}
	}{
		{name: "create ingress_map", failAt: "CreateBPFMap", n: 1},
		{name: "get ingress_map from pin path", failAt: "GetMapFromPinPath", n: 1, wantMaps: []int{ingressMapFD}},
		{name: "get global map from pin path", failAt: "GetMapFromPinPath", n: 2, wantMaps: []int{conntrackMapFD, ingressMapFD}},
		{name: "create third map", failAt: "CreateBPFMap", n: 3, wantMaps: []int{ingressMapFD}},
		{name: "load first program", failAt: "LoadProg", n: 1, wantMaps: []int{ingressMapFD}},
		{name: "load third program", failAt: "LoadProg", n: 3, wantMaps: []int{ingressMapFD}, wantProgs: 2},
		{name: "get program from pin path", failAt: "GetProgFromPinPath", n: 2, wantMaps: []int{ingressMapFD}, wantProgs: 2},
		{name: "get associated map IDs", failAt: "GetBPFProgAssociatedMapsIDs", n: 1, wantMaps: []int{ingressMapFD}, wantProgs: 3},
		{name: "pin prefix with underscore", failAt: "LoadProg", n: 1, wantMaps: []int{ingressMapFD}, prefix: "web_v2@ns"},
		{name: "no namespaced maps configured", failAt: "LoadProg", n: 3, wantProgs: 2, namespaced: map[string]struct{}{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := setup(t, "../../test-data/tc.ingress.bpf.elf")
			defer m.ctrl.Finish()
			released := recordReleases(t)
			calls := map[string]int{}
			fail := func(call string) bool {
				calls[call]++
				return call == tt.failAt && calls[call] == tt.n
			}
			nextProgFD := 200
			m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes().DoAndReturn(func(in ebpf_maps.CreateEBPFMapInput) (ebpf_maps.BpfMap, error) {
				if fail("CreateBPFMap") {
					return ebpf_maps.BpfMap{}, errInjected
				}
				return ebpf_maps.BpfMap{MapFD: mapFDs[in.Name]}, nil
			})
			m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes().DoAndReturn(func(string) (ebpf_maps.BpfMapInfo, error) {
				if fail("GetMapFromPinPath") {
					return ebpf_maps.BpfMapInfo{}, errInjected
				}
				return ebpf_maps.BpfMapInfo{}, nil
			})
			m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes().DoAndReturn(func(ebpf_progs.CreateEBPFProgInput) (int, error) {
				if fail("LoadProg") {
					return -1, errInjected
				}
				nextProgFD++
				return nextProgFD, nil
			})
			m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes().DoAndReturn(func(string) (ebpf_progs.BpfProgInfo, int, error) {
				if fail("GetProgFromPinPath") {
					return ebpf_progs.BpfProgInfo{}, -1, errInjected
				}
				return ebpf_progs.BpfProgInfo{}, -1, nil
			})
			m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes().DoAndReturn(func(int) ([]uint32, error) {
				if fail("GetBPFProgAssociatedMapsIDs") {
					return nil, errInjected
				}
				return nil, nil
			})

			f, err := os.Open(m.path)
			assert.NoError(t, err)
			defer f.Close()
			elfFile, err := elf.NewFile(f)
			assert.NoError(t, err)
			prefix, namespaced := "test", map[string]struct{}{"ingress_map": {}}
			if tt.prefix != "" {
				prefix = tt.prefix
			}
			if tt.namespaced != nil {
				namespaced = tt.namespaced
			}
			loader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, prefix, mapClassifier{namespacedMaps: namespaced})

			progs, maps, err := loader.doLoadELF(BpfCustomData{})
			assert.Error(t, err)
			assert.Nil(t, progs)
			assert.Nil(t, maps)

			var gotMaps []int
			gotProgs := 0
			for _, obj := range *released {
				if obj.fd > 200 {
					gotProgs++
					assert.True(t, strings.HasPrefix(obj.pinPath, constdef.PROG_BPF_FS), "program pin path %s", obj.pinPath)
					continue
				}
				gotMaps = append(gotMaps, obj.fd)
				assert.Equal(t, strings.Replace(mapPins[obj.fd], "test_", prefix+"_", 1), obj.pinPath)
			}
			assert.Equal(t, tt.wantMaps, gotMaps)
			assert.Equal(t, tt.wantProgs, gotProgs)
			if tt.wantProgs > 0 && len(tt.wantMaps) > 0 {
				assert.Equal(t, ingressMapFD, (*released)[len(*released)-1].fd, "maps are released after the programs that use them")
			}
		})
	}
}

func TestLoadSuccessReleasesNothing(t *testing.T) {
	m := setup(t, "../../test-data/tc.ingress.bpf.elf")
	defer m.ctrl.Finish()
	released := recordReleases(t)
	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).AnyTimes().Return(ebpf_maps.BpfMap{MapFD: 101}, nil)
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).AnyTimes()
	m.ebpf_progs.EXPECT().LoadProg(gomock.Any()).AnyTimes().Return(201, nil)
	m.ebpf_progs.EXPECT().GetProgFromPinPath(gomock.Any()).AnyTimes().Return(ebpf_progs.BpfProgInfo{}, -1, nil)
	m.ebpf_progs.EXPECT().GetBPFProgAssociatedMapsIDs(gomock.Any()).AnyTimes()

	f, err := os.Open(m.path)
	assert.NoError(t, err)
	defer f.Close()
	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	loader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", mapClassifier{namespacedMaps: map[string]struct{}{"ingress_map": {}}})

	_, _, err = loader.doLoadELF(BpfCustomData{})
	assert.NoError(t, err)
	assert.Empty(t, *released)
}

// A map created with PIN_NONE was never pinned, so only its FD is released.
func TestLoadFailureReleasesUnpinnedMapByFDOnly(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	released := recordReleases(t)
	mockBpfMapAPI := mock_ebpf_maps.NewMockBpfMapAPIs(ctrl)
	mockBpfMapAPI.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 10}, nil)
	mockBpfMapAPI.EXPECT().GetBPFmapInfo(uint32(10)).Return(ebpf_maps.BpfMapInfo{}, errors.New("injected"))
	loader := &elfLoader{
		bpfMapApi:         mockBpfMapAPI,
		customizedPinPath: "pod",
		mapClassifier:     mapClassifier{namespacedMaps: map[string]struct{}{"test_map": {}}},
	}

	_, err := loader.loadMap([]ebpf_maps.CreateEBPFMapInput{{
		Name:       "test_map",
		PinOptions: &ebpf_maps.BpfMapPinOptions{Type: constdef.PIN_NONE.Index()},
	}})
	assert.Error(t, err)
	loader.releaseCreated()
	assert.Equal(t, []createdObject{{fd: 10}}, *released)
}

// A program load that fails after real maps were created leaves no pin or FD
// for the namespaced map. The global maps stay cached and pinned.
func TestLoadFailureReleasesRealKernelObjects(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps in the kernel")
	}
	assert.NoError(t, utils.Mount_bpf_fs())
	defer utils.Unmount_bpf_fs()
	t.Cleanup(closeCachedGlobalMaps)

	var releasedFDs []int
	orig := releaseObject
	t.Cleanup(func() { releaseObject = orig })
	releaseObject = func(obj createdObject) {
		releasedFDs = append(releasedFDs, obj.fd)
		orig(obj)
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockBpfProgAPI := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)
	mockBpfProgAPI.EXPECT().LoadProg(gomock.Any()).Return(-1, errors.New("injected"))

	f, err := os.Open("../../test-data/tc.ingress.bpf.elf")
	assert.NoError(t, err)
	defer f.Close()
	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	loader := newElfLoader(elfFile, &ebpf_maps.BpfMap{}, mockBpfProgAPI, "rk_release", mapClassifier{namespacedMaps: map[string]struct{}{"ingress_map": {}}})

	_, _, err = loader.doLoadELF(BpfCustomData{})
	assert.ErrorContains(t, err, "injected")

	_, err = os.Stat(constdef.MAP_BPF_FS + "rk_release_ingress_map")
	assert.True(t, os.IsNotExist(err), "namespaced map pin must be removed, got %v", err)
	_, err = os.Stat(constdef.MAP_BPF_FS + "rk_release_aws_conntrack_map")
	assert.NoError(t, err, "global map stays pinned")
	if assert.Len(t, releasedFDs, 1) {
		_, err = unix.FcntlInt(uintptr(releasedFDs[0]), unix.F_GETFD, 0)
		assert.ErrorIs(t, err, unix.EBADF, "released map FD must be closed")
	}
}

// A pin that another object replaced during the load is not unlinked by the
// rollback; only this load's FD is closed.
func TestLoadFailureKeepsReplacedPin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps in the kernel")
	}
	assert.NoError(t, utils.Mount_bpf_fs())
	defer utils.Unmount_bpf_fs()
	t.Cleanup(closeCachedGlobalMaps)

	pinPath := constdef.MAP_BPF_FS + "rk_replaced_ingress_map"
	var foreign ebpf_maps.BpfMap
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockBpfProgAPI := mock_ebpf_progs.NewMockBpfProgAPIs(ctrl)
	mockBpfProgAPI.EXPECT().LoadProg(gomock.Any()).DoAndReturn(func(ebpf_progs.CreateEBPFProgInput) (int, error) {
		// Another load replaces the pin before this one fails.
		var err error
		foreign, err = (&ebpf_maps.BpfMap{}).CreateBPFMap(ebpf_maps.CreateEBPFMapInput{
			Type: uint32(constdef.BPF_MAP_TYPE_HASH.Index()), KeySize: 4, ValueSize: 4, MaxEntries: 1,
			PinOptions: &ebpf_maps.BpfMapPinOptions{Type: constdef.PIN_GLOBAL_NS.Index(), PinPath: pinPath},
		})
		assert.NoError(t, err)
		return -1, errors.New("injected")
	})

	f, err := os.Open("../../test-data/tc.ingress.bpf.elf")
	assert.NoError(t, err)
	defer f.Close()
	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	loader := newElfLoader(elfFile, &ebpf_maps.BpfMap{}, mockBpfProgAPI, "rk_replaced", mapClassifier{namespacedMaps: map[string]struct{}{"ingress_map": {}}})

	_, _, err = loader.doLoadELF(BpfCustomData{})
	assert.ErrorContains(t, err, "injected")

	foreignInfo, err := ebpf_maps.GetBPFmapInfo(int(foreign.MapFD))
	assert.NoError(t, err)
	pinned, err := (&ebpf_maps.BpfMap{}).GetMapFromPinPath(pinPath)
	if assert.NoError(t, err, "the replaced pin must survive the rollback") {
		assert.Equal(t, foreignInfo.Id, pinned.Id)
	}
	assert.NoError(t, foreign.UnPinMap(pinPath))
}

// failLinkProgAPI loads programs for real and fails the map-ID lookup that
// follows, after letting the test replace a pin.
type failLinkProgAPI struct {
	*ebpf_progs.BpfProgram
	beforeFail func()
}

func (f failLinkProgAPI) GetBPFProgAssociatedMapsIDs(int) ([]uint32, error) {
	f.beforeFail()
	return nil, errors.New("injected")
}

// Programs a failed load pinned are unpinned, except a pin another program
// replaced during the load.
func TestLoadFailureReleasesRealKernelPrograms(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load programs into the kernel")
	}
	assert.NoError(t, utils.Mount_bpf_fs())
	defer utils.Unmount_bpf_fs()
	t.Cleanup(func() {
		sdkCache.Delete("aws_conntrack_map")
		sdkCache.Delete("policy_events")
	})

	listPins := func() []string {
		var pins []string
		entries, _ := os.ReadDir(constdef.PROG_BPF_FS)
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "rk_progfail") {
				pins = append(pins, constdef.PROG_BPF_FS+e.Name())
			}
		}
		return pins
	}
	var replacedPin string
	var foreignID uint32
	progAPI := failLinkProgAPI{BpfProgram: &ebpf_progs.BpfProgram{}, beforeFail: func() {
		pins := listPins()
		if !assert.NotEmpty(t, pins) {
			return
		}
		// Another load replaces one program pin: mov r0, 0; exit.
		replacedPin = pins[0]
		fd, err := (&ebpf_progs.BpfProgram{}).LoadProg(ebpf_progs.CreateEBPFProgInput{
			ProgType:   "tc_cls",
			ProgData:   []byte{0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0},
			LicenseStr: "GPL",
			PinPath:    replacedPin,
			InsDefSize: 8,
		})
		if assert.NoError(t, err) {
			info, err := ebpf_progs.GetBPFprogInfo(fd)
			assert.NoError(t, err)
			foreignID = info.ID
			unix.Close(fd)
		}
	}}

	f, err := os.Open("../../test-data/tc.ingress.bpf.elf")
	assert.NoError(t, err)
	defer f.Close()
	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	loader := newElfLoader(elfFile, &ebpf_maps.BpfMap{}, progAPI, "rk_progfail", mapClassifier{namespacedMaps: map[string]struct{}{"ingress_map": {}}})

	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		assert.NoError(t, err)
		return len(entries)
	}
	before := countFDs()
	_, _, err = loader.doLoadELF(BpfCustomData{})
	assert.ErrorContains(t, err, "associatedmapIDs failed")
	// Only the two global maps the load cached in sdkCache keep an FD open.
	assert.Equal(t, before+2, countFDs(), "program and namespaced map FDs must be closed")
	for _, name := range []string{"aws_conntrack_map", "policy_events"} {
		if fd, ok := sdkCache.Get(name); ok {
			unix.Close(fd)
		}
	}
	assert.Equal(t, []string{replacedPin}, listPins(), "only the replaced pin survives")
	pinned, fd, err := (&ebpf_progs.BpfProgram{}).GetProgFromPinPath(replacedPin)
	if assert.NoError(t, err) {
		assert.Equal(t, foreignID, pinned.ID)
		unix.Close(fd)
	}
	assert.NoError(t, utils.UnPinObject(replacedPin))
}

// A load that fails in parseProg, here on a kfunc the kernel lacks, releases
// the maps it created before.
func TestLoadFailureInParseProgReleasesMaps(t *testing.T) {
	m := setup(t, "../../test-data/tc.kfunc.bpf.elf")
	defer m.ctrl.Finish()
	released := recordReleases(t)
	t.Cleanup(func() { sdkCache.Delete("kfunc_counters") })
	m.ebpf_maps.EXPECT().CreateBPFMap(gomock.Any()).Return(ebpf_maps.BpfMap{MapFD: 5}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetBPFmapInfo(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()
	m.ebpf_maps.EXPECT().GetMapFromPinPath(gomock.Any()).Return(ebpf_maps.BpfMapInfo{Id: 100}, nil).AnyTimes()

	f, err := os.Open(m.path)
	assert.NoError(t, err)
	defer f.Close()
	elfFile, err := elf.NewFile(f)
	assert.NoError(t, err)
	// kfunc_counters must be namespaced, or it is cached as global and kept.
	loader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test", mapClassifier{namespacedMaps: map[string]struct{}{"kfunc_counters": {}}})
	loader.kfuncResolver = &fakeKfuncResolver{err: errors.New("injected")}

	_, _, err = loader.doLoadELF(BpfCustomData{})
	assert.ErrorContains(t, err, "injected")
	assert.Equal(t, []createdObject{{fd: 5, pinPath: constdef.MAP_BPF_FS + "test_kfunc_counters"}}, *released)
}

// closeCachedGlobalMaps closes and forgets the real global maps a
// tc.ingress.bpf.elf load cached. Deleting a cache entry alone leaves its FD open.
func closeCachedGlobalMaps() {
	for _, name := range []string{"aws_conntrack_map", "policy_events"} {
		if fd, ok := sdkCache.Get(name); ok {
			unix.Close(fd)
			sdkCache.Delete(name)
		}
	}
}

// Rollback unpins a map even when the failed load left no free descriptor:
// the ownership check reopens the pin with the descriptor closing frees.
func TestReleaseObjectAtDescriptorLimit(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps in the kernel")
	}
	require.NoError(t, utils.Mount_bpf_fs())
	defer utils.Unmount_bpf_fs()
	// Keep the map off fd 0 in case an earlier test closed stdin. Open
	// returns the lowest free descriptor, so it takes fd 0 itself then.
	if _, err := unix.FcntlInt(0, unix.F_GETFD, 0); err != nil {
		devNull, err := unix.Open(os.DevNull, unix.O_RDONLY, 0)
		require.NoError(t, err)
		if devNull != 0 {
			require.NoError(t, unix.Dup2(devNull, 0))
			unix.Close(devNull)
		}
	}

	pinPath := constdef.MAP_BPF_FS + "rk_fdlimit_map"
	created, err := (&ebpf_maps.BpfMap{}).CreateBPFMap(ebpf_maps.CreateEBPFMapInput{
		Type: uint32(constdef.BPF_MAP_TYPE_HASH.Index()), KeySize: 4, ValueSize: 4, MaxEntries: 1,
		PinOptions: &ebpf_maps.BpfMapPinOptions{Type: constdef.PIN_GLOBAL_NS.Index(), PinPath: pinPath},
	})
	require.NoError(t, err)
	require.NotZero(t, created.MapFD)

	open, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	var limit unix.Rlimit
	require.NoError(t, unix.Getrlimit(unix.RLIMIT_NOFILE, &limit))
	lowered := limit
	lowered.Cur = uint64(len(open) + 16)
	require.NoError(t, unix.Setrlimit(unix.RLIMIT_NOFILE, &lowered))
	var fillers []int
	t.Cleanup(func() {
		for _, fd := range fillers {
			unix.Close(fd)
		}
		unix.Setrlimit(unix.RLIMIT_NOFILE, &limit)
	})
	for {
		fd, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			require.ErrorIs(t, err, unix.EMFILE)
			break
		}
		fillers = append(fillers, fd)
	}

	releaseObject(createdObject{fd: int(created.MapFD), pinPath: pinPath})

	_, err = os.Stat(pinPath)
	assert.True(t, os.IsNotExist(err), "pin must be removed at the descriptor limit, got %v", err)
}

// An object a failed load created on fd 0 (stdin closed) is still closed and
// unpinned.
func TestReleaseObjectOnFDZero(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create maps in the kernel")
	}
	require.NoError(t, utils.Mount_bpf_fs())
	defer utils.Unmount_bpf_fs()

	pinPath := constdef.MAP_BPF_FS + "rk_fdzero_map"
	created, err := (&ebpf_maps.BpfMap{}).CreateBPFMap(ebpf_maps.CreateEBPFMapInput{
		Type: uint32(constdef.BPF_MAP_TYPE_HASH.Index()), KeySize: 4, ValueSize: 4, MaxEntries: 1,
		PinOptions: &ebpf_maps.BpfMapPinOptions{Type: constdef.PIN_GLOBAL_NS.Index(), PinPath: pinPath},
	})
	require.NoError(t, err)
	info, err := ebpf_maps.GetBPFmapInfo(int(created.MapFD))
	require.NoError(t, err)

	// Move the map onto fd 0, as if the process had started with stdin closed.
	stdin, err := unix.Dup(0)
	require.NoError(t, err)
	t.Cleanup(func() {
		unix.Dup2(stdin, 0)
		unix.Close(stdin)
	})
	require.NoError(t, unix.Dup2(int(created.MapFD), 0))
	require.NoError(t, unix.Close(int(created.MapFD)))

	releaseObject(createdObject{fd: 0, pinPath: pinPath})

	_, err = os.Stat(pinPath)
	assert.True(t, os.IsNotExist(err), "pin must be removed, got %v", err)
	// With the pin and its only FD gone, the kernel frees the map.
	assert.Eventually(t, func() bool {
		fd, err := utils.GetMapFDFromID(int(info.Id))
		if err == nil {
			unix.Close(fd)
		}
		return err != nil
	}, 2*time.Second, 50*time.Millisecond, "map %d must be freed", info.Id)
}
