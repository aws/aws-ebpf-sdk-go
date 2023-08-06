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
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	mock_ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps/mocks"
	mock_ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

var (
	MAPINDEX = 8
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

func TestLoadelf(t *testing.T) {
	m := setup(t, "../../test-data/tc.ingress.bpf.elf")
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

	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")
	_, _, err = elfLoader.doLoadELF()
	assert.NoError(t, err)
}

func TestLoadelfWithoutReloc(t *testing.T) {
	m := setup(t, "../../test-data/tc.bpf.elf")
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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")
	_, _, err = elfLoader.doLoadELF()
	assert.NoError(t, err)
}

func TestLoadelfWithoutProg(t *testing.T) {
	m := setup(t, "../../test-data/test.map.bpf.elf")
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
	elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")
	_, _, err = elfLoader.doLoadELF()
	assert.NoError(t, err)
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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

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
			want:        MAPINDEX,
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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				gotMapIndex := elfLoader.mapSectionIndex
				assert.Equal(t, tt.want, gotMapIndex)
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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

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
			name:        "Test reloc section",
			elfFileName: "../../test-data/tc.ingress.bpf.elf",
			expectList:  []string{"kprobe", "tc_cls", "tracepoint", "xdp"},
			want:        2,
			wantErr:     nil,
		},
		{
			name:        "Missing reloc section",
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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			assert.NoError(t, err)
			mapData, err := elfLoader.parseMap()
			if tt.wantErr != nil {
				assert.EqualError(t, err, tt.wantErr.Error())
			} else {
				//gotMapIndex := elfLoader.mapSectionIndex
				mapDataLen := len(mapData)
				assert.Equal(t, tt.want, mapDataLen)
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
			want:        []int{27, 0, 0, 262144, 0},
			wantErr:     nil,
		},
		{
			name:        "Invalid map contents",
			elfFileName: "../../test-data/test.map.bpf.elf",
			invalidate:  true,
			want:        []int{27, 0, 0, 262144, 0},
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
			elfLoader := newElfLoader(elfFile, m.ebpf_maps, m.ebpf_progs, "test")

			err = elfLoader.parseSection()
			assert.NoError(t, err)
			if tt.invalidate {
				var dummySection elf.Section = elf.Section{}
				copiedMapSection := *(elfLoader.mapSection)
				copiedMapSection.SectionHeader = dummySection.SectionHeader
				elfLoader.mapSection = &copiedMapSection
			}
			mapData, err := elfLoader.parseMap()
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
