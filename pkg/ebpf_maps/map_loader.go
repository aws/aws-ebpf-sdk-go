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

package ebpf_maps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"github.com/aws/aws-ebpf-sdk-go/pkg/utils"
	"golang.org/x/sys/unix"
)

var log = logger.Get()

type BPFMap struct {
	MapFD       uint32
	MapID       uint32
	MapMetaData BpfMapData
}

type BpfMapDef struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	InnerMapFd uint32
	Pinning    uint32
}

type BpfMapData struct {
	Def      BpfMapDef
	numaNode uint32
	Name     string
}

type BpfMapInfo struct {
	Type                  uint32
	Id                    uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	Name                  [utils.BPFObjNameLen]byte
	IfIndex               uint32
	BtfVmLinuxValueTypeId uint32
	NetnsDev              uint64
	NetnsIno              uint64
	BTFID                 uint32
	BTFKeyTypeID          uint32
	BTFValueTypeId        uint32
	Pad                   uint32
	MapExtra              uint64
}

/*
 *
 *	struct { anonymous struct used by BPF_*_GET_*_ID
 *		union {
 *			__u32		start_id;
 *			__u32		prog_id;
 *			__u32		map_id;
 *			__u32		btf_id;
 *			__u32		link_id;
 *		};
 *		__u32		next_id;
 *		__u32		open_flags;
 *	};
 */

type BpfMapShowAttr struct {
	Map_id     uint32
	next_id    uint32
	open_flags uint32
}

/*
 * struct { anonymous struct used by BPF_OBJ_GET_INFO_BY_FD
 *	__u32		bpf_fd;
 *	__u32		info_len;
 *	__aligned_u64	info;
 * } info;
*
*/
type BpfObjGetInfo struct {
	bpf_fd   uint32
	info_len uint32
	info     uintptr
}

/*
 *	struct { anonymous struct used by BPF_OBJ_* commands
 *	__aligned_u64	pathname;
 *	__u32		bpf_fd;
 *	__u32		file_flags;
 * };
 */
type BpfObjGet struct {
	pathname   uintptr
	bpf_fd     uint32
	file_flags uint32
}

type BpfMapAPIs interface {
	CreateMap(MapMetaData BpfMapData) (BPFMap, error)
	PinMap(pinPath string) error
	UnPinMap(pinPath string) error
	CreateMapEntry(key, value uintptr) error
	UpdateMapEntry(key, value uintptr) error
	CreateUpdateMap(key, value uintptr, updateFlags uint64) error
	DeleteMapEntry(key uintptr) error
	GetFirstMapEntry(nextKey uintptr) error
	GetNextMapEntry(key, nextKey uintptr) error
	GetMapEntry(key, value uintptr) error
	BulkUpdateMapEntry(keyvalue map[uintptr]uintptr) error
	BulkDeleteMapEntry(keyvalue map[uintptr]uintptr) error
	BulkRefreshMapEntries(newMapContents map[string]uintptr) error
	BpfGetMapFromPinPath(pinPath string) (BpfMapInfo, error)
}

func (m *BPFMap) CreateMap(MapMetaData BpfMapData) (BPFMap, error) {

	mapCont := BpfMapData{
		Def: BpfMapDef{
			Type:       uint32(MapMetaData.Def.Type),
			KeySize:    MapMetaData.Def.KeySize,
			ValueSize:  MapMetaData.Def.ValueSize,
			MaxEntries: MapMetaData.Def.MaxEntries,
			Flags:      MapMetaData.Def.Flags,
			InnerMapFd: 0,
		},
		Name: MapMetaData.Name,
	}
	mapData := unsafe.Pointer(&mapCont)
	mapDataSize := unsafe.Sizeof(mapCont)

	log.Infof("Calling BPFsys for name %s mapType %d keysize %d valuesize %d max entries %d and flags %d", string(MapMetaData.Name[:]), MapMetaData.Def.Type, MapMetaData.Def.KeySize, MapMetaData.Def.ValueSize, MapMetaData.Def.MaxEntries, MapMetaData.Def.Flags)

	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_CREATE,
		uintptr(mapData),
		mapDataSize,
	)

	if (errno < 0) || (int(ret) == -1) {
		log.Infof("Unable to create map and ret %d and err %s", int(ret), errno)
		return BPFMap{}, fmt.Errorf("Unable to create map: %s", errno)
	}

	log.Infof("Create map done with fd : %d", int(ret))

	bpfMap := BPFMap{
		MapFD:       uint32(ret),
		MapMetaData: MapMetaData,
	}
	return bpfMap, nil
}

func (m *BPFMap) PinMap(pinPath string) error {
	if m.MapMetaData.Def.Pinning == utils.PIN_NONE {
		return nil
	}

	if m.MapMetaData.Def.Pinning == utils.PIN_GLOBAL_NS {

		//If pinPath is already present lets delete and create a new one
		if utils.IsfileExists(pinPath) {
			log.Infof("Found file %s so deleting the path", pinPath)
			err := utils.UnPinObject(pinPath)
			if err != nil {
				log.Infof("Failed to UnPinObject %v", err)
				return err
			}
		}
		err := os.MkdirAll(filepath.Dir(pinPath), 0755)
		if err != nil {
			log.Infof("error creating directory %s: %v", filepath.Dir(pinPath), err)
			return fmt.Errorf("error creating directory %s: %v", filepath.Dir(pinPath), err)
		}
		_, err = os.Stat(pinPath)
		if err == nil {
			log.Infof("aborting, found file at %s", pinPath)
			return fmt.Errorf("aborting, found file at %s", pinPath)
		}
		if err != nil && !os.IsNotExist(err) {
			log.Infof("failed to stat %s: %v", pinPath, err)
			return fmt.Errorf("failed to stat %s: %v", pinPath, err)
		}

		return utils.PinObject(m.MapFD, pinPath)

	}
	return nil

}

func (m *BPFMap) UnPinMap(pinPath string) error {
	err := utils.UnPinObject(pinPath)
	if err != nil {
		log.Infof("Failed to unpin map")
		return err
	}
	if m.MapFD <= 0 {
		log.Infof("FD is invalid or closed %d", m.MapFD)
		return nil
	}
	return unix.Close(int(m.MapFD))
}

func (m *BPFMap) CreateMapEntry(key, value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(utils.BPF_NOEXIST))
}

func (m *BPFMap) UpdateMapEntry(key, value uintptr) error {
	return m.CreateUpdateMap(key, value, uint64(utils.BPF_ANY))
}

func (m *BPFMap) CreateUpdateMap(key, value uintptr, updateFlags uint64) error {

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}

	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Flags: updateFlags,
		Key:   uint64(key),
		Value: uint64(value),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)

	if errno != 0 {
		log.Infof("Unable to create/update map entry and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to update map: %s", errno)
	}

	log.Infof("Create/Update map entry done with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

func (m *BPFMap) DeleteMapEntry(key uintptr) error {

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ID %d and err %s", int(m.MapID), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_DELETE_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Unable to delete map entry and ret %d and err %s", int(ret), errno)
		return fmt.Errorf("Unable to update map: %s", errno)
	}

	log.Infof("Delete map entry done with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

// To get the first entry pass key as `nil`
func (m *BPFMap) GetFirstMapEntry(nextKey uintptr) error {
	return m.GetNextMapEntry(uintptr(unsafe.Pointer(nil)), nextKey)
}

func (m *BPFMap) GetNextMapEntry(key, nextKey uintptr) error {

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(nextKey),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errors.Is(errno, unix.ENOENT) {
		log.Infof("Last entry read done")
		unix.Close(mapFD)
		return errno
	}
	if errno != 0 {
		log.Infof("Unable to get next map entry and ret %d and err %s", int(ret), errno)
		unix.Close(mapFD)
		return fmt.Errorf("Unable to get next map entry: %s", errno)
	}

	log.Infof("Got next map entry with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

func (m *BPFMap) GetAllMapKeys() ([]string, error) {
	var keyList []string
	keySize := m.MapMetaData.Def.KeySize

	curKey := make([]byte, keySize)
	nextKey := make([]byte, keySize)

	err := m.GetFirstMapEntry(uintptr(unsafe.Pointer(&curKey[0])))
	if err != nil {
		log.Infof("Unable to get first key %s", err)
		return nil, fmt.Errorf("Unable to get first key entry: %s", err)
	} else {
		for {
			err = m.GetNextMapEntry(uintptr(unsafe.Pointer(&curKey[0])), uintptr(unsafe.Pointer(&nextKey[0])))
			log.Infof("Adding to key list %v", curKey)
			keyList = append(keyList, string(curKey))
			if errors.Is(err, unix.ENOENT) {
				log.Infof("Done reading all entries")
				return keyList, nil
			}
			if err != nil {
				log.Infof("Unable to get next key %s", err)
				break
			}
			//curKey = nextKey
			copy(curKey, nextKey)
		}
	}
	log.Infof("Done get all keys")
	return keyList, err
}

func (m *BPFMap) GetMapEntry(key, value uintptr) error {

	mapFD, err := utils.GetMapFDFromID(int(m.MapID))
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(value),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		log.Infof("Unable to get map entry and ret %d and err %s", int(ret), errno)
		unix.Close(mapFD)
		return fmt.Errorf("Unable to get next map entry: %s", errno)
	}

	log.Infof("Got map entry with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

func (m *BPFMap) BulkDeleteMapEntry(keyvalue map[uintptr]uintptr) error {
	for k, _ := range keyvalue {
		err := m.DeleteMapEntry(k)
		if err != nil {
			log.Infof("One of the element delete failed hence returning from bulk update")
			return err
		}
	}
	log.Infof("Bulk delete is successful for mapID: %d", int(m.MapID))
	return nil
}

func (m *BPFMap) BulkUpdateMapEntry(keyvalue map[uintptr]uintptr) error {
	for k, v := range keyvalue {
		log.Infof("Key being programmed - in bytearray ", *((*uint64)(unsafe.Pointer(k))))
		err := m.UpdateMapEntry(k, v)
		if err != nil {
			log.Infof("One of the element update failed hence returning from bulk update")
			return err
		}
	}
	log.Infof("Bulk update is successful for mapID: %d", int(m.MapID))
	return nil
}

func (m *BPFMap) BulkRefreshMapEntries(newMapContents map[string]uintptr) error {

	// 1. Construct i/p to bulkMap
	keyvaluePtr := make(map[uintptr]uintptr)

	for k, v := range newMapContents {
		keyByte := []byte(k)
		log.Infof("Converted string to bytearray %v", keyByte)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
		keyvaluePtr[keyPtr] = v
	}

	// 2. Update all map entries
	err := m.BulkUpdateMapEntry(keyvaluePtr)
	if err != nil {
		log.Infof("Refresh map failed: during update %v", err)
		return err
	}

	// 3. Read all map entries
	retrievedMapKeyList, err := m.GetAllMapKeys()
	if err != nil {
		log.Infof("Get all map keys failed: during Refresh %v", err)
		return err
	}

	// 4. Delete stale Keys
	log.Infof("Check for stale entries and got %d entries from BPF map", len(retrievedMapKeyList))
	for _, key := range retrievedMapKeyList {
		log.Infof("Checking if key %s is deltable", key)
		if _, ok := newMapContents[key]; !ok {
			log.Infof("This can be deleted, not needed anymore...")
			deletableKeyByte := []byte(key)
			deletableKeyBytePtr := uintptr(unsafe.Pointer(&deletableKeyByte[0]))
			err = m.DeleteMapEntry(deletableKeyBytePtr)
			if err != nil {
				log.Infof("Unable to delete entry %s but will continue and err %v", key, err)
			}
		}
	}
	return nil
}

func (attr *BpfMapShowAttr) isBpfMapGetNextID() bool {
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_GET_NEXT_ID,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Infof("Done get_next_id for Map - ret %d and err %s", int(ret), errno)
		return false
	}

	attr.Map_id = attr.next_id
	return true
}

func (objattr *BpfObjGetInfo) BpfGetMapInfoForFD() error {
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_OBJ_GET_INFO_BY_FD,
		uintptr(unsafe.Pointer(objattr)),
		unsafe.Sizeof(*objattr),
	)
	if errno != 0 {
		log.Infof("Failed to get object info by FD - ret %d and err %s", int(ret), errno)
		return errno
	}
	return nil
}

func GetIDFromFD(mapFD int) (int, error) {
	mapInfo, err := GetBPFmapInfo(mapFD)
	if err != nil {
		return -1, err
	}
	return int(mapInfo.Id), nil
}

func GetBPFmapInfo(mapFD int) (BpfMapInfo, error) {
	var bpfMapInfo BpfMapInfo
	objInfo := BpfObjGetInfo{
		bpf_fd:   uint32(mapFD),
		info_len: uint32(unsafe.Sizeof(bpfMapInfo)),
		info:     uintptr(unsafe.Pointer(&bpfMapInfo)),
	}

	err := objInfo.BpfGetMapInfoForFD()
	if err != nil {
		log.Infof("Failed to get map Info for FD - ", mapFD)
		return BpfMapInfo{}, err
	}

	return bpfMapInfo, nil
}

func BpfGetAllMapInfo() ([]BpfMapInfo, error) {
	loadedMaps := []BpfMapInfo{}
	attr := BpfMapShowAttr{}
	log.Infof("In get all prog info")
	for attr.isBpfMapGetNextID() {
		log.Infof("Got ID - %d", attr.next_id)

		mapfd, err := utils.GetMapFDFromID(int(attr.next_id))
		if err != nil {
			log.Infof("Failed to get map Info")
			return nil, err
		}
		log.Infof("Found map FD - %d", mapfd)
		bpfMapInfo, err := GetBPFmapInfo(mapfd)
		if err != nil {
			log.Infof("Failed to get map Info for FD", mapfd)
			return nil, err
		}
		unix.Close(mapfd)

		loadedMaps = append(loadedMaps, bpfMapInfo)
	}
	log.Infof("Done all map info!!!")
	return loadedMaps, nil
}

func (attr *BpfObjGet) BpfGetObject() (int, error) {
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_OBJ_GET,
		uintptr(unsafe.Pointer(attr)),
		unsafe.Sizeof(*attr),
	)
	if errno != 0 {
		log.Infof("Failed to get Map FD - ret %d and err %s", int(ret), errno)
		return 0, errno
	}
	return int(ret), nil
}

func (m *BPFMap) BpfGetMapFromPinPath(pinPath string) (BpfMapInfo, error) {
	if len(pinPath) == 0 {
		return BpfMapInfo{}, fmt.Errorf("Invalid pinPath")
	}

	cPath := []byte(pinPath + "\x00")
	objInfo := BpfObjGet{
		pathname: uintptr(unsafe.Pointer(&cPath[0])),
	}

	mapFD, err := objInfo.BpfGetObject()
	if err != nil {
		log.Infof("Failed to get object")
		return BpfMapInfo{}, err

	}

	bpfMapInfo, err := GetBPFmapInfo(mapFD)
	if err != nil {
		log.Infof("Failed to get map Info for FD - %d", mapFD)
		return bpfMapInfo, err
	}
	err = unix.Close(int(mapFD))
	if err != nil {
		log.Infof("Failed to close but return the mapinfo")
	}

	return bpfMapInfo, nil
}

func GetFirstMapEntryByID(nextKey uintptr, mapID int) error {
	return GetNextMapEntryByID(uintptr(unsafe.Pointer(nil)), nextKey, mapID)
}

func GetNextMapEntryByID(key, nextKey uintptr, mapID int) error {

	mapFD, err := utils.GetMapFDFromID(mapID)
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}
	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(nextKey),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_GET_NEXT_KEY,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errors.Is(errno, unix.ENOENT) {
		unix.Close(mapFD)
		return errno
	}
	if errno != 0 {
		log.Infof("Unable to get next map entry and ret %d and err %s", int(ret), errno)
		unix.Close(mapFD)
		return fmt.Errorf("Unable to get next map entry: %s", errno)
	}

	log.Infof("Got next map entry with fd : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}

func GetMapEntryByID(key, value uintptr, mapID int) error {

	mapFD, err := utils.GetMapFDFromID(mapID)
	if err != nil {
		log.Infof("Unable to GetMapFDfromID and ret %d and err %s", int(mapFD), err)
		return fmt.Errorf("Unable to get FD: %s", err)
	}

	attr := utils.BpfMapAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(key),
		Value: uint64(value),
	}
	ret, _, errno := unix.Syscall(
		unix.SYS_BPF,
		utils.BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)

	if errno != 0 {
		log.Infof("Unable to get map entry and ret %d and err %s", int(ret), errno)
		unix.Close(mapFD)
		return fmt.Errorf("Unable to get next map entry: %s", errno)
	}

	log.Infof("Got map entry with ret : %d and err %s", int(ret), errno)
	unix.Close(mapFD)
	return nil
}
