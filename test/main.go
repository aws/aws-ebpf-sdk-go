package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"
	"unsafe"

	goelf "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
	ebpf_maps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	ebpf_progs "github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	ebpf_tc "github.com/aws/aws-ebpf-sdk-go/pkg/tc"
	"github.com/fatih/color"
)

type testFunc struct {
	Name string
	Func func() error
}

func mount_bpf_fs() error {
	fmt.Println("Let's mount BPF FS")
	err := syscall.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "mode=0700")
	if err != nil {
		fmt.Println("error mounting bpffs: %v", err)
	}
	return err
}

func unmount_bpf_fs() error {
	fmt.Println("Let's unmount BPF FS")
	err := syscall.Unmount("/sys/fs/bpf", 0)
	if err != nil {
		fmt.Println("error unmounting bpffs: %v", err)
	}
	return err
}

func print_failure() {
	fmt.Println("\x1b[31mFAILED\x1b[0m")
}

func print_success() {
	fmt.Println("\x1b[32mSUCCESS!\x1b[0m")
}

func print_message(message string) {
	color := "\x1b[33m"
	formattedMessage := fmt.Sprintf("%s%s\x1b[0m", color, message)
	fmt.Println(formattedMessage)
}

func main() {
	fmt.Println("\x1b[34mStart testing SDK.........\x1b[0m")
	mount_bpf_fs()
	testFunctions := []testFunc{
		{Name: "Test loading Program", Func: TestLoadProg},
		{Name: "Test loading V6 Program", Func: TestLoadv6Prog},
		{Name: "Test loading TC filter", Func: TestLoadTCfilter},
		{Name: "Test loading Maps without Program", Func: TestLoadMapWithNoProg},
		{Name: "Test loading Map operations", Func: TestMapOperations},
		{Name: "Test updating Map size", Func: TestLoadMapWithCustomSize},
		{Name: "Test bulk Map operations", Func: TestBulkMapOperations},
		{Name: "Test bulk refresh Map operations", Func: TestBulkRefreshMapOperations},
		{Name: "Test tail call prog array", Func: TestTailCallProgArray},
	}

	testSummary := make(map[string]string)

	for _, fn := range testFunctions {
		message := "Testing " + fn.Name
		print_message(message)
		err := fn.Func()
		if err != nil {
			print_failure()
			testSummary[fn.Name] = "FAILED"
		} else {
			print_success()
			testSummary[fn.Name] = "SUCCESS"
		}
	}
	unmount_bpf_fs()

	fmt.Println(color.MagentaString("==========================================================="))
	fmt.Println(color.MagentaString("                   TESTING SUMMARY                         "))
	fmt.Println(color.MagentaString("==========================================================="))
	summary := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.AlignRight|tabwriter.Debug)
	header := strings.Join([]string{color.YellowString("TestCase"), color.YellowString("Result")}, "\t")

	fmt.Fprintln(summary, header)

	for testName, testStatus := range testSummary {
		if testStatus == "FAILED" {
			fmt.Fprintf(summary, "%s\t%s\n", testName, color.RedString(testStatus))
		}
		if testStatus == "SUCCESS" {
			fmt.Fprintf(summary, "%s\t%s\n", testName, color.GreenString(testStatus))
		}
	}
	summary.Flush()
	fmt.Println(color.MagentaString("==========================================================="))
}

func TestLoadProg() error {
	gosdkClient := goelf.New(goelf.Config{})
	progInfo, _, err := gosdkClient.LoadBpfFile("c/test.bpf.elf", "test")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for pinPath, _ := range progInfo {
		fmt.Println("Prog Info: ", "Pin Path: ", pinPath)
	}
	return nil
}

func TestLoadv6Prog() error {
	gosdkClient := goelf.New(goelf.Config{})
	progInfo, _, err := gosdkClient.LoadBpfFile("c/test-v6.bpf.elf", "test")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for pinPath, _ := range progInfo {
		fmt.Println("Prog Info: ", "Pin Path: ", pinPath)
	}
	return nil
}

func TestLoadMapWithNoProg() error {
	gosdkClient := goelf.New(goelf.Config{})
	_, loadedMap, err := gosdkClient.LoadBpfFile("c/test-map.bpf.elf", "test")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for mapName, _ := range loadedMap {
		fmt.Println("Map Info: ", "Name: ", mapName)
	}
	return nil

}

func TestMapOperations() error {
	gosdkClient := goelf.New(goelf.Config{})
	_, loadedMap, err := gosdkClient.LoadBpfFile("c/test-map.bpf.elf", "operations")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for mapName, _ := range loadedMap {
		fmt.Println("Map Info: ", "Name: ", mapName)
	}

	type BPFInetTrieKey struct {
		Prefixlen uint32
		Addr      [4]byte
	}
	dummykey := BPFInetTrieKey{
		Prefixlen: 32,
		Addr:      [4]byte{192, 168, 0, 0},
	}
	dummyvalue := uint32(40)

	dummykey2 := BPFInetTrieKey{
		Prefixlen: 32,
		Addr:      [4]byte{192, 168, 0, 1},
	}
	dummyvalue2 := uint32(30)

	if mapToUpdate, ok := loadedMap["ingress_map"]; ok {
		fmt.Println("Found map to Create entry")
		err = mapToUpdate.CreateMapEntry(uintptr(unsafe.Pointer((&dummykey))), uintptr(unsafe.Pointer((&dummyvalue))))
		if err != nil {
			fmt.Println("Unable to Insert into eBPF map: ", err)
			return err
		}
		dummyvalue := uint32(20)

		fmt.Println("Found map to Update entry")
		err = mapToUpdate.UpdateMapEntry(uintptr(unsafe.Pointer((&dummykey))), uintptr(unsafe.Pointer((&dummyvalue))))
		if err != nil {
			fmt.Println("Unable to Update into eBPF map: ", err)
			return err
		}

		var mapVal uint32
		fmt.Println("Get map entry")
		err := mapToUpdate.GetMapEntry(uintptr(unsafe.Pointer(&dummykey)), uintptr(unsafe.Pointer(&mapVal)))
		if err != nil {
			fmt.Println("Unable to get map entry: ", err)
			return err
		} else {
			fmt.Println("Found the map entry and value ", mapVal)
		}

		fmt.Println("Found map to Create dummy2 entry")
		err = mapToUpdate.CreateMapEntry(uintptr(unsafe.Pointer((&dummykey2))), uintptr(unsafe.Pointer((&dummyvalue2))))
		if err != nil {
			fmt.Println("Unable to Insert into eBPF map: ", err)
			return err
		}

		fmt.Println("Try get first  key")
		nextKey := BPFInetTrieKey{}
		err = mapToUpdate.GetNextMapEntry(uintptr(unsafe.Pointer(nil)), uintptr(unsafe.Pointer(&nextKey)))
		if err != nil {
			fmt.Println("Unable to get next key: ", err)
			return err
		} else {
			fmt.Println("Get map entry of next key")
			var newMapVal uint32
			err := mapToUpdate.GetMapEntry(uintptr(unsafe.Pointer(&nextKey)), uintptr(unsafe.Pointer(&newMapVal)))
			if err != nil {
				fmt.Println("Unable to get next map entry: ", err)
				return err
			} else {
				fmt.Println("Found the next map entry and value ", newMapVal)
			}
		}

		fmt.Println("Try next key")
		nextKey = BPFInetTrieKey{}
		err = mapToUpdate.GetNextMapEntry(uintptr(unsafe.Pointer(&dummykey)), uintptr(unsafe.Pointer(&nextKey)))
		if err != nil {
			fmt.Println("Unable to get next key: ", err)
			return err
		} else {
			fmt.Println("Get map entry of next key")
			var newMapVal uint32
			err := mapToUpdate.GetMapEntry(uintptr(unsafe.Pointer(&nextKey)), uintptr(unsafe.Pointer(&newMapVal)))
			if err != nil {
				fmt.Println("Unable to get next map entry: ", err)
				return err
			} else {
				fmt.Println("Found the next map entry and value ", newMapVal)
			}
		}

		fmt.Println("Dump all entries in map")

		iterKey := BPFInetTrieKey{}
		iterNextKey := BPFInetTrieKey{}

		err = mapToUpdate.GetFirstMapEntry(uintptr(unsafe.Pointer(&iterKey)))
		if err != nil {
			fmt.Println("Unable to get First key: ", err)
			return err
		} else {
			for {
				var newMapVal uint32
				err = mapToUpdate.GetMapEntry(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&newMapVal)))
				if err != nil {
					fmt.Println("Unable to get map entry: ", err)
					return err
				} else {
					fmt.Println("Found the map entry and value ", newMapVal)
				}

				err = mapToUpdate.GetNextMapEntry(uintptr(unsafe.Pointer(&iterKey)), uintptr(unsafe.Pointer(&iterNextKey)))
				if err != nil {
					fmt.Println("Done searching")
					break
				}
				iterKey = iterNextKey
			}
		}

		fmt.Println("Found map to Delete entry")
		err = mapToUpdate.DeleteMapEntry(uintptr(unsafe.Pointer((&dummykey))))
		if err != nil {
			fmt.Println("Unable to Delete in eBPF map: ", err)
			return err
		}
	}
	return nil

}

func TestLoadTCfilter() error {
	gosdkClient := goelf.New(goelf.Config{})
	progInfo, _, err := gosdkClient.LoadBpfFile("c/test.bpf.elf", "test")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for pinPath, _ := range progInfo {
		fmt.Println("Prog Info: ", "Pin Path: ", pinPath)
	}

	tcProg := progInfo["/sys/fs/bpf/globals/aws/programs/test_handle_ingress"].Program
	progFD := tcProg.ProgFD

	gosdkTcClient := ebpf_tc.New([]string{"lo"})

	fmt.Println("Try Attach ingress probe")
	err = gosdkTcClient.TCIngressAttach("lo", int(progFD), "ingress_test")
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	fmt.Println("Try Attach egress probe")
	err = gosdkTcClient.TCEgressAttach("lo", int(progFD), "egress_test")
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	fmt.Println("Try Detach ingress probe")
	err = gosdkTcClient.TCIngressDetach("lo")
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	fmt.Println("Try Detach egress probe")
	err = gosdkTcClient.TCEgressDetach("lo")
	if err != nil {
		fmt.Println("Failed attaching ingress probe")
	}
	return nil
}

func TestLoadMapWithCustomSize() error {
	gosdkClient := goelf.New(goelf.Config{})

	var customData goelf.BpfCustomData
	customData.FilePath = "c/test-map.bpf.elf"
	customData.CustomPinPath = "test"
	customData.CustomMapSize = make(map[string]int)
	customData.CustomMapSize["ingress_map"] = 1024

	_, loadedMap, err := gosdkClient.LoadBpfFileWithCustomData(customData)
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for mapName, mapData := range loadedMap {
		fmt.Println("Map Info: ", "Name: ", mapName)
		fmt.Println("Map Info: ", "Size: ", mapData.MapMetaData.MaxEntries)
	}
	return nil

}

func TestBulkMapOperations() error {
	gosdkClient := goelf.New(goelf.Config{})
	_, loadedMap, err := gosdkClient.LoadBpfFile("c/test-map.bpf.elf", "operations")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for mapName, _ := range loadedMap {
		fmt.Println("Map Info: ", "Name: ", mapName)
	}

	type BPFInetTrieKey struct {
		Prefixlen uint32
		Addr      [4]byte
	}

	const numEntries = 32 * 1000 // 32K entries

	// Create 32K entries
	mapToUpdate, ok := loadedMap["ingress_map"]
	if !ok {
		return fmt.Errorf("map 'ingress_map' not found")
	}

	for i := 0; i < numEntries; i++ {
		dummykey := BPFInetTrieKey{
			Prefixlen: 32,
			Addr:      [4]byte{byte(192 + i/256), byte(168 + (i/256)%256), byte(i % 256), 0},
		}
		dummyvalue := uint32(40)

		err = mapToUpdate.CreateMapEntry(uintptr(unsafe.Pointer(&dummykey)), uintptr(unsafe.Pointer(&dummyvalue)))
		if err != nil {
			fmt.Println("Unable to Insert into eBPF map: ", err)
			return err
		}
	}
	fmt.Println("Created 32K entries successfully")

	// Update 32K entries
	for i := 0; i < numEntries; i++ {
		dummykey := BPFInetTrieKey{
			Prefixlen: 32,
			Addr:      [4]byte{byte(192 + i/256), byte(168 + (i/256)%256), byte(i % 256), 0},
		}
		dummyvalue := uint32(20)

		err = mapToUpdate.UpdateMapEntry(uintptr(unsafe.Pointer(&dummykey)), uintptr(unsafe.Pointer(&dummyvalue)))
		if err != nil {
			fmt.Println("Unable to Update into eBPF map: ", err)
			return err
		}
	}
	fmt.Println("Updated 32K entries successfully")

	return nil
}

func ComputeTrieKey(n net.IPNet) []byte {
	prefixLen, _ := n.Mask.Size()
	key := make([]byte, 8)

	// Set the prefix length
	key[0] = byte(prefixLen)

	// Set the IP address
	copy(key[4:], n.IP.To4())

	fmt.Printf("Key: %v\n", key)
	return key
}

type BPFInetTrieKey struct {
	Prefixlen uint32
	Addr      [4]byte
}

func bpfInetTrieKeyToIPNet(key BPFInetTrieKey) net.IPNet {
	ip := net.IPv4(key.Addr[0], key.Addr[1], key.Addr[2], key.Addr[3])
	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(int(key.Prefixlen), 32),
	}
}

func TestBulkRefreshMapOperations() error {
	gosdkClient := goelf.New(goelf.Config{})
	_, loadedMap, err := gosdkClient.LoadBpfFile("c/test-map.bpf.elf", "operations")
	if err != nil {
		fmt.Println("Load BPF failed", "err:", err)
		return err
	}

	for mapName, _ := range loadedMap {
		fmt.Println("Map Info: ", "Name: ", mapName)
	}

	const numEntries = 32 * 1000 // 32K entries
	// Create 32K entries
	mapToUpdate, ok := loadedMap["ingress_map"]
	if !ok {
		return fmt.Errorf("map 'ingress_map' not found")
	}

	newMapContents := make(map[string][]byte, numEntries)
	for i := 0; i < numEntries; i++ {
		dummykey := BPFInetTrieKey{
			Prefixlen: 32,
			Addr:      [4]byte{byte(1 + i/65536), byte(0 + (i/256)%256), byte(i % 256), 0},
		}
		dummyvalue := uint32(40)

		err = mapToUpdate.CreateMapEntry(uintptr(unsafe.Pointer(&dummykey)), uintptr(unsafe.Pointer(&dummyvalue)))
		if err != nil {
			fmt.Println("Unable to Insert into eBPF map: ", err)
			return err
		}
		dummyvalue = uint32(50)
		ipnet := bpfInetTrieKeyToIPNet(dummykey)
		fmt.Println(ipnet)
		keyByte := ComputeTrieKey(ipnet)
		dummyValueByteArray := make([]byte, 4)
		binary.LittleEndian.PutUint32(dummyValueByteArray, dummyvalue)
		newMapContents[string(keyByte)] = dummyValueByteArray

	}
	fmt.Println("Created 32K entries successfully")

	// Update 32K entries
	err = mapToUpdate.BulkRefreshMapEntries(newMapContents)
	if err != nil {
		fmt.Println("Unable to Bulk Refresh eBPF map: ", err)
		return err
	}
	fmt.Println("Updated 32K entries successfully")

	return nil
}

func TestTailCallProgArray() error {
	// Step 1: Load the tailcall BPF program which contains a BPF_MAP_TYPE_PROG_ARRAY
	gosdkClient := goelf.New(goelf.Config{})
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/tc.tailcall.bpf.elf", "tailcall")
	if err != nil {
		fmt.Println("Load tailcall BPF failed", "err:", err)
		return err
	}

	fmt.Println("Loaded tailcall programs:")
	for pinPath, _ := range progInfo {
		fmt.Println("  Prog Pin Path: ", pinPath)
	}
	fmt.Println("Loaded tailcall maps:")
	for mapName, _ := range loadedMaps {
		fmt.Println("  Map Name: ", mapName)
	}

	// Step 2: Verify we got the prog array map
	progArrayMap, ok := loadedMaps["tailcall_map"]
	if !ok {
		return fmt.Errorf("tailcall_map not found in loaded maps")
	}
	fmt.Println("Found tailcall_map with FD:", progArrayMap.MapFD)

	// Step 3: Load the tail call target programs
	targetProgInfo, _, err := gosdkClient.LoadBpfFile("c/tc.tailcall_target.bpf.elf", "target")
	if err != nil {
		fmt.Println("Load tailcall target BPF failed", "err:", err)
		return err
	}

	fmt.Println("Loaded target programs:")
	for pinPath, _ := range targetProgInfo {
		fmt.Println("  Target Prog Pin Path: ", pinPath)
	}

	// Step 4: Get program FDs for the targets
	dropFD, passFD := -1, -1
	for pinPath, data := range targetProgInfo {
		switch {
		case strings.Contains(pinPath, "tailcall_target_drop"):
			dropFD = data.Program.ProgFD
			fmt.Println("  Drop target FD:", dropFD)
		case strings.Contains(pinPath, "tailcall_target_pass"):
			passFD = data.Program.ProgFD
			fmt.Println("  Pass target FD:", passFD)
		}
	}

	if dropFD < 0 || passFD < 0 {
		return fmt.Errorf("failed to find target program FDs: dropFD=%d passFD=%d", dropFD, passFD)
	}

	// Step 5: Test UpdateProgArrayEntry - insert tail call targets into prog array
	fmt.Println("Inserting drop program into slot 0...")
	err = progArrayMap.UpdateProgArrayEntry(0, dropFD)
	if err != nil {
		fmt.Println("UpdateProgArrayEntry slot 0 failed:", err)
		return err
	}

	fmt.Println("Inserting pass program into slot 1...")
	err = progArrayMap.UpdateProgArrayEntry(1, passFD)
	if err != nil {
		fmt.Println("UpdateProgArrayEntry slot 1 failed:", err)
		return err
	}

	// Step 6: Verify the prog array entries by reading them back
	// Prog array lookup returns program IDs (not FDs)
	dropProgInfo, err := ebpf_progs.GetBPFprogInfo(dropFD)
	if err != nil {
		fmt.Println("GetBPFprogInfo for drop failed:", err)
		return err
	}
	passProgInfo, err := ebpf_progs.GetBPFprogInfo(passFD)
	if err != nil {
		fmt.Println("GetBPFprogInfo for pass failed:", err)
		return err
	}

	key0 := uint32(0)
	val0 := uint32(0)
	err = progArrayMap.GetMapEntry(uintptr(unsafe.Pointer(&key0)), uintptr(unsafe.Pointer(&val0)))
	if err != nil {
		fmt.Println("GetMapEntry for slot 0 failed:", err)
		return err
	}
	if val0 != dropProgInfo.ID {
		return fmt.Errorf("slot 0: expected prog ID %d, got %d", dropProgInfo.ID, val0)
	}
	fmt.Printf("Slot 0 verified: prog ID %d matches drop program\n", val0)

	key1 := uint32(1)
	val1 := uint32(0)
	err = progArrayMap.GetMapEntry(uintptr(unsafe.Pointer(&key1)), uintptr(unsafe.Pointer(&val1)))
	if err != nil {
		fmt.Println("GetMapEntry for slot 1 failed:", err)
		return err
	}
	if val1 != passProgInfo.ID {
		return fmt.Errorf("slot 1: expected prog ID %d, got %d", passProgInfo.ID, val1)
	}
	fmt.Printf("Slot 1 verified: prog ID %d matches pass program\n", val1)

	// Step 7: Test UpdateProgArrayEntry - overwrite slot 0 with pass program
	fmt.Println("Overwriting slot 0 with pass program...")
	err = progArrayMap.UpdateProgArrayEntry(0, passFD)
	if err != nil {
		fmt.Println("UpdateProgArrayEntry overwrite slot 0 failed:", err)
		return err
	}

	val0 = uint32(0)
	err = progArrayMap.GetMapEntry(uintptr(unsafe.Pointer(&key0)), uintptr(unsafe.Pointer(&val0)))
	if err != nil {
		fmt.Println("GetMapEntry for overwritten slot 0 failed:", err)
		return err
	}
	if val0 != passProgInfo.ID {
		return fmt.Errorf("overwritten slot 0: expected prog ID %d, got %d", passProgInfo.ID, val0)
	}
	fmt.Printf("Slot 0 overwrite verified: prog ID %d matches pass program\n", val0)

	// Step 8: Test DeleteProgArrayEntry - clear slot 1
	fmt.Println("Deleting slot 1...")
	err = progArrayMap.DeleteProgArrayEntry(1)
	if err != nil {
		fmt.Println("DeleteProgArrayEntry slot 1 failed:", err)
		return err
	}

	// After deletion, lookup should fail
	val1 = uint32(0)
	err = progArrayMap.GetMapEntry(uintptr(unsafe.Pointer(&key1)), uintptr(unsafe.Pointer(&val1)))
	if err == nil {
		return fmt.Errorf("slot 1 should be empty after delete, but got prog ID %d", val1)
	}
	fmt.Println("Slot 1 deletion verified: lookup correctly returns error")

	// Step 9: Test error cases
	// Test with wrong map type
	fmt.Println("Testing error case: wrong map type...")
	wrongMap := ebpf_maps.BpfMap{MapMetaData: ebpf_maps.CreateEBPFMapInput{
		Name: "not_prog_array",
		Type: 1, // BPF_MAP_TYPE_HASH
	}}
	err = wrongMap.UpdateProgArrayEntry(0, dropFD)
	if err == nil {
		return fmt.Errorf("expected error when using UpdateProgArrayEntry on non-prog-array map")
	}
	fmt.Println("  Correctly rejected wrong map type:", err)

	// Test with negative FD
	fmt.Println("Testing error case: negative FD...")
	err = progArrayMap.UpdateProgArrayEntry(0, -1)
	if err == nil {
		return fmt.Errorf("expected error when using negative FD")
	}
	fmt.Println("  Correctly rejected negative FD:", err)

	// Step 10: Test DeleteProgArrayEntry with wrong map type
	fmt.Println("Testing error case: DeleteProgArrayEntry on wrong map type...")
	err = wrongMap.DeleteProgArrayEntry(0)
	if err == nil {
		return fmt.Errorf("expected error when using DeleteProgArrayEntry on non-prog-array map")
	}
	fmt.Println("  Correctly rejected wrong map type for delete:", err)

	// Step 11: Clean up - delete remaining slot
	fmt.Println("Cleaning up: deleting slot 0...")
	err = progArrayMap.DeleteProgArrayEntry(0)
	if err != nil {
		fmt.Println("DeleteProgArrayEntry cleanup slot 0 failed:", err)
		return err
	}

	fmt.Println("Tail call prog array test PASSED!")
	return nil
}
