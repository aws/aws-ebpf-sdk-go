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
	gosdkClient := goelf.New()
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
	gosdkClient := goelf.New()
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
	gosdkClient := goelf.New()
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
	gosdkClient := goelf.New()
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
	gosdkClient := goelf.New()
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

	gosdkTcClient := ebpf_tc.New("lo")

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
	gosdkClient := goelf.New()

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
	gosdkClient := goelf.New()
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
	gosdkClient := goelf.New()
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
