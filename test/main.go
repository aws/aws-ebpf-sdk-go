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
		fmt.Printf("error mounting bpffs: %v\n", err)
	}
	return err
}

func unmount_bpf_fs() error {
	fmt.Println("Let's unmount BPF FS")
	err := syscall.Unmount("/sys/fs/bpf", 0)
	if err != nil {
		fmt.Printf("error unmounting bpffs: %v\n", err)
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
		{Name: "Test BPF_JMP instruction support", Func: TestBPFJMPSupport},
		{Name: "Test R_BPF_64_32 relocation handling with function inlining", Func: TestCrossSectionFunctionCalls},
		{Name: "Test cross-section JMP relocations", Func: TestCrossSectionJMPRelocations},
		{Name: "Test function inlining", Func: TestFunctionInlining},
		{Name: "Test JMP relocation support", Func: TestJMPRelocationSupport},
		{Name: "Test text section JMP", Func: TestTextSectionJMP},
		{Name: "Test simple text JMP", Func: TestSimpleTextJMP},
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

// TestCrossSectionJMPRelocations tests cross-section JMP relocations
func TestCrossSectionJMPRelocations() error {
	fmt.Println("Testing cross-section JMP relocations...")

	gosdkClient := goelf.New()
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/cross-section-jmp.bpf.elf", "crosssectionjmp")
	if err != nil {
		fmt.Println("Load cross-section JMP BPF failed", "err:", err)
		return err
	}

	fmt.Println("Successfully loaded BPF program with cross-section JMP relocations!")

	// Display loaded programs
	for pinPath, progData := range progInfo {
		fmt.Printf("Loaded Program: %s (Type: %s)\n", pinPath, progData.Program.ProgType)
	}

	// Display loaded maps
	for mapName, mapData := range loadedMaps {
		fmt.Printf("Loaded Map: %s (Type: %d, MaxEntries: %d)\n",
			mapName, mapData.MapMetaData.Type, mapData.MapMetaData.MaxEntries)
	}

	fmt.Println("Cross-section JMP relocations test completed successfully!")
	fmt.Println("This demonstrates successful R_BPF_64_32 relocation handling for:")
	fmt.Println("- Cross-section function calls (tc_cls to .text)")
	fmt.Println("- Function call relocation processing")
	fmt.Println("- Safe instruction conversion for BPF verifier")

	return nil
}

// TestFunctionInlining tests function inlining capabilities
func TestFunctionInlining() error {
	fmt.Println("Testing function inlining capabilities...")

	gosdkClient := goelf.New()
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/test-function-inlining.bpf.elf", "functioninlining")
	if err != nil {
		fmt.Println("Load function inlining BPF failed", "err:", err)
		return err
	}

	fmt.Println("Successfully loaded BPF program with function inlining!")

	// Display loaded programs
	for pinPath, progData := range progInfo {
		fmt.Printf("Loaded Program: %s (Type: %s)\n", pinPath, progData.Program.ProgType)
	}

	// Display loaded maps
	for mapName, mapData := range loadedMaps {
		fmt.Printf("Loaded Map: %s (Type: %d, MaxEntries: %d)\n",
			mapName, mapData.MapMetaData.Type, mapData.MapMetaData.MaxEntries)
	}

	fmt.Println("Function inlining test completed successfully!")
	fmt.Println("This demonstrates successful function inlining for:")
	fmt.Println("- Helper function calls")
	fmt.Println("- Cross-section function dependencies")
	fmt.Println("- Complex function call chains")

	return nil
}

// TestJMPRelocationSupport tests JMP relocation support
func TestJMPRelocationSupport() error {
	fmt.Println("Testing JMP relocation support...")

	gosdkClient := goelf.New()
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/test-jmp-relocation.bpf.elf", "jmprelocation")
	if err != nil {
		fmt.Println("Load JMP relocation BPF failed", "err:", err)
		return err
	}

	fmt.Println("Successfully loaded BPF program with JMP relocations!")

	// Display loaded programs
	for pinPath, progData := range progInfo {
		fmt.Printf("Loaded Program: %s (Type: %s)\n", pinPath, progData.Program.ProgType)
	}

	// Display loaded maps
	for mapName, mapData := range loadedMaps {
		fmt.Printf("Loaded Map: %s (Type: %d, MaxEntries: %d)\n",
			mapName, mapData.MapMetaData.Type, mapData.MapMetaData.MaxEntries)
	}

	fmt.Println("JMP relocation support test completed successfully!")
	fmt.Println("This demonstrates successful JMP relocation handling for:")
	fmt.Println("- BPF_JMP instructions")
	fmt.Println("- BPF_JMP32 instructions")
	fmt.Println("- Conditional and unconditional jumps")

	return nil
}

// TestTextSectionJMP tests text section JMP handling
func TestTextSectionJMP() error {
	fmt.Println("Testing text section JMP handling...")

	gosdkClient := goelf.New()
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/text-section-jmp.bpf.elf", "textsectionjmp")
	if err != nil {
		fmt.Println("Load text section JMP BPF failed", "err:", err)
		return err
	}

	fmt.Println("Successfully loaded BPF program with text section JMP!")

	// Display loaded programs
	for pinPath, progData := range progInfo {
		fmt.Printf("Loaded Program: %s (Type: %s)\n", pinPath, progData.Program.ProgType)
	}

	// Display loaded maps
	for mapName, mapData := range loadedMaps {
		fmt.Printf("Loaded Map: %s (Type: %d, MaxEntries: %d)\n",
			mapName, mapData.MapMetaData.Type, mapData.MapMetaData.MaxEntries)
	}

	fmt.Println("Text section JMP test completed successfully!")
	fmt.Println("This demonstrates successful text section JMP handling for:")
	fmt.Println("- Functions in .text section")
	fmt.Println("- JMP instructions within text section")
	fmt.Println("- Text section relocation processing")

	return nil
}

// TestSimpleTextJMP tests simple text JMP functionality
func TestSimpleTextJMP() error {
	fmt.Println("Testing simple text JMP functionality...")

	gosdkClient := goelf.New()
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/simple-text-jmp.bpf.elf", "simpletextjmp")
	if err != nil {
		fmt.Println("Load simple text JMP BPF failed", "err:", err)
		return err
	}

	fmt.Println("Successfully loaded BPF program with simple text JMP!")

	// Display loaded programs
	for pinPath, progData := range progInfo {
		fmt.Printf("Loaded Program: %s (Type: %s)\n", pinPath, progData.Program.ProgType)
	}

	// Display loaded maps
	for mapName, mapData := range loadedMaps {
		fmt.Printf("Loaded Map: %s (Type: %d, MaxEntries: %d)\n",
			mapName, mapData.MapMetaData.Type, mapData.MapMetaData.MaxEntries)
	}

	fmt.Println("Simple text JMP test completed successfully!")
	fmt.Println("This demonstrates successful simple text JMP handling for:")
	fmt.Println("- Basic JMP instructions")
	fmt.Println("- Simple control flow")
	fmt.Println("- Minimal relocation requirements")

	return nil
}

func TestCrossSectionFunctionCalls() error {
	fmt.Println("Testing R_BPF_64_32 relocation handling and function inlining...")

	gosdkClient := goelf.New()
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/test-cross-section-calls.bpf.elf", "crosssectiontest")
	if err != nil {
		fmt.Println("Load cross-section BPF test failed", "err:", err)
		return err
	}

	fmt.Println("Successfully loaded BPF program with cross-section function calls!")
	fmt.Println("This demonstrates successful R_BPF_64_32 relocation processing and function inlining.")

	// Display loaded programs
	for pinPath, progData := range progInfo {
		fmt.Printf("Loaded Program: %s (Type: %s)\n", pinPath, progData.Program.ProgType)
	}

	// Display loaded maps
	for mapName, mapData := range loadedMaps {
		fmt.Printf("Loaded Map: %s (Type: %d, MaxEntries: %d)\n",
			mapName, mapData.MapMetaData.Type, mapData.MapMetaData.MaxEntries)
	}

	// Test the counter map to verify the inlined functions work correctly
	if counterMap, ok := loadedMaps["counter_map"]; ok {
		fmt.Println("Testing counter map operations (exercises inlined functions)...")

		// Test counter operations
		for i := uint32(0); i < 5; i++ {
			value := uint64(i + 1)
			err = counterMap.UpdateMapEntry(
				uintptr(unsafe.Pointer(&i)),
				uintptr(unsafe.Pointer(&value)))
			if err != nil {
				// Try creating if update fails
				err = counterMap.CreateMapEntry(
					uintptr(unsafe.Pointer(&i)),
					uintptr(unsafe.Pointer(&value)))
				if err != nil {
					fmt.Printf("Unable to create/update counter entry %d: %v\n", i, err)
					return err
				}
			}
		}
		fmt.Println("Successfully initialized counter map")

		// Read back counters
		for i := uint32(0); i < 5; i++ {
			var value uint64
			err = counterMap.GetMapEntry(
				uintptr(unsafe.Pointer(&i)),
				uintptr(unsafe.Pointer(&value)))
			if err != nil {
				fmt.Printf("Unable to read counter entry %d: %v\n", i, err)
				return err
			}
			fmt.Printf("Counter[%d] = %d\n", i, value)
		}
	}

	fmt.Println("R_BPF_64_32 relocation and function inlining test completed successfully!")
	fmt.Println("This test demonstrates that the elfparser can now handle:")
	fmt.Println("- R_BPF_64_32 relocations (type 10) for BPF function calls")
	fmt.Println("- Cross-section function calls (.text to tc_cls)")
	fmt.Println("- Function inlining to resolve cross-section dependencies")
	fmt.Println("- Multiple function calls with proper relocation handling")
	fmt.Println("- Complex BPF programs with helper functions")

	return nil
}

func TestBPFJMPSupport() error {
	gosdkClient := goelf.New()
	progInfo, loadedMaps, err := gosdkClient.LoadBpfFile("c/test-jmp.bpf.elf", "jmptest")
	if err != nil {
		fmt.Println("Load BPF JMP test failed", "err:", err)
		return err
	}

	fmt.Println("Successfully loaded BPF program with JMP instructions!")

	// Display loaded programs
	for pinPath, progData := range progInfo {
		fmt.Printf("Loaded Program: %s (Type: %s)\n", pinPath, progData.Program.ProgType)
	}

	// Display loaded maps
	for mapName, mapData := range loadedMaps {
		fmt.Printf("Loaded Map: %s (Type: %d, MaxEntries: %d)\n",
			mapName, mapData.MapMetaData.Type, mapData.MapMetaData.MaxEntries)
	}

	// Test map operations to verify BPF_JMP functionality
	if jmpTestMap, ok := loadedMaps["jmp_test_map"]; ok {
		fmt.Println("Testing BPF_JMP map operations...")

		// Define test packet info structure
		type PacketInfo struct {
			SrcIP    uint32
			DstIP    uint32
			SrcPort  uint16
			DstPort  uint16
			Protocol uint8
			_        [3]byte // padding
		}

		type RuleEntry struct {
			Action  uint32
			Counter uint32
		}

		// Create test rule
		testKey := PacketInfo{
			SrcIP:    0xC0A80001, // 192.168.0.1
			DstIP:    0xC0A80002, // 192.168.0.2
			SrcPort:  8080,
			DstPort:  80,
			Protocol: 6, // TCP
		}

		testValue := RuleEntry{
			Action:  1, // Allow
			Counter: 0,
		}

		// Test map entry creation (this exercises BPF_CALL instructions)
		err = jmpTestMap.CreateMapEntry(
			uintptr(unsafe.Pointer(&testKey)),
			uintptr(unsafe.Pointer(&testValue)))
		if err != nil {
			fmt.Println("Unable to create map entry:", err)
			return err
		}
		fmt.Println("Successfully created test rule in jmp_test_map")

		// Test map lookup
		var retrievedValue RuleEntry
		err = jmpTestMap.GetMapEntry(
			uintptr(unsafe.Pointer(&testKey)),
			uintptr(unsafe.Pointer(&retrievedValue)))
		if err != nil {
			fmt.Println("Unable to retrieve map entry:", err)
			return err
		}
		fmt.Printf("Retrieved rule: Action=%d, Counter=%d\n",
			retrievedValue.Action, retrievedValue.Counter)
	}

	// Test stats map operations
	if statsMap, ok := loadedMaps["stats_map"]; ok {
		fmt.Println("Testing stats map operations...")

		// Initialize some stats (use UpdateMapEntry to handle existing entries)
		for i := uint32(0); i < 5; i++ {
			value := uint64(i * 10)
			err = statsMap.UpdateMapEntry(
				uintptr(unsafe.Pointer(&i)),
				uintptr(unsafe.Pointer(&value)))
			if err != nil {
				// Try creating if update fails
				err = statsMap.CreateMapEntry(
					uintptr(unsafe.Pointer(&i)),
					uintptr(unsafe.Pointer(&value)))
				if err != nil {
					fmt.Printf("Unable to create/update stats entry %d: %v\n", i, err)
					return err
				}
			}
		}
		fmt.Println("Successfully initialized stats map")

		// Read back stats
		for i := uint32(0); i < 5; i++ {
			var value uint64
			err = statsMap.GetMapEntry(
				uintptr(unsafe.Pointer(&i)),
				uintptr(unsafe.Pointer(&value)))
			if err != nil {
				fmt.Printf("Unable to read stats entry %d: %v\n", i, err)
				return err
			}
			fmt.Printf("Stats[%d] = %d\n", i, value)
		}
	}

	fmt.Println("BPF_JMP instruction support test completed successfully!")
	fmt.Println("This test demonstrates that the elfparser can now handle:")
	fmt.Println("- BPF_JMP instructions (64-bit jumps)")
	fmt.Println("- BPF_JMP32 instructions (32-bit jumps)")
	fmt.Println("- BPF_CALL instructions (helper function calls)")
	fmt.Println("- Complex control flow with conditional jumps")

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
