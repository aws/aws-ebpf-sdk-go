# aws-ebpf-sdk-go

Golang based SDK for kernel eBPF operations i.e, load/attach/detach eBPF programs and create/delete/update maps. SDK relies on Unix bpf() system calls.

SDK currently supports -

1. eBPF program types -
   a. Traffic Classifiers
   b. XDP
   c. Kprobes/Kretprobes
   d. Tracepoint probes
2. Ring buffer (would need kernel 5.10+)

SDK currently do not support -

1. Map in Map
2. Perf buffer

Contributions welcome!

Note: This is the first version of SDK and interface is subject to change so kindly review the release notes before upgrading.

# Getting started

## How to build SDK?

Run `make build-linux` - this will build the sdk binary.

## How to build elf file?

```
clang -I../../.. -O2 -target bpf -c <C file> -o <ELF file>
```

## How to use the SDK?

**Note:** SDK expects the BPF File System (/sys/fs/bpf) to be mounted.
 
In your application, 

1. Get the latest SDK -

```
GOPROXY=direct go get github.com/aws/aws-ebpf-sdk-go
```

2. Import the elfparser - 

```
goebpfelfparser "github.com/aws/aws-ebpf-sdk-go/pkg/elfparser"
```

3. Load the elf -

```
sdkClient := goebpfelfparser.New(goebpfelfparser.Config{})
sdkClient.LoadBpfFile(<ELF file>, <custom pin path>)
```

On a successful load, SDK returns -

1. loaded programs (includes associated maps) 

```
This is indexed by the pinpath - 

type BpfData struct {
	Program ebpf_progs.BpfProgram       // Return the program
	Maps    map[string]ebpf_maps.BpfMap // List of associated maps
}
```

2. All maps in the elf file
```
This is indexed by the map name -

type BpfMap struct {
	MapFD       uint32
	MapID       uint32
	MapMetaData CreateEBPFMapInput
}
```

Application can specify custom pinpath while loading the elf file.

Maps and Programs pinpath location is not customizable with the current version of SDK and will be installed under the below locations by default -

Program PinPath - "/sys/fs/bpf/globals/aws/programs/"

Map PinPath - "/sys/fs/bpf/globals/aws/maps/"

Map defintion should follow the below definition else the SDK will fail to create the map.

```
struct bpf_map_def_pvt {
	__u32 type;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	__u32 pinning;
	__u32 inner_map_fd;
};
```

## How to use tail calls (BPF_MAP_TYPE_PROG_ARRAY)?

Declare a `BPF_MAP_TYPE_PROG_ARRAY` map in your BPF C source and use
`bpf_tail_call()` as usual. The SDK handles map relocation like any other
map. Populating the prog array is done after loading, once target program
FDs are available.

### Example

```go
sdkClient := goebpfelfparser.New(goebpfelfparser.Config{})

// Load the caller (creates the prog array map)
callerProgs, maps, err := sdkClient.LoadBpfFile("tc.policy.bpf.elf", "policy")

// Load the tail call target
targetProgs, _, err := sdkClient.LoadBpfFile("tc.edt.bpf.elf", "edt")

// Wire target into prog array slot
progArray := maps["jump_table"]
for pinPath, data := range targetProgs {
    if strings.Contains(pinPath, "handle_edt") {
        err = progArray.UpdateProgArrayEntry(1, data.Program.ProgFD)
        break
    }
}

// Remove a slot (tail call to this index falls through)
err = progArray.DeleteProgArrayEntry(1)
```

`LoadBpfFile` returns programs keyed by full pin path
(e.g. `/sys/fs/bpf/globals/aws/programs/edt_handle_edt`), so match
by substring to find the target.

## How to debug SDK issues?

SDK logs are located here `/var/log/aws-routed-eni/ebpf-sdk.log`.

## How to run unit-test

Run `sudo make unit-test`

Note: you would need to run this on you linux system

## How to run functional tests

Go to -

```
cd test/
sudo make run-test
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

If you think you’ve found a potential security issue, please do not post it in the Issues. Instead, please follow the
instructions [here](https://aws.amazon.com/security/vulnerability-reporting/) or [email AWS security directly](mailto:aws-security@amazon.com).

## License

This project is licensed under the Apache-2.0 License.
