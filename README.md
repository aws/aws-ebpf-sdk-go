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

A `BPF_MAP_TYPE_PROG_ARRAY` map (declared like any other map above) and a
`bpf_tail_call()` call in your BPF C source need no special ELF-loader
handling from the SDK: `bpf_tail_call()` is an ordinary helper call, and the
prog array map FD is applied through the same relocation path as any other
map reference. What the ELF loader cannot do for you is populate the map,
since that requires the FDs of the *target* programs, which only exist after
they've been loaded.

### Example: wiring an EDT rate-limiter as a tail-call target

Suppose you have a policy program (`tc.v4egress.bpf.c`) that tail-calls into
an EDT program (`edt.v4egress.bpf.c`) at index 1. Both ELFs declare the same
`tc_jump_table` prog array with `PIN_GLOBAL_NS`, so the kernel shares a
single map instance across loads.

1. Load the caller ELF (the program that issues `bpf_tail_call`). This
   creates the prog array map and loads the caller program:

```go
sdkClient := goebpfelfparser.New(goebpfelfparser.Config{})
callerProgs, maps, err := sdkClient.LoadBpfFile("tc.v4egress.bpf.elf", "egress")
```

2. Load the tail-call target from its own ELF. Because the prog array map
   uses `PIN_GLOBAL_NS`, both ELFs share the same kernel map instance via
   pinning — there is no need to pass the map FD across loads manually:

```go
targetProgs, _, err := sdkClient.LoadBpfFile("edt.v4egress.bpf.elf", "edt")
```

3. Look up the prog array map by name from the caller's maps, find the
   target program's FD from the second load, and populate the tail-call slot.

   `LoadBpfFile` returns programs keyed by their **full pin path**
   (e.g. `/sys/fs/bpf/globals/aws/programs/edt_handle_edt_egress`), so you
   need to iterate and match the C function name:

```go
progArray := maps["tc_jump_table"]
for pinPath, data := range targetProgs {
    if strings.Contains(pinPath, "handle_edt_egress") {
        err = progArray.UpdateProgArrayEntry(1 /* TC_TAIL_CALL_EDT_EGRESS */, data.Program.ProgFD)
        break
    }
}
```

### API reference

`UpdateProgArrayEntry` rejects maps that aren't `BPF_MAP_TYPE_PROG_ARRAY` and
negative FDs up front, rather than surfacing an opaque `EINVAL` from the
kernel. To remove a slot (so a tail call to that index falls through instead
of jumping), use `progArray.DeleteProgArrayEntry(index)`.

### Future improvements

The current API requires callers to iterate the returned program map and
match pin paths by substring to find a target program. Two planned
improvements would reduce this boilerplate:

- **`FindProgByFunc(progs map[string]BpfData, funcName string) (BpfData, bool)`** —
  a lookup helper that finds a loaded program by its C function name, removing
  the need for manual iteration and `strings.Contains` matching.

- **`LoadAndWireTailCall(targetELF, pinPrefix, funcName string, progArray BpfMap, index uint32)`** —
  a single-call method that loads a target ELF and inserts the named program
  into a prog array slot, collapsing steps 2–3 above into one operation.

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
