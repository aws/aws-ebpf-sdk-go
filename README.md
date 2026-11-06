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

# Upgrading

## Breaking changes since v1.0.20

1. **`New` now returns an error.** `New(cfg Config) BpfSDKClient` became
   `New(cfg Config) (BpfSDKClient, error)`. It rejects a `Config` it knows
   cannot classify your pins; see
   [How to configure the SDK?](#how-to-configure-the-sdk).

2. **Global maps must now be declared.** `Config` gained `GlobalMaps` and
   `GlobalPinPrefix`. Previously a map was treated as global if it was *not*
   listed in `NamespacedMaps`, so global classification worked with no
   configuration. It is now a positive check against `GlobalMaps`, so a caller
   that upgrades without setting these two fields classifies nothing as global
   and `RecoverGlobalMaps` recovers nothing. Populate both fields.

3. **`BpfSDKClient` gained a method,** `GetProgIdentifierFromBPFPinPath`:

   ```go
   GetProgIdentifierFromBPFPinPath(pinPath string) (podIdentifier, progName string, isGlobal bool, err error)
   ```

   It returns an error naming the specific defect for a pin filename it cannot
   parse, so callers can test `err != nil` rather than checking for an empty
   identifier. Code that provides its own implementation of the interface
   (including generated mocks) must be regenerated or updated.

4. **Recovery returns a result alongside a partial-failure error.**
   `RecoverAllBpfProgramsAndMaps` and `GetAllBpfProgramsAndMaps` now skip a pin
   they cannot read instead of abandoning the whole walk, and report it by
   wrapping the new `ErrPartialRecovery`. If you treat any non-nil error from
   these as total failure, you will discard a usable result; see
   [How to recover state after a restart?](#how-to-recover-state-after-a-restart).

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
sdkClient, err := goebpfelfparser.New(goebpfelfparser.Config{})
if err != nil {
	panic(err)
}
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

## How to configure the SDK?

`New` takes a `Config` describing how your pin filenames are laid out. The SDK
uses it to tell a per-pod pin from a node-wide (global) one when it walks the
BPF filesystem.

```go
sdkClient, err := goebpfelfparser.New(goebpfelfparser.Config{
	// Map names you pin once per pod, under a "<podName>@<namespace>"
	// identifier passed as the custom pin path to LoadBpfFile. These pin as
	// "<podName>@<namespace>_<mapName>".
	NamespacedMaps: []string{"ingress_map", "egress_map"},

	// Map names you pin once per node. These pin as
	// "<GlobalPinPrefix>_<mapName>".
	GlobalMaps: []string{"aws_conntrack_map", "policy_events"},

	// Filename prefix for node-wide pins, e.g. "global" gives
	// "global_aws_conntrack_map".
	GlobalPinPrefix: "global",
})
```

**Every map name you pin must appear in exactly one of `NamespacedMaps` or
`GlobalMaps`.** A name in neither list cannot be classified, so programs
referencing it are not recovered after a restart. `New` returns an error for a
`Config` it knows cannot work — a name in both lists, or `GlobalMaps` set with
an empty `GlobalPinPrefix` — so check it rather than discarding it.

An empty `Config{}` is valid and is all you need to load and attach programs,
which is why the examples above use it. It classifies nothing as global,
so if you also use the recovery calls below, populate these fields.

## How to recover state after a restart?

When your application restarts, the programs and maps it pinned are still live
in the kernel but the file descriptors are gone. These calls rebuild them from
the pins.

```go
// Node-wide maps first: per-pod programs are relocated against them.
globalMaps, err := sdkClient.RecoverGlobalMaps()
if err != nil {
	// Nothing usable was returned - recreate global state.
}

loadedPrograms, err := sdkClient.RecoverAllBpfProgramsAndMaps()
if errors.Is(err, goebpfelfparser.ErrPartialRecovery) {
	// loadedPrograms IS usable - see below.
	log.Printf("partial recovery: %v", err)
} else if err != nil {
	// Total failure, e.g. the BPF filesystem is not mounted.
}
```

The two calls deliberately behave differently on failure:

| Call | On failure |
|---|---|
| `RecoverGlobalMaps` | All-or-nothing. Returns either every map named in `Config.GlobalMaps`, or a nil map and an error. Every pod program binds to all of the global maps, so a subset is not a usable starting point. Any FDs it opened are closed before it returns. |
| `RecoverAllBpfProgramsAndMaps`, `GetAllBpfProgramsAndMaps` | Partial. A pin that cannot be read costs only the workload that owns it, so the walk continues and you get everything else back **together with** a non-nil error wrapping `ErrPartialRecovery`. |

That second row is the important one: **a non-nil error does not mean an empty
result.** Test `errors.Is(err, ErrPartialRecovery)` and proceed with the data
returned — treating any non-nil error as total failure turns one stray file
under the pin directory into a full reload of every workload on the node.

On a first start, before any pin exists, `RecoverGlobalMaps` returns an empty
set and a nil error — recovering nothing from nothing is not a failure.

## How to use tail calls (BPF_MAP_TYPE_PROG_ARRAY)?

Declare a `BPF_MAP_TYPE_PROG_ARRAY` map in your BPF C source and use
`bpf_tail_call()` as usual. The SDK handles map relocation like any other
map. Populating the prog array is done after loading, once target program
FDs are available.

### Example

```go
sdkClient, err := goebpfelfparser.New(goebpfelfparser.Config{})
if err != nil {
	panic(err)
}

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
