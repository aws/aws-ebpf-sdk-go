package constants

type EBPFMapType uint32

// Currently synced with 5.10.188 - https://elixir.bootlin.com/linux/v5.10.188/source/include/uapi/linux/bpf.h
const (
	// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
	BPF_MAP_TYPE_UNSPEC EBPFMapType = iota
	BPF_MAP_TYPE_HASH
	BPF_MAP_TYPE_ARRAY
	BPF_MAP_TYPE_PROG_ARRAY
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	BPF_MAP_TYPE_PERCPU_HASH
	BPF_MAP_TYPE_PERCPU_ARRAY
	BPF_MAP_TYPE_STACK_TRACE
	BPF_MAP_TYPE_CGROUP_ARRAY
	BPF_MAP_TYPE_LRU_HASH
	BPF_MAP_TYPE_LRU_PERCPU_HASH
	BPF_MAP_TYPE_LPM_TRIE
	BPF_MAP_TYPE_ARRAY_OF_MAPS
	BPF_MAP_TYPE_HASH_OF_MAPS
	BPF_MAP_TYPE_DEVMAP
	BPF_MAP_TYPE_SOCKMAP
	BPF_MAP_TYPE_CPUMAP
	BPF_MAP_TYPE_XSKMAP
	BPF_MAP_TYPE_SOCKHASH
	BPF_MAP_TYPE_CGROUP_STORAGE
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	BPF_MAP_TYPE_QUEUE
	BPF_MAP_TYPE_STACK
	BPF_MAP_TYPE_SK_STORAGE
	BPF_MAP_TYPE_DEVMAP_HASH
	BPF_MAP_TYPE_STRUCT_OPS
	BPF_MAP_TYPE_RINGBUF
	BPF_MAP_TYPE_INODE_STORAGE
)

func (mapType EBPFMapType) Index() uint32 {
	return uint32(mapType)
}

type EBPFCmdType uint32

const (
	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	BPF_MAP_CREATE EBPFCmdType = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
)

type EBPFMapUpdateType uint32

const (
	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY EBPFMapUpdateType = iota
	BPF_NOEXIST
	BPF_EXIST
)

type EBPFPinType uint32

const (
	// BPF MAP pinning
	PIN_NONE EBPFPinType = iota
	PIN_OBJECT_NS
	PIN_GLOBAL_NS
	PIN_CUSTOM_NS
)

func (pinType EBPFPinType) Index() uint32 {
	return uint32(pinType)
}

const (
	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1

	BPF_DIR_MNT     = "/sys/fs/bpf/"
	BPF_DIR_GLOBALS = "globals"
	BPF_FS_MAGIC    = 0xcafe4a11

	BPFObjNameLen    = 16
	BPFProgInfoAlign = 8
	BPFTagSize       = 8

	/*
	 * C struct of bpf_ins is 8 bytes because of this -
	 * struct bpf_insn {
	 *	__u8	code;
	 * 	__u8	dst_reg:4;
	 *	__u8	src_reg:4;
	 * 	__s16	off;
	 * 	__s32	imm;
	 *	};
	 * while go struct will return 9 since we dont have bit fields hence we dec(1).
	 */
	PROG_BPF_FS = "/sys/fs/bpf/globals/aws/programs/"
	MAP_BPF_FS  = "/sys/fs/bpf/globals/aws/maps/"

	TRACEPOINT_EVENTS = "/sys/kernel/debug/tracing/events"

	KPROBE_SYS_EVENTS   = "/sys/kernel/debug/tracing/kprobe_events"
	KPROBE_SYS_DEBUG    = "/sys/kernel/debug/tracing/events/kprobes"
	KRETPROBE_SYS_DEBUG = "/sys/kernel/debug/tracing/events/kretprobes"

	QDISC_HANDLE              = 0xffff
	DEFAULT_BPF_FILTER_HANDLE = 0x1
)

type XDPattachType int

const (
	XDP_ATTACH_MODE_NONE = 1 << iota
	XDP_ATTACH_MODE_SKB
	XDP_ATTACH_MODE_DRV
	XDP_ATTACH_MODE_HW
)
