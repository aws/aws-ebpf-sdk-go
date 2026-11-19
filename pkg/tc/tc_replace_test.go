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

package tc

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/progs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	tcActOK   = 0
	tcActShot = 2
	// IEEE 802 local experimental ethertype, so the test frames are not
	// handled by anything else on the link.
	testEtherType = 0x88b5
)

var (
	ingressHook = uint32(netlink.HANDLE_MIN_INGRESS)
	egressHook  = uint32(netlink.HANDLE_MIN_EGRESS)
)

func requireRoot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Test requires root privileges.")
	}
}

// loadRetProg loads "r0 = ret; exit" as a new sched_cls program and returns
// its fd and ID.
func loadRetProg(t *testing.T, ret uint32) (int, int) {
	insns := []uint64{
		0x00000000000000b7 | (uint64(ret) << 32), // mov r0, ret
		0x0000000000000095,                       // exit
	}
	license := []byte("GPL\x00")
	attr := netlink.BPFAttr{
		ProgType: uint32(netlink.BPF_PROG_TYPE_SCHED_CLS),
		InsnCnt:  uint32(len(insns)),
		Insns:    uintptr(unsafe.Pointer(&insns[0])),
		License:  uintptr(unsafe.Pointer(&license[0])),
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(constdef.BPF_PROG_LOAD),
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	runtime.KeepAlive(insns)
	runtime.KeepAlive(license)
	require.Zero(t, errno, "BPF_PROG_LOAD")
	t.Cleanup(func() { unix.Close(int(fd)) })

	info, err := progs.GetBPFprogInfo(int(fd))
	require.NoError(t, err)
	return int(fd), int(info.ID)
}

func filtersAtHandle(t *testing.T, link netlink.Link, hook uint32) []*netlink.BpfFilter {
	filters, err := netlink.FilterList(link, hook)
	require.NoError(t, err)
	var out []*netlink.BpfFilter
	for _, f := range filters {
		if bpf, ok := f.(*netlink.BpfFilter); ok && f.Attrs().Handle == uint32(constdef.DEFAULT_BPF_FILTER_HANDLE) {
			out = append(out, bpf)
		}
	}
	return out
}

func linkByName(t *testing.T, name string) netlink.Link {
	link, err := netlink.LinkByName(name)
	require.NoError(t, err)
	return link
}

type tcSetter func(BpfTc, string, int, string) error

var (
	ingressAttach  tcSetter = func(c BpfTc, i string, fd int, n string) error { return c.TCIngressAttach(i, fd, n) }
	ingressReplace tcSetter = func(c BpfTc, i string, fd int, n string) error { return c.TCIngressReplace(i, fd, n) }
	egressAttach   tcSetter = func(c BpfTc, i string, fd int, n string) error { return c.TCEgressAttach(i, fd, n) }
	egressReplace  tcSetter = func(c BpfTc, i string, fd int, n string) error { return c.TCEgressReplace(i, fd, n) }
)

var replaceHooks = []struct {
	name    string
	hook    uint32
	attach  tcSetter
	replace tcSetter
}{
	{"host ingress hook", ingressHook, ingressAttach, ingressReplace},
	{"host egress hook", egressHook, egressAttach, egressReplace},
}

// Replace with no filter on the hook creates it, the same filter attach
// would create, and does not touch the other hook.
func TestTCReplaceCreatesFilter(t *testing.T) {
	requireRoot(t)
	for _, h := range replaceHooks {
		t.Run(h.name, func(t *testing.T) {
			setupTest([]string{"eni1"}, t)
			defer teardownTest([]string{"eni1"}, t)
			client := New([]string{"eni"})
			fd, id := loadRetProg(t, tcActOK)

			require.NoError(t, h.replace(client, "eni1", fd, DUMMY_PROG_NAME))

			link := linkByName(t, "eni1")
			got := filtersAtHandle(t, link, h.hook)
			require.Len(t, got, 1)
			assert.Equal(t, id, int(got[0].Id))
			assert.Equal(t, uint16(unix.ETH_P_ALL), got[0].Protocol)
			assert.Equal(t, uint16(1), got[0].Priority)
			assert.True(t, got[0].DirectAction)

			other := egressHook
			if h.hook == egressHook {
				other = ingressHook
			}
			assert.Empty(t, filtersAtHandle(t, link, other), "replace must only touch its own hook")
		})
	}
}

// Replace swaps the program of an existing filter, where attach fails with
// EEXIST.
func TestTCReplaceSwapsProgram(t *testing.T) {
	requireRoot(t)
	for _, h := range replaceHooks {
		t.Run(h.name, func(t *testing.T) {
			setupTest([]string{"eni1"}, t)
			defer teardownTest([]string{"eni1"}, t)
			client := New([]string{"eni"})
			fdA, idA := loadRetProg(t, tcActOK)
			fdB, idB := loadRetProg(t, tcActOK)
			require.NotEqual(t, idA, idB)

			require.NoError(t, h.attach(client, "eni1", fdA, DUMMY_PROG_NAME))
			err := h.attach(client, "eni1", fdB, DUMMY_PROG_NAME)
			assert.True(t, errors.Is(err, unix.EEXIST), "attach over an attached filter: got %v", err)

			require.NoError(t, h.replace(client, "eni1", fdB, DUMMY_PROG_NAME))
			link := linkByName(t, "eni1")
			got := filtersAtHandle(t, link, h.hook)
			require.Len(t, got, 1)
			assert.Equal(t, idB, int(got[0].Id))

			// GetAllAttachedProgIds reads the hook through the pod direction.
			podIngress, podEgress, err := client.GetAllAttachedProgIds()
			require.NoError(t, err)
			if h.hook == egressHook {
				assert.Equal(t, idB, podIngress["eni1"])
			} else {
				assert.Equal(t, idB, podEgress["eni1"])
			}

			// Replacing with the program already attached is a no-op.
			require.NoError(t, h.replace(client, "eni1", fdB, DUMMY_PROG_NAME))
			got = filtersAtHandle(t, link, h.hook)
			require.Len(t, got, 1)
			assert.Equal(t, idB, int(got[0].Id))
		})
	}
}

// Replace works when clsact was installed by someone else first.
func TestTCReplaceExistingClsact(t *testing.T) {
	requireRoot(t)
	setupTest([]string{"eni1"}, t)
	defer teardownTest([]string{"eni1"}, t)
	client := New([]string{"eni"})
	link := linkByName(t, "eni1")
	require.NoError(t, netlink.QdiscAdd(&netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(constdef.QDISC_HANDLE, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}))
	fd, id := loadRetProg(t, tcActOK)
	require.NoError(t, client.TCIngressReplace("eni1", fd, DUMMY_PROG_NAME))
	require.NoError(t, client.TCEgressReplace("eni1", fd, DUMMY_PROG_NAME))
	assert.Equal(t, id, int(filtersAtHandle(t, link, ingressHook)[0].Id))
	assert.Equal(t, id, int(filtersAtHandle(t, link, egressHook)[0].Id))
}

// clsactAttrs are the attributes of the SDK's clsact qdisc on link.
func clsactAttrs(link netlink.Link) netlink.QdiscAttrs {
	return netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(constdef.QDISC_HANDLE, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
}

// missFirstList makes client's next qdisc list return nothing, as when
// another TC user adds a qdisc right after the SDK lists.
func missFirstList(client BpfTc) {
	missed := false
	client.(*bpfTc).qdiscList = func(link netlink.Link) ([]netlink.Qdisc, error) {
		if !missed {
			missed = true
			return nil, nil
		}
		return netlink.QdiscList(link)
	}
}

// clsact another TC user added between the list and the add is fine: both
// hooks still get their filter.
func TestTCReplaceClsactAddedDuringAttach(t *testing.T) {
	requireRoot(t)
	setupTest([]string{"eni1"}, t)
	defer teardownTest([]string{"eni1"}, t)
	client := New([]string{"eni"})
	link := linkByName(t, "eni1")
	require.NoError(t, netlink.QdiscAdd(&netlink.GenericQdisc{QdiscAttrs: clsactAttrs(link), QdiscType: "clsact"}))
	fd, id := loadRetProg(t, tcActOK)
	for _, h := range replaceHooks {
		missFirstList(client)
		require.NoError(t, h.replace(client, "eni1", fd, DUMMY_PROG_NAME))
		got := filtersAtHandle(t, link, h.hook)
		require.Len(t, got, 1, h.name)
		assert.Equal(t, id, int(got[0].Id))
	}
}

// An ingress qdisc in clsact's place, present or added during the attach,
// doesn't fail the call, as before replace existed. Both hooks share its one
// filter block, so the second replace swaps the first one's program.
func TestTCReplaceOnIngressQdisc(t *testing.T) {
	requireRoot(t)
	for _, race := range []bool{false, true} {
		name := "present"
		if race {
			name = "added during the attach"
		}
		t.Run(name, func(t *testing.T) {
			setupTest([]string{"eni1"}, t)
			defer teardownTest([]string{"eni1"}, t)
			client := New([]string{"eni"})
			link := linkByName(t, "eni1")
			require.NoError(t, netlink.QdiscAdd(&netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_INGRESS}}))
			var lastID int
			for _, h := range replaceHooks {
				fd, id := loadRetProg(t, tcActOK)
				if race {
					missFirstList(client)
				}
				require.NoError(t, h.replace(client, "eni1", fd, DUMMY_PROG_NAME))
				lastID = id
			}
			got := filtersAtHandle(t, link, ingressHook)
			require.Len(t, got, 1)
			assert.Equal(t, lastID, int(got[0].Id))
		})
	}
}

// With an ingress qdisc and a u32 filter at priority 1, as the CNI bandwidth
// plugin sets up, replace fails with EINVAL and leaves the u32 filter alone.
func TestTCReplaceOnBandwidthPluginQdisc(t *testing.T) {
	requireRoot(t)
	setupTest([]string{"eni1"}, t)
	defer teardownTest([]string{"eni1"}, t)
	client := New([]string{"eni"})
	link := linkByName(t, "eni1")
	require.NoError(t, netlink.QdiscAdd(&netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.HANDLE_INGRESS}}))
	require.NoError(t, netlink.FilterAdd(&netlink.U32{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0), Priority: 1, Protocol: unix.ETH_P_ALL}, ClassId: netlink.MakeHandle(1, 1)}))
	fd, _ := loadRetProg(t, tcActOK)
	for _, h := range replaceHooks {
		err := h.replace(client, "eni1", fd, DUMMY_PROG_NAME)
		assert.True(t, errors.Is(err, unix.EINVAL), "%s: got %v", h.name, err)
	}
	filters, err := netlink.FilterList(link, netlink.MakeHandle(0xffff, 0))
	require.NoError(t, err)
	require.Len(t, filters, 1)
	assert.Equal(t, "u32", filters[0].Type())
}

// When the qdisc list keeps failing, the SDK still adds clsact if it is
// missing. If clsact is there, the add's EEXIST can't be confirmed, so the call
// fails and the existing filter stays.
func TestTCReplaceQdiscListFails(t *testing.T) {
	requireRoot(t)
	failList := func(client BpfTc) {
		client.(*bpfTc).qdiscList = func(netlink.Link) ([]netlink.Qdisc, error) { return nil, errors.New("list failed") }
	}
	t.Run("no qdisc", func(t *testing.T) {
		setupTest([]string{"eni1"}, t)
		defer teardownTest([]string{"eni1"}, t)
		client := New([]string{"eni"})
		fd, id := loadRetProg(t, tcActOK)
		failList(client)
		require.NoError(t, client.TCIngressReplace("eni1", fd, DUMMY_PROG_NAME))
		got := filtersAtHandle(t, linkByName(t, "eni1"), ingressHook)
		require.Len(t, got, 1)
		assert.Equal(t, id, int(got[0].Id))
	})
	t.Run("clsact and filter present", func(t *testing.T) {
		setupTest([]string{"eni1"}, t)
		defer teardownTest([]string{"eni1"}, t)
		client := New([]string{"eni"})
		fdA, idA := loadRetProg(t, tcActOK)
		fdB, _ := loadRetProg(t, tcActOK)
		require.NoError(t, client.TCIngressReplace("eni1", fdA, DUMMY_PROG_NAME))
		failList(client)
		err := client.TCIngressReplace("eni1", fdB, DUMMY_PROG_NAME)
		assert.True(t, errors.Is(err, unix.EEXIST), "got %v", err)
		got := filtersAtHandle(t, linkByName(t, "eni1"), ingressHook)
		require.Len(t, got, 1)
		assert.Equal(t, idA, int(got[0].Id))
	})
}

func TestTCReplaceErrors(t *testing.T) {
	requireRoot(t)
	setupTest([]string{"eni1"}, t)
	defer teardownTest([]string{"eni1"}, t)
	client := New([]string{"eni"})
	fd, _ := loadRetProg(t, tcActOK)
	for _, h := range replaceHooks {
		t.Run(h.name, func(t *testing.T) {
			err := h.replace(client, "eni404", fd, DUMMY_PROG_NAME)
			assert.EqualError(t, err, "Link not found")

			err = h.replace(client, "veth1", fd, DUMMY_PROG_NAME)
			assert.EqualError(t, err, "Mismatched initialized prefix name and passed interface name")

			// An fd that is not a BPF program is rejected and leaves no filter.
			r, w, err := os.Pipe()
			require.NoError(t, err)
			defer r.Close()
			defer w.Close()
			notProg := int(r.Fd())
			assert.Error(t, h.replace(client, "eni1", notProg, DUMMY_PROG_NAME))
			assert.Empty(t, filtersAtHandle(t, linkByName(t, "eni1"), h.hook))

			// A failed replace keeps the filter that was there.
			fdA, idA := loadRetProg(t, tcActOK)
			require.NoError(t, h.attach(client, "eni1", fdA, DUMMY_PROG_NAME))
			assert.Error(t, h.replace(client, "eni1", notProg, DUMMY_PROG_NAME))
			got := filtersAtHandle(t, linkByName(t, "eni1"), h.hook)
			require.Len(t, got, 1)
			assert.Equal(t, idA, int(got[0].Id))
		})
	}
}

// Another TC user's filter on the same hook. The SDK's filter is the tuple
// (handle 1, priority 1, ETH_P_ALL); replace only ever addresses that tuple.
func TestTCReplaceForeignFilter(t *testing.T) {
	requireRoot(t)
	foreign := func(link netlink.Link, prio uint16, proto uint16, handle uint32, fd int) *netlink.BpfFilter {
		return &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    ingressHook,
				Handle:    handle,
				Protocol:  proto,
				Priority:  prio,
			},
			Fd:           fd,
			Name:         "foreign",
			DirectAction: true,
		}
	}

	// A filter at another priority is left alone; ours is created next to it.
	t.Run("other priority", func(t *testing.T) {
		setupTest([]string{"eni1"}, t)
		defer teardownTest([]string{"eni1"}, t)
		client := New([]string{"eni"})
		fdF, idF := loadRetProg(t, tcActOK)
		fd, id := loadRetProg(t, tcActOK)
		require.NoError(t, client.TCIngressAttach("eni1", fdF, DUMMY_PROG_NAME)) // adds clsact
		require.NoError(t, client.TCIngressDetach("eni1"))
		link := linkByName(t, "eni1")
		require.NoError(t, netlink.FilterAdd(foreign(link, 2, unix.ETH_P_ALL, 1, fdF)))

		require.NoError(t, client.TCIngressReplace("eni1", fd, DUMMY_PROG_NAME))
		ids := map[uint16]int{}
		for _, f := range filtersAtHandle(t, link, ingressHook) {
			ids[f.Priority] = int(f.Id)
		}
		assert.Equal(t, map[uint16]int{1: id, 2: idF}, ids)
	})

	// Priority 1 already holds a filter of another protocol. The kernel
	// rejects a second protocol at one priority, so replace fails with
	// EINVAL, the same way attach does, and the foreign filter is kept.
	t.Run("same priority other protocol", func(t *testing.T) {
		setupTest([]string{"eni1"}, t)
		defer teardownTest([]string{"eni1"}, t)
		client := New([]string{"eni"})
		fdF, idF := loadRetProg(t, tcActOK)
		fd, _ := loadRetProg(t, tcActOK)
		require.NoError(t, client.TCIngressAttach("eni1", fdF, DUMMY_PROG_NAME))
		require.NoError(t, client.TCIngressDetach("eni1"))
		link := linkByName(t, "eni1")
		require.NoError(t, netlink.FilterAdd(foreign(link, 1, unix.ETH_P_IP, 1, fdF)))

		err := client.TCIngressReplace("eni1", fd, DUMMY_PROG_NAME)
		assert.True(t, errors.Is(err, unix.EINVAL), "replace: got %v", err)
		err = client.TCIngressAttach("eni1", fd, DUMMY_PROG_NAME)
		assert.True(t, errors.Is(err, unix.EINVAL), "attach: got %v", err)
		got := filtersAtHandle(t, link, ingressHook)
		require.Len(t, got, 1)
		assert.Equal(t, idF, int(got[0].Id))
		assert.Equal(t, uint16(unix.ETH_P_IP), got[0].Protocol)
	})

	// Same priority and protocol, other handle: ours is added to the same
	// classifier next to it and the foreign filter is kept.
	t.Run("same priority and protocol other handle", func(t *testing.T) {
		setupTest([]string{"eni1"}, t)
		defer teardownTest([]string{"eni1"}, t)
		client := New([]string{"eni"})
		fdF, idF := loadRetProg(t, tcActOK)
		fd, id := loadRetProg(t, tcActOK)
		require.NoError(t, client.TCIngressAttach("eni1", fdF, DUMMY_PROG_NAME))
		require.NoError(t, client.TCIngressDetach("eni1"))
		link := linkByName(t, "eni1")
		require.NoError(t, netlink.FilterAdd(foreign(link, 1, unix.ETH_P_ALL, 2, fdF)))

		require.NoError(t, client.TCIngressReplace("eni1", fd, DUMMY_PROG_NAME))
		filters, err := netlink.FilterList(link, ingressHook)
		require.NoError(t, err)
		ids := map[uint32]int{}
		for _, f := range filters {
			if bpf, ok := f.(*netlink.BpfFilter); ok {
				ids[f.Attrs().Handle] = int(bpf.Id)
			}
		}
		assert.Equal(t, map[uint32]int{1: id, 2: idF}, ids)
	})

	// A filter at exactly our tuple cannot be told apart from ours: replace
	// swaps its program, where attach fails with EEXIST.
	t.Run("same tuple", func(t *testing.T) {
		setupTest([]string{"eni1"}, t)
		defer teardownTest([]string{"eni1"}, t)
		client := New([]string{"eni"})
		fdF, _ := loadRetProg(t, tcActOK)
		fd, id := loadRetProg(t, tcActOK)
		require.NoError(t, client.TCIngressAttach("eni1", fdF, DUMMY_PROG_NAME))
		require.NoError(t, client.TCIngressDetach("eni1"))
		link := linkByName(t, "eni1")
		require.NoError(t, netlink.FilterAdd(foreign(link, 1, unix.ETH_P_ALL, 1, fdF)))

		err := client.TCIngressAttach("eni1", fd, DUMMY_PROG_NAME)
		assert.True(t, errors.Is(err, unix.EEXIST), "attach: got %v", err)
		require.NoError(t, client.TCIngressReplace("eni1", fd, DUMMY_PROG_NAME))
		got := filtersAtHandle(t, link, ingressHook)
		require.Len(t, got, 1)
		assert.Equal(t, id, int(got[0].Id))
	})
}

// swapLoop alternates the hook between two programs up to n times, with
// replace or with detach + attach, until stop returns true.
func swapLoop(t *testing.T, client BpfTc, iface string, hook uint32, fds [2]int, n int, useReplace bool, stop func() bool) {
	replace, attach, detach := client.TCIngressReplace, client.TCIngressAttach, client.TCIngressDetach
	if hook == egressHook {
		replace, attach, detach = client.TCEgressReplace, client.TCEgressAttach, client.TCEgressDetach
	}
	for i := 0; i < n && !stop(); i++ {
		fd := fds[i%2]
		if useReplace {
			require.NoError(t, replace(iface, fd, DUMMY_PROG_NAME))
			continue
		}
		require.NoError(t, detach(iface))
		require.NoError(t, attach(iface, fd, DUMMY_PROG_NAME))
	}
}

// A filter dump in a tight loop must always see exactly one filter while
// the program is swapped. The detach + attach control shows the dump can see
// a gap.
func TestTCReplaceNoGapInFilterDump(t *testing.T) {
	requireRoot(t)
	const swaps = 500
	for _, h := range replaceHooks {
		for _, useReplace := range []bool{true, false} {
			name := h.name + "/replace"
			if !useReplace {
				name = h.name + "/detach+attach control"
			}
			t.Run(name, func(t *testing.T) {
				setupTest([]string{"eni1"}, t)
				defer teardownTest([]string{"eni1"}, t)
				client := New([]string{"eni"})
				fdA, idA := loadRetProg(t, tcActOK)
				fdB, idB := loadRetProg(t, tcActOK)
				require.NoError(t, h.attach(client, "eni1", fdA, DUMMY_PROG_NAME))
				link := linkByName(t, "eni1")

				var stop atomic.Bool
				var dumps, empty, other atomic.Int64
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					for !stop.Load() {
						filters, err := netlink.FilterList(link, h.hook)
						if err != nil {
							continue
						}
						dumps.Add(1)
						n := 0
						for _, f := range filters {
							bpf, ok := f.(*netlink.BpfFilter)
							if !ok || f.Attrs().Handle != uint32(constdef.DEFAULT_BPF_FILTER_HANDLE) {
								continue
							}
							n++
							if id := int(bpf.Id); id != idA && id != idB {
								other.Add(1)
							}
						}
						if n != 1 {
							empty.Add(1)
						}
					}
				}()
				// Stop the dump even if swapLoop fails the test.
				defer func() { stop.Store(true); wg.Wait() }()
				swapLoop(t, client, "eni1", h.hook, [2]int{fdA, fdB}, swaps, useReplace, func() bool { return !useReplace && empty.Load() > 0 })
				stop.Store(true)
				wg.Wait()

				t.Logf("%d dumps, %d without exactly one filter", dumps.Load(), empty.Load())
				require.Greater(t, dumps.Load(), int64(0))
				assert.Zero(t, other.Load(), "dump saw a program that was never attached")
				if useReplace {
					assert.Zero(t, empty.Load(), "replace left the hook without our filter")
				} else {
					assert.Greater(t, empty.Load(), int64(0), "the dump never saw the detach gap, so it can't detect one")
				}
			})
		}
	}
}

// setupVethPair creates tx <-> rx in the current netns, both up.
func setupVethPair(t *testing.T, tx, rx string) {
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: tx}, PeerName: rx}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { netlink.LinkDel(veth) })
	require.NoError(t, netlink.LinkSetUp(linkByName(t, tx)))
	require.NoError(t, netlink.LinkSetUp(linkByName(t, rx)))
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func packetSocket(t *testing.T, ifindex int, proto uint16) int {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(proto)))
	require.NoError(t, err)
	t.Cleanup(func() { unix.Close(fd) })
	require.NoError(t, unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(proto), Ifindex: ifindex}))
	return fd
}

// countFrames sends test frames out of tx as fast as it can while fn runs,
// and returns how many sends were attempted and how many frames reached rx.
// A frame a TC program drops makes its send fail, so failures are counted too.
func countFrames(t *testing.T, tx, rx string, fn func(received func() int64)) (sent, received int64) {
	txIdx, rxIdx := linkByName(t, tx).Attrs().Index, linkByName(t, rx).Attrs().Index
	sendFd := packetSocket(t, txIdx, 0)
	recvFd := packetSocket(t, rxIdx, testEtherType)
	require.NoError(t, unix.SetsockoptTimeval(recvFd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}))

	frame := make([]byte, 64)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x02, 0, 0, 0, 0, 1})
	frame[12], frame[13] = testEtherType>>8, testEtherType&0xff
	to := &unix.SockaddrLinklayer{Ifindex: txIdx, Halen: 6, Addr: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}

	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = unix.Sendto(sendFd, frame, 0, to)
			atomic.AddInt64(&sent, 1)
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for {
			if _, _, err := unix.Recvfrom(recvFd, buf, 0); err == nil {
				atomic.AddInt64(&received, 1)
			} else if stop.Load() {
				return
			}
		}
	}()
	// Stop the goroutines even if fn fails the test.
	defer func() { stop.Store(true); wg.Wait() }()
	fn(func() int64 { return atomic.LoadInt64(&received) })
	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	return sent, received
}

// No frame may get past a drop program on tx's host egress hook while it is
// replaced. The detach + attach control shows frames getting through.
func TestTCReplaceNoTrafficGap(t *testing.T) {
	requireRoot(t)
	const swaps = 500
	tx, rx := "eni1", "vethrx1"

	t.Run("setup passes traffic without a filter", func(t *testing.T) {
		setupVethPair(t, tx, rx)
		sent, received := countFrames(t, tx, rx, func(func() int64) { time.Sleep(100 * time.Millisecond) })
		t.Logf("sent %d, received %d", sent, received)
		require.Greater(t, sent, int64(0))
		require.Greater(t, received, int64(0))
	})

	for _, useReplace := range []bool{true, false} {
		name := "replace"
		if !useReplace {
			name = "detach+attach control"
		}
		t.Run(name, func(t *testing.T) {
			setupVethPair(t, tx, rx)
			client := New([]string{"eni"})
			fdA, _ := loadRetProg(t, tcActShot)
			fdB, _ := loadRetProg(t, tcActShot)
			require.NoError(t, client.TCEgressAttach(tx, fdA, DUMMY_PROG_NAME))

			sent, received := countFrames(t, tx, rx, func(received func() int64) {
				swapLoop(t, client, tx, egressHook, [2]int{fdA, fdB}, swaps, useReplace,
					func() bool { return !useReplace && received() > 0 })
			})
			t.Logf("sent %d, received %d", sent, received)
			require.Greater(t, sent, int64(0))
			if useReplace {
				assert.Zero(t, received, "a frame got past the hook while its program was replaced")
			} else {
				assert.Greater(t, received, int64(0), "no frame got through the detach gap, so the test can't detect one")
			}
		})
	}
}
