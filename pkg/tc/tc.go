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
	"fmt"
	"strings"

	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	FILTER_CLEANUP_FAILED = "filter cleanup failed"
)

var log = logger.Get()

type BpfTc interface {
	TCIngressAttach(interfaceName string, progFD int, funcName string) error
	TCIngressDetach(interfaceName string) error
	TCEgressAttach(interfaceName string, progFD int, funcName string) error
	TCEgressDetach(interfaceName string) error
	CleanupQdiscs(ingressCleanup bool, egressCleanup bool) error
	mismatchedInterfacePrefix(interfaceName string) error
}

var _ BpfTc = &bpfTc{}

type bpfTc struct {
	InterfacePrefix string
}

func New(interfacePrefix string) BpfTc {
	return &bpfTc{
		InterfacePrefix: interfacePrefix,
	}

}

func enableQdisc(link netlink.Link) bool {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		log.Infof("Unable to check qdisc hence try installing")
		return true
	}

	qdiscHandle := netlink.MakeHandle(constdef.QDISC_HANDLE, 0)
	for _, qdisc := range qdiscs {
		attrs := qdisc.Attrs()
		if attrs.LinkIndex != link.Attrs().Index {
			continue
		}
		if (attrs.Handle&qdiscHandle) == qdiscHandle && attrs.Parent == netlink.HANDLE_CLSACT {
			log.Infof("Found qdisc hence don't install again")
			return false
		}
	}
	log.Infof("Qdisc is not enabled hence install")
	return true

}

func (m *bpfTc) mismatchedInterfacePrefix(interfaceName string) error {
	if !strings.HasPrefix(interfaceName, m.InterfacePrefix) {
		log.Errorf("expected prefix - %s but got %s", m.InterfacePrefix, interfaceName)
		return errors.New("Mismatched initialized prefix name and passed interface name")
	}
	return nil
}

func (m *bpfTc) TCIngressAttach(interfaceName string, progFD int, funcName string) error {

	if err := m.mismatchedInterfacePrefix(interfaceName); err != nil {
		return err
	}

	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Errorf("failed to find device by name %s: %w", interfaceName, err)
		return err
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index,
		Handle:    netlink.MakeHandle(constdef.QDISC_HANDLE, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	if enableQdisc(intf) {
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: attrs,
			QdiscType:  "clsact",
		}

		if err := netlink.QdiscAdd(qdisc); err != nil {
			log.Errorf("cannot add clsact qdisc: %v", err)
			return err
		}
	}

	// construct the filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: attrs.LinkIndex,
			Parent:    uint32(netlink.HANDLE_MIN_INGRESS),
			Handle:    constdef.DEFAULT_BPF_FILTER_HANDLE,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFD,
		Name:         funcName,
		DirectAction: true,
	}

	if err = netlink.FilterAdd(filter); err != nil {
		log.Errorf("while loading ingress program %q on fd %d: %v", "handle ingress", progFD, err)
		return err
	}
	log.Infof("TC ingress filter add done %s", interfaceName)
	return nil
}

func (m *bpfTc) TCIngressDetach(interfaceName string) error {

	if err := m.mismatchedInterfacePrefix(interfaceName); err != nil {
		return err
	}

	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Errorf("failed to find device by name %s: %w", interfaceName, err)
		return err
	}

	//Currently supports only one handle, in future we might need to cache the handle
	filterHandle := uint32(constdef.DEFAULT_BPF_FILTER_HANDLE)
	filterParent := uint32(netlink.HANDLE_MIN_INGRESS)

	filters, err := netlink.FilterList(intf, filterParent)
	if err != nil {
		log.Errorf("failed to get filter list: %v", err)
		return err
	}

	for _, filter := range filters {
		if filter.Attrs().Handle == filterHandle {
			err = netlink.FilterDel(filter)
			if err != nil {
				log.Errorf("delete filter failed on intf %s : %v", interfaceName, err)
				return errors.New(FILTER_CLEANUP_FAILED)
			}
			log.Infof("TC ingress filter detach done")
			return nil
		}
	}
	return fmt.Errorf("no active filter to detach-%s", interfaceName)
}

func (m *bpfTc) TCEgressAttach(interfaceName string, progFD int, funcName string) error {

	if err := m.mismatchedInterfacePrefix(interfaceName); err != nil {
		return err
	}

	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Errorf("failed to find device by name %s: %w", interfaceName, err)
		return err
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index,
		Handle:    netlink.MakeHandle(constdef.QDISC_HANDLE, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	if enableQdisc(intf) {
		qdisc := &netlink.GenericQdisc{
			QdiscAttrs: attrs,
			QdiscType:  "clsact",
		}

		if err := netlink.QdiscAdd(qdisc); err != nil {
			log.Errorf("cannot add clsact qdisc: %v", err)
			return err
		}
	}

	// construct the filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: attrs.LinkIndex,
			Parent:    uint32(netlink.HANDLE_MIN_EGRESS),
			Handle:    constdef.DEFAULT_BPF_FILTER_HANDLE,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           progFD,
		Name:         funcName,
		DirectAction: true,
	}

	if err = netlink.FilterAdd(filter); err != nil {
		log.Errorf("while loading egress program %q on fd %d: %v", "handle egress", progFD, err)
		return err
	}
	log.Infof("TC filter egress add done %s", interfaceName)
	return nil
}

func (m *bpfTc) TCEgressDetach(interfaceName string) error {

	if err := m.mismatchedInterfacePrefix(interfaceName); err != nil {
		return err
	}

	intf, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Errorf("failed to find device by name %s: %w", interfaceName, err)
		return err
	}

	//Currently supports only one handle, in future we might need to cache the handle
	filterHandle := uint32(0x1)
	filterParent := uint32(netlink.HANDLE_MIN_EGRESS)

	filters, err := netlink.FilterList(intf, filterParent)
	if err != nil {
		log.Errorf("failed to get filter list: %v", err)
		return err
	}

	for _, filter := range filters {
		if filter.Attrs().Handle == filterHandle {
			err = netlink.FilterDel(filter)
			if err != nil {
				log.Errorf("delete filter failed on intf %s : %v", interfaceName, err)
				return errors.New(FILTER_CLEANUP_FAILED)
			}
			log.Infof("TC egress filter detach done")
			return nil
		}
	}
	return fmt.Errorf("no active filter to detach-%s", interfaceName)
}

func (m *bpfTc) CleanupQdiscs(ingressCleanup bool, egressCleanup bool) error {

	if m.InterfacePrefix == "" {
		log.Errorf("invalid empty prefix")
		return nil
	}

	linkList, err := netlink.LinkList()
	if err != nil {
		log.Errorf("unable to get link list")
		return err
	}

	for _, link := range linkList {
		linkName := link.Attrs().Name
		if strings.HasPrefix(linkName, m.InterfacePrefix) {
			if ingressCleanup {
				log.Infof("Trying to cleanup ingress on %s", linkName)
				err = m.TCIngressDetach(linkName)
				if err != nil {
					if err.Error() == FILTER_CLEANUP_FAILED {
						log.Errorf("failed to detach ingress, might not be present so moving on")
					}
				}
			}

			if egressCleanup {
				log.Infof("Trying to cleanup egress on %s", linkName)
				err = m.TCEgressDetach(linkName)
				if err != nil {
					if err.Error() == FILTER_CLEANUP_FAILED {
						log.Errorf("failed to detach egress, might not be present so moving on")
					}
				}
			}
		}
	}
	return nil
}
