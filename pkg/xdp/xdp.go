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

package xdp

import (
	constdef "github.com/aws/aws-ebpf-sdk-go/pkg/constants"
	"github.com/aws/aws-ebpf-sdk-go/pkg/logger"
	"github.com/vishvananda/netlink"
)

var log = logger.Get()

func XDPAttach(interfaceName string, progFD int) error {

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Errorf("failed linkbyname: %v", err)
		return err
	}

	log.Infof("Attaching xdp to interface %s and prog %d", interfaceName, progFD)

	if err := netlink.LinkSetXdpFdWithFlags(link, progFD, constdef.XDP_ATTACH_MODE_SKB); err != nil {
		log.Errorf("failed to setxdp: %v", err)
		return err
	}
	log.Infof("Attached XDP to interface %s", interfaceName)

	return nil
}

func XDPDetach(interfaceName string) error {

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		log.Errorf("failed linkbyname: %v", err)
		return err
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, -1, constdef.XDP_ATTACH_MODE_SKB); err != nil {
		log.Errorf("failed to setxdp: %v", err)
		return err
	}
	return nil
}
