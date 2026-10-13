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

// Package btf reports whether the running kernel has the kfuncs a program
// calls, so callers can pick a program that loads before trying it.
package btf

import (
	internalbtf "github.com/aws/aws-ebpf-sdk-go/pkg/internal/btf"
)

// CheckKfuncs returns nil if the running kernel's BTF (vmlinux or a loaded
// module) defines every kfunc in names. Otherwise it returns an error, which
// names the missing kfunc or says why kernel BTF couldn't be read. It uses the same process-wide resolver as
// LoadBpfFile, so a successful check also caches the results that loading a
// program calling these kfuncs needs. Failed lookups are not cached, and each
// one walks the kernel's BTF again, so call it once (for example at startup)
// rather than before every load.
func CheckKfuncs(names []string) error {
	_, err := internalbtf.KernelKfuncResolver().ResolveKfuncs(names)
	return err
}
