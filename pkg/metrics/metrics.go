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
// limitations under the License.

// Package metrics exposes process-wide observability counters for the SDK.
//
// The counters are plain atomics rather than prometheus metrics so the SDK
// stays free of a metrics-library dependency. Consumers (e.g. the network
// policy agent) read them via the getters here and register them against their
// own prometheus registry (such as controller-runtime's).
package metrics

import "sync/atomic"

var (
	// progLoadEAGAINRetries counts individual BPF_PROG_LOAD attempts that
	// returned EAGAIN and were retried. A single load may contribute more than
	// one retry, so this is an attempt count, not a load count.
	progLoadEAGAINRetries atomic.Uint64
	// progLoadEAGAINExhausted counts BPF_PROG_LOAD calls that returned EAGAIN on
	// every attempt and were given up on — these are genuine enforcement gaps.
	progLoadEAGAINExhausted atomic.Uint64
	// mapMutateENOMEMRetries counts individual map mutation attempts that
	// returned ENOMEM and were retried, so this is an attempt count rather than
	// a mutation count.
	mapMutateENOMEMRetries atomic.Uint64
	// mapMutateENOMEMExhausted counts map mutations that returned ENOMEM on
	// every attempt and were given up on — these are genuine enforcement gaps.
	mapMutateENOMEMExhausted atomic.Uint64
)

// RecordProgLoadEAGAINRetry records one BPF_PROG_LOAD attempt that was retried
// after the verifier returned EAGAIN.
func RecordProgLoadEAGAINRetry() { progLoadEAGAINRetries.Add(1) }

// RecordProgLoadEAGAINExhausted records one BPF_PROG_LOAD call that exhausted
// all retry attempts on EAGAIN and failed.
func RecordProgLoadEAGAINExhausted() { progLoadEAGAINExhausted.Add(1) }

// ProgLoadEAGAINRetries returns the cumulative number of BPF_PROG_LOAD attempts
// retried after the verifier returned EAGAIN.
func ProgLoadEAGAINRetries() uint64 { return progLoadEAGAINRetries.Load() }

// ProgLoadEAGAINExhausted returns the cumulative number of BPF_PROG_LOAD calls
// that exhausted all retry attempts on EAGAIN and failed.
func ProgLoadEAGAINExhausted() uint64 { return progLoadEAGAINExhausted.Load() }

// RecordMapMutateENOMEMRetry records one map mutation attempt that was retried
// after the kernel returned ENOMEM.
func RecordMapMutateENOMEMRetry() { mapMutateENOMEMRetries.Add(1) }

// RecordMapMutateENOMEMExhausted records one map mutation that exhausted all
// retry attempts on ENOMEM and failed.
func RecordMapMutateENOMEMExhausted() { mapMutateENOMEMExhausted.Add(1) }

// MapMutateENOMEMRetries returns the cumulative number of map mutation attempts
// retried after the kernel returned ENOMEM.
func MapMutateENOMEMRetries() uint64 { return mapMutateENOMEMRetries.Load() }

// MapMutateENOMEMExhausted returns the cumulative number of map mutations that
// exhausted all retry attempts on ENOMEM and failed.
func MapMutateENOMEMExhausted() uint64 { return mapMutateENOMEMExhausted.Load() }
