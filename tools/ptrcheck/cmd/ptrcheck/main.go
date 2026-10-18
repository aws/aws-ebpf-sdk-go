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

// Command ptrcheck runs the ptrcheck analyzer.
//
// Build it, then run it over the packages to check:
//
//	go build -o /tmp/ptrcheck ./cmd/ptrcheck
//	/tmp/ptrcheck ./pkg/...
//
// It exits non-zero when it reports a diagnostic, so it can be used directly as
// a CI gate. singlechecker is used rather than unitchecker because unitchecker
// expects to be driven by the go command's vet protocol, which supplies a
// pre-computed compilation unit and does not accept package patterns.
package main

import (
	"github.com/aws/aws-ebpf-sdk-go/tools/ptrcheck"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() {
	singlechecker.Main(ptrcheck.Analyzer)
}
