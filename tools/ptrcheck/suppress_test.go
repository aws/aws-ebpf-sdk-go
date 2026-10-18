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

package ptrcheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"golang.org/x/tools/go/analysis"
)

// TestSuppressedLinesIsPerFile checks that a //ptrcheck:ignore directive only
// silences the file it appears in. Keying suppression on the line number alone
// would let a directive in one file hide a real finding at the same line number
// in another, which is not something the analysistest fixtures can express
// without fragile line padding.
func TestSuppressedLinesIsPerFile(t *testing.T) {
	const withDirective = `package p

//ptrcheck:ignore justified
var a = 1
`
	// No directive here; line 3 must not be suppressed in this file.
	const withoutDirective = `package p

var b = 2
`

	fset := token.NewFileSet()
	f1, err := parser.ParseFile(fset, "with.go", withDirective, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse with.go: %v", err)
	}
	f2, err := parser.ParseFile(fset, "without.go", withoutDirective, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse without.go: %v", err)
	}

	pass := &analysis.Pass{Fset: fset, Files: []*ast.File{f1, f2}}
	suppressed := suppressedLines(pass)

	// The directive sits on line 3 of with.go and covers line 4 as well.
	for _, line := range []int{3, 4} {
		if !suppressed[fileLine{"with.go", line}] {
			t.Errorf("with.go line %d should be suppressed", line)
		}
	}

	// without.go has no directive, so the same line numbers must stay reportable.
	for _, line := range []int{3, 4} {
		if suppressed[fileLine{"without.go", line}] {
			t.Errorf("without.go line %d must not be suppressed by a directive in another file", line)
		}
	}
}
