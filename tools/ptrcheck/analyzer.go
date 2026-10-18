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

// Package ptrcheck provides a go/analysis pass that reports pointers converted
// to uintptr and then stored, instead of being converted inline in a syscall
// argument list.
//
// The Go runtime moves goroutine stacks (on growth, and on GC shrink) and
// rewrites only pointers it can see. A uintptr holding an object address is an
// integer as far as the runtime is concerned, so it is not rewritten and goes
// stale if the stack moves before the value reaches the kernel. The kernel then
// reads or writes freed memory, which surfaces as zeroed results or EFAULT /
// EINVAL rather than an obvious crash.
//
// The unsafe package documents this as rule (4): the uintptr conversion is only
// guaranteed safe when it appears in the argument list of a call to a function
// implemented in assembly, such as syscall.Syscall. Only then does the compiler
// keep the referenced object alive and unmoved for the duration of the call.
// Storing the uintptr in a struct field or local variable, or passing it to an
// ordinary Go function, loses that guarantee. Crossing a function boundary is
// especially risky because the callee's prologue is itself a stack-growth point.
//
// Safe, and not reported:
//
//	unix.Syscall(unix.SYS_BPF, op, uintptr(unsafe.Pointer(&attr)), size)
//
// Reported:
//
//	attr := bpfAttr{info: uintptr(unsafe.Pointer(&info))} // stored in a field
//	p := uintptr(unsafe.Pointer(&info))                   // stored in a variable
//	doWork(uintptr(unsafe.Pointer(&info)))                // passed to a Go func
//
// The usual remedy is to type the field or parameter as unsafe.Pointer so the
// runtime tracks it, and convert to uintptr only at the syscall call site.
package ptrcheck

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const doc = `check for pointers converted to uintptr and stored rather than used inline in a syscall

A uintptr is invisible to the garbage collector, so an object address held in one
goes stale when the runtime moves the goroutine stack. Converting to uintptr is
only safe inline in a syscall argument list, where the compiler pins the object
for the call. Type the field or parameter as unsafe.Pointer instead.`

// Analyzer reports uintptr(unsafe.Pointer(x)) conversions that are stored
// instead of being passed directly to a syscall.
var Analyzer = &analysis.Analyzer{
	Name:     "ptrcheck",
	Doc:      doc,
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      run,
}

// isTypeExpr reports whether e denotes a type rather than a value, which is what
// distinguishes a conversion from an ordinary call. TypesInfo.Types is populated
// either way, so only TypeAndValue.IsType separates them.
func isTypeExpr(pass *analysis.Pass, e ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[e]
	return ok && tv.IsType()
}

// isUintptrConversion reports whether e converts to uintptr, resolving the
// target through the type checker so that named and aliased uintptr types are
// recognised and a shadowed uintptr identifier is not.
func isUintptrConversion(pass *analysis.Pass, e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 || !isTypeExpr(pass, call.Fun) {
		return false
	}
	basic, ok := pass.TypesInfo.TypeOf(call.Fun).Underlying().(*types.Basic)
	return ok && basic.Kind() == types.Uintptr
}

// pointerOperand returns the operand of a conversion to uintptr whose argument
// is already an unsafe.Pointer, and whether e is such a conversion.
//
// The operand's type is resolved rather than its syntax, so this matches both
// the inline uintptr(unsafe.Pointer(&x)) form and the two-step form where the
// pointer arrives through a variable or a function result. Both lose the
// runtime's tracking in the same way.
func pointerOperand(pass *analysis.Pass, e ast.Expr) (ast.Expr, bool) {
	if !isUintptrConversion(pass, e) {
		return nil, false
	}
	arg := e.(*ast.CallExpr).Args[0]
	if !isUnsafePointerType(pass, arg) {
		return nil, false
	}
	return arg, true
}

// isUnsafePointerType reports whether e has type unsafe.Pointer.
func isUnsafePointerType(pass *analysis.Pass, e ast.Expr) bool {
	t := pass.TypesInfo.TypeOf(e)
	if t == nil {
		return false
	}
	basic, ok := t.Underlying().(*types.Basic)
	return ok && basic.Kind() == types.UnsafePointer
}

// isNilOperand reports whether e is an untyped nil, or a conversion of one, as
// in unsafe.Pointer(nil). Such a conversion carries no object address, so it
// cannot go stale.
func isNilOperand(pass *analysis.Pass, e ast.Expr) bool {
	if id, ok := e.(*ast.Ident); ok && id.Name == "nil" {
		return true
	}
	if call, ok := e.(*ast.CallExpr); ok && len(call.Args) == 1 && isTypeExpr(pass, call.Fun) {
		if id, ok := call.Args[0].(*ast.Ident); ok && id.Name == "nil" {
			return true
		}
	}
	return false
}

// isSyscallCall reports whether call targets a syscall entry point, where the
// compiler applies the unsafe.Pointer rule (4) exemption.
//
// The callee is resolved through the type checker and matched on its declaring
// package path, so an aliased import such as sys "golang.org/x/sys/unix" is
// recognised, while a method on a receiver merely named unix is not. Only the
// assembly-implemented wrappers in package syscall and its golang.org/x/sys
// mirror carry the compiler's keep-alive guarantee.
func isSyscallCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	fn, ok := pass.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	// A method has a receiver; the syscall wrappers are package-level functions.
	if fn.Type().(*types.Signature).Recv() != nil {
		return false
	}
	switch fn.Pkg().Path() {
	case "syscall", "golang.org/x/sys/unix":
	default:
		return false
	}
	name := fn.Name()
	return strings.HasPrefix(name, "Syscall") || strings.HasPrefix(name, "RawSyscall")
}

func run(pass *analysis.Pass) (interface{}, error) {
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	nodeTypes := []ast.Node{(*ast.CallExpr)(nil)}

	// First pass: record the conversions that are exempt.
	exempt := make(map[ast.Expr]bool)
	insp.Preorder(nodeTypes, func(n ast.Node) {
		call := n.(*ast.CallExpr)

		// Rule (4): the conversion appears in a syscall argument list. Arguments
		// are unwrapped through parentheses and arithmetic, because an offset
		// applied to the address is still passed straight to the kernel.
		if isSyscallCall(pass, call) {
			for _, arg := range call.Args {
				exemptSyscallArg(pass, arg, exempt)
			}
			return
		}

		// Rule (3): Pointer to uintptr, arithmetic, and back to Pointer, all in
		// one expression, as in unsafe.Pointer(uintptr(unsafe.Pointer(p)) + off).
		// The round trip keeps the result within the original object. Only the
		// conversions reached through arithmetic are exempt, so a conversion
		// nested inside an ordinary call is still reported.
		if isUnsafePointerType(pass, call) && len(call.Args) == 1 && isTypeExpr(pass, call.Fun) {
			exemptRoundTrip(pass, call.Args[0], exempt)
		}
	})

	suppressed := suppressedLines(pass)

	// Second pass: report every remaining conversion. Whatever is left is
	// stored in a field or variable, or handed to an ordinary Go function.
	insp.Preorder(nodeTypes, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		arg, ok := pointerOperand(pass, call)
		if !ok || exempt[call] || isNilOperand(pass, arg) {
			return
		}
		pos := pass.Fset.Position(call.Pos())
		if suppressed[fileLine{pos.Filename, pos.Line}] {
			return
		}
		pass.Reportf(call.Pos(),
			"pointer converted to uintptr and stored; the address is not tracked by the "+
				"runtime and goes stale if the goroutine stack moves. Type the field or "+
				"parameter as unsafe.Pointer, and convert to uintptr inline at the syscall call")
	})

	return nil, nil
}

// exemptSyscallArg exempts a conversion passed to a syscall, looking through
// parentheses and address arithmetic. The compiler's own keep-alive handling is
// narrower than this, but a conversion written in a syscall argument list is a
// deliberate rule (4) use and reporting it would only push contributors towards
// blanket suppression.
func exemptSyscallArg(pass *analysis.Pass, e ast.Expr, exempt map[ast.Expr]bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		exemptSyscallArg(pass, x.X, exempt)
	case *ast.BinaryExpr:
		exemptSyscallArg(pass, x.X, exempt)
		exemptSyscallArg(pass, x.Y, exempt)
	case *ast.CallExpr:
		if _, ok := pointerOperand(pass, x); ok {
			exempt[x] = true
		}
	}
}

// exemptRoundTrip exempts the conversion inside
// unsafe.Pointer(uintptr(ptr) +/- offset), reaching it only through arithmetic
// operators. A bare round trip with no arithmetic is not a rule (3) use and is
// left reportable.
func exemptRoundTrip(pass *analysis.Pass, e ast.Expr, exempt map[ast.Expr]bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		exemptRoundTrip(pass, x.X, exempt)
	case *ast.BinaryExpr:
		if x.Op == token.ADD || x.Op == token.SUB {
			exemptRoundTripOperand(pass, x.X, exempt)
			exemptRoundTripOperand(pass, x.Y, exempt)
		}
	}
}

// exemptRoundTripOperand exempts a conversion appearing as an operand of the
// arithmetic in a rule (3) round trip.
func exemptRoundTripOperand(pass *analysis.Pass, e ast.Expr, exempt map[ast.Expr]bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		exemptRoundTripOperand(pass, x.X, exempt)
	case *ast.BinaryExpr:
		if x.Op == token.ADD || x.Op == token.SUB {
			exemptRoundTripOperand(pass, x.X, exempt)
			exemptRoundTripOperand(pass, x.Y, exempt)
		}
	case *ast.CallExpr:
		if _, ok := pointerOperand(pass, x); ok {
			exempt[x] = true
		}
	}
}

// fileLine identifies a source line. The filename is part of the key so that a
// directive in one file cannot silence the same line number in another.
type fileLine struct {
	filename string
	line     int
}

// suppressedLines collects the lines silenced by a //ptrcheck:ignore comment.
//
// A directive on its own line annotates the line below it. A trailing directive
// annotates only the line it sits on, so it does not reach the next line: two
// conversions on consecutive lines each need their own justification.
//
// Suppression is line-granular, so a single directive covers every conversion on
// the annotated line. Two conversions written on one line therefore share one
// justification. Splitting them across lines restores per-conversion review.
//
// Suppression is for addresses handed to a struct defined outside this repository
// whose field type cannot be changed, where the object is instead kept alive with
// runtime.KeepAlive. Every use should say why in the same comment.
func suppressedLines(pass *analysis.Pass) map[fileLine]bool {
	suppressed := make(map[fileLine]bool)
	for _, f := range pass.Files {
		for _, group := range f.Comments {
			for _, c := range group.List {
				if !strings.Contains(c.Text, "ptrcheck:ignore") {
					continue
				}
				pos := pass.Fset.Position(c.Pos())
				suppressed[fileLine{pos.Filename, pos.Line}] = true
				if isOwnLineComment(pass, f, c) {
					suppressed[fileLine{pos.Filename, pos.Line + 1}] = true
				}
			}
		}
	}
	return suppressed
}

// isOwnLineComment reports whether c is the first token on its line, meaning it
// is a standalone directive that annotates the line below rather than a trailing
// one that annotates its own line.
//
// A comment is trailing when any node ends on the comment's line at or before
// its column. That covers a closing brace or paren of a multi-line construct as
// well as an ordinary trailing comment: in both cases code precedes the comment
// on that line, so it cannot be annotating the line below. The enclosing
// ast.File is skipped because it ends on the last line of the file rather than
// at any particular token.
func isOwnLineComment(pass *analysis.Pass, f *ast.File, c *ast.Comment) bool {
	cPos := pass.Fset.Position(c.Pos())
	ownLine := true
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil || !ownLine {
			return false
		}
		endPos := pass.Fset.Position(n.End())
		if endPos.Line == cPos.Line && endPos.Column <= cPos.Column {
			if _, isFile := n.(*ast.File); !isFile {
				ownLine = false
				return false
			}
		}
		return true
	})
	return ownLine
}
