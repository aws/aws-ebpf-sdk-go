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

// Package a holds fixtures for the ptrcheck analyzer test. Lines that should be
// reported carry a "want" comment; every other line must stay silent.
package a

import (
	"syscall"
	"unsafe"

	sys "golang.org/x/sys/unix"
)

type info struct {
	n uint32
}

// attrTwo has two adjacent uintptr fields, for the suppression adjacency case.
type attrTwo struct {
	x uintptr
	y uintptr
}

// namedAddr and aliasAddr are uintptr under a different spelling.
type namedAddr uintptr

type aliasAddr = uintptr

var (
	sinkNamed   namedAddr
	sinkAliased aliasAddr
	sinkPlain   uintptr
)

// fakeSys has a Syscall method but carries none of the compiler's guarantees.
type fakeSys struct{}

func (fakeSys) Syscall(a, b, c uintptr) {}

// unix shadows nothing real; it exists so a method call can look like a syscall.
var unix fakeSys

// attrUintptr models the unsafe shape: a kernel-facing struct that holds the
// userspace address as a raw integer.
type attrUintptr struct {
	fd   uint32
	_    uint32
	info uintptr
}

// attrPointer models the safe shape, with the address kept in a tracked pointer.
type attrPointer struct {
	fd   uint32
	_    uint32
	info unsafe.Pointer
}

func takesUintptr(p uintptr)              {}
func takesTwoUintptr(a, b uintptr)        {}
func takesPointer(p unsafe.Pointer)       {}
func syscallWrapper(a *attrUintptr) error { return nil }

// storedInStructField is the shape that caused zeroed BPF prog info: the address
// is frozen into a field before the syscall runs.
func storedInStructField() {
	var i info
	a := attrUintptr{
		info: uintptr(unsafe.Pointer(&i)), // want `pointer converted to uintptr and stored`
	}
	_ = syscallWrapper(&a)
}

// storedInLocalVariable holds the address in a local across a call boundary.
func storedInLocalVariable() {
	var i info
	p := uintptr(unsafe.Pointer(&i)) // want `pointer converted to uintptr and stored`
	takesUintptr(p)
}

// passedToGoFunction converts inline, but the callee is ordinary Go code, so the
// rule (4) exemption does not apply and the callee prologue may move the stack.
func passedToGoFunction() {
	var i info
	takesUintptr(uintptr(unsafe.Pointer(&i))) // want `pointer converted to uintptr and stored`
}

// storedInSlice keeps addresses well past the point they can be trusted.
func storedInSlice() {
	var i info
	ptrs := []uintptr{
		uintptr(unsafe.Pointer(&i)), // want `pointer converted to uintptr and stored`
	}
	_ = ptrs
}

// inlineSyscall is the documented safe form: the conversion sits in the argument
// list of an assembly-implemented function.
func inlineSyscall() {
	var i info
	syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(0),
		uintptr(unsafe.Pointer(&i)),
		unsafe.Sizeof(i),
	)
}

// inlineSyscall6 covers the numbered syscall variants.
func inlineSyscall6() {
	var i info
	syscall.Syscall6(
		syscall.SYS_IOCTL,
		uintptr(0),
		uintptr(unsafe.Pointer(&i)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
}

// inlineRawSyscall covers the raw variants.
func inlineRawSyscall() {
	var i info
	syscall.RawSyscall(
		syscall.SYS_IOCTL,
		uintptr(0),
		uintptr(unsafe.Pointer(&i)),
		unsafe.Sizeof(i),
	)
}

// nilPointer carries no object address, so it cannot go stale.
func nilPointer() {
	takesUintptr(uintptr(unsafe.Pointer(nil)))
}

// pointerArithmetic is the documented rule (3) form: Pointer to uintptr, offset,
// and back to Pointer in a single expression. The result stays inside the
// original object, so the round trip is safe.
func pointerArithmetic() {
	buf := make([]byte, 64)
	p := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(8))
	takesPointer(p)
}

// pointerArithmeticAssignedToField covers the same round trip when the result is
// stored, which is how the ring buffer walks its pages.
func pointerArithmeticAssignedToField() {
	buf := make([]byte, 64)
	a := attrPointer{
		info: unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(16)),
	}
	takesPointer(a.info)
}

// trackedPointer is the remedy: keep the address in an unsafe.Pointer so the
// runtime rewrites it when the stack moves.
func trackedPointer() {
	var i info
	a := attrPointer{
		info: unsafe.Pointer(&i),
	}
	takesPointer(a.info)
}

// callReturningUintptr must not be reported: the callee is an ordinary function
// returning uintptr, not a conversion to it.
func callReturningUintptr() {
	var i info
	sinkPlain = asAddr(unsafe.Pointer(&i))
}

func asAddr(p unsafe.Pointer) uintptr { return 0 }

// unsafePointerReturningCall must not be reported either: the callee is a
// function whose result is unsafe.Pointer, not a conversion to it.
func unsafePointerReturningCall() {
	var i info
	takesPointer(makePointer(&i))
}

func makePointer(i *info) unsafe.Pointer { return unsafe.Pointer(i) }

// plainUintptrArithmetic must not be reported; no pointer is involved.
func plainUintptrArithmetic() {
	var n uint32 = 42
	takesUintptr(uintptr(n))
}

// suppressedTrailing silences a report with a trailing directive.
func suppressedTrailing() {
	var i info
	a := attrUintptr{
		info: uintptr(unsafe.Pointer(&i)), //ptrcheck:ignore third-party field type, kept alive below
	}
	_ = syscallWrapper(&a)
}

// suppressedAbove silences a report with the directive on the preceding line.
func suppressedAbove() {
	var i info
	//ptrcheck:ignore third-party field type, kept alive below
	p := uintptr(unsafe.Pointer(&i))
	takesUintptr(p)
}

// trailingDirectiveDoesNotReachNextLine checks that a trailing directive covers
// only its own line. The second conversion has no justification of its own and
// must still be reported, which is the shape at pkg/maps/loader.go:449-450.
func trailingDirectiveDoesNotReachNextLine() {
	var p, q info
	a := attrTwo{
		x: uintptr(unsafe.Pointer(&p)), //ptrcheck:ignore justified for x only
		y: uintptr(unsafe.Pointer(&q)), // want `pointer converted to uintptr and stored`
	}
	_ = a
}

// indentedStandaloneDirective covers a directive on its own line inside a
// function body, which is the form used in pkg/progs/loader.go.
func indentedStandaloneDirective() {
	var i info
	//ptrcheck:ignore indented standalone directive
	takesUintptr(uintptr(unsafe.Pointer(&i)))
}

// standaloneDirectiveInLiteral covers the same form inside a composite literal,
// where the directive is indented and the annotated line follows it.
func standaloneDirectiveInLiteral() {
	var p, q info
	a := attrTwo{
		//ptrcheck:ignore indented standalone directive in a literal
		x: uintptr(unsafe.Pointer(&p)),
		y: uintptr(unsafe.Pointer(&q)), // want `pointer converted to uintptr and stored`
	}
	_ = a
}

// directiveThenBlankLine checks that a standalone directive reaches only the
// line immediately below it, so a blank line breaks the association.
func directiveThenBlankLine() {
	var i info
	//ptrcheck:ignore this directive annotates the blank line below it

	takesUintptr(uintptr(unsafe.Pointer(&i))) // want `pointer converted to uintptr and stored`
}

// directiveAfterClosingBrace checks that a directive sharing a line with the
// closing brace of a multi-line construct is treated as trailing. Code precedes
// it on that line, so it cannot be annotating the line below.
func directiveAfterClosingBrace() {
	var i, j info
	func() {
		_ = i
	}() //ptrcheck:ignore nothing on this line needs suppressing
	takesUintptr(uintptr(unsafe.Pointer(&j))) // want `pointer converted to uintptr and stored`
}

// twoConversionsOnOneLine documents that suppression is line-granular: a single
// trailing directive covers both conversions on the line, so they share one
// justification. Splitting them across lines would require one each.
func twoConversionsOnOneLine() {
	var p, q info
	takesTwoUintptr(uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&q))) //ptrcheck:ignore covers the whole line
}

// twoStepConversion reaches the conversion through a variable. The runtime loses
// track of the address exactly as it does for the inline form, so the type of the
// operand decides this, not its syntax.
func twoStepConversion() {
	var i info
	up := unsafe.Pointer(&i)
	takesUintptr(uintptr(up)) // want `pointer converted to uintptr and stored`
}

// conversionThroughHelperResult covers an unsafe.Pointer arriving from a call.
func conversionThroughHelperResult() {
	var i info
	takesUintptr(uintptr(pointerTo(&i))) // want `pointer converted to uintptr and stored`
}

func pointerTo(i *info) unsafe.Pointer { return unsafe.Pointer(i) }

// namedUintptrType must be reported: the conversion target is uintptr underneath,
// whatever it is spelled.
func namedUintptrType() {
	var i info
	sinkNamed = namedAddr(unsafe.Pointer(&i)) // want `pointer converted to uintptr and stored`
}

// aliasedUintptrType covers a type alias for uintptr.
func aliasedUintptrType() {
	var i info
	sinkAliased = aliasAddr(unsafe.Pointer(&i)) // want `pointer converted to uintptr and stored`
}

// aliasedSyscallImport is a safe rule (4) use reached through an aliased import.
// Matching the import name rather than the resolved package would report it.
func aliasedSyscallImport() {
	var i info
	sys.Syscall(sys.SYS_IOCTL, uintptr(0), uintptr(unsafe.Pointer(&i)), unsafe.Sizeof(i))
}

// methodNamedSyscall must be reported. The receiver is merely named like the
// syscall package, so the compiler's keep-alive guarantee does not apply.
func methodNamedSyscall() {
	var i info
	unix.Syscall(uintptr(0), uintptr(unsafe.Pointer(&i)), uintptr(0)) // want `pointer converted to uintptr and stored`
}

// syscallArgWithOffset is a safe rule (4) use with arithmetic applied to the
// address in the argument list.
func syscallArgWithOffset() {
	buf := make([]byte, 64)
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(0), uintptr(unsafe.Pointer(&buf[0]))+8, uintptr(4))
}

// syscallArgParenthesised is a safe rule (4) use wrapped in parentheses.
func syscallArgParenthesised() {
	var i info
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(0), (uintptr(unsafe.Pointer(&i))), unsafe.Sizeof(i))
}

// bareRoundTrip has no arithmetic, so it is not a rule (3) round trip and the
// stored address is reportable.
func bareRoundTrip() unsafe.Pointer {
	var i info
	return unsafe.Pointer(uintptr(unsafe.Pointer(&i))) // want `pointer converted to uintptr and stored`
}

// roundTripThroughCall wraps a stored conversion in unsafe.Pointer without any
// arithmetic. Exempting the whole subtree would hide it.
func roundTripThroughCall() unsafe.Pointer {
	var i info
	return unsafe.Pointer(storeAndReturn(uintptr(unsafe.Pointer(&i)))) // want `pointer converted to uintptr and stored`
}

func storeAndReturn(p uintptr) uintptr { sinkPlain = p; return p }
