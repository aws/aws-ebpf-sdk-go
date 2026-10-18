# ptrcheck

A `go/analysis` pass that reports pointers converted to `uintptr` and then
stored, instead of being converted inline in a syscall argument list.

## Why

The Go runtime moves goroutine stacks, on growth and on GC shrink, and rewrites
only the pointers it can see. A `uintptr` holding an object address is just an
integer to the runtime, so it is not rewritten and goes stale if the stack moves
before the value reaches the kernel. The kernel then reads or writes freed
memory. There is no crash: the caller reads back zeros, or the syscall fails with
`EFAULT` or `EINVAL`, usually only under load and usually intermittently.

The `unsafe` package documents this as rule (4). The conversion is guaranteed
safe only when it appears in the argument list of a call to a function
implemented in assembly, such as `syscall.Syscall`, because only then does the
compiler keep the object alive and unmoved for the duration of the call.

```go
// Safe: the compiler pins the object for the call.
unix.Syscall(unix.SYS_BPF, op, uintptr(unsafe.Pointer(&attr)), size)

// Unsafe: the address is stored, and nothing keeps it valid.
attr := bpfAttr{info: uintptr(unsafe.Pointer(&info))}
```

Passing a `uintptr` to an ordinary Go function is the same problem, and is worse
in practice, because the callee's prologue is itself a stack-growth point.

Neither `go vet` nor `go vet -unsafeptr` catches this. `unsafeptr` looks for the
opposite direction, `unsafe.Pointer(someUintptr)`. Storing a pointer as an
integer is valid Go and invisible to the existing analyzers, which is why this
pass exists.

## Running it

```sh
cd tools/ptrcheck
go build -o /tmp/ptrcheck ./cmd/ptrcheck
cd ../..
/tmp/ptrcheck ./pkg/...
```

It exits non-zero when it reports anything, so it can serve as a CI gate. The
`Pointer safety` job in `.github/workflows/pr-tests.yaml` runs it on every PR.

That job is currently advisory (`continue-on-error: true`). There are outstanding
occurrences in `pkg/` awaiting migration to `unsafe.Pointer`, so a blocking check
would fail every PR. Findings show up in the job log and as a step annotation.
Remove `continue-on-error` once the migration lands.

The binary is invoked directly rather than through `go vet -vettool=`. Go 1.26
expects a vet tool to write its JSON to the file named by the vet config's
`Stdout` field (`cmd/go/internal/work/exec.go`), and `x/tools` v0.26.0's
`unitchecker.Config` has no such field. Under `go vet -vettool=` the JSON goes to
the process stdout instead, `go` never parses it, and the command exits 0 despite
reporting diagnostics, which is unusable as a gate. `singlechecker.Main` does
support the `.cfg` protocol, so this can be revisited when `x/tools` catches up.

## Using it from another repository

`ptrcheck` is a separate Go module so that `golang.org/x/tools` stays out of the
`aws-ebpf-sdk-go` dependency graph. Consumers of the SDK do not pull in the
analysis framework.

Being its own module also lets other repositories use it. That matters for callers
of this SDK, which hit the same pattern when passing addresses into the map APIs.
Until a `tools/ptrcheck/vX.Y.Z` tag is published, clone and build:

```sh
git clone https://github.com/aws/aws-ebpf-sdk-go
cd aws-ebpf-sdk-go/tools/ptrcheck
go build -o /tmp/ptrcheck ./cmd/ptrcheck
cd /path/to/your/repo && /tmp/ptrcheck ./...
```

`go install .../tools/ptrcheck/cmd/ptrcheck@latest` does not work yet. A nested
module resolves `@latest` against tags prefixed with its subdirectory, and this
repository publishes only root tags (`v1.0.x`), so the resolver finds the root
module and reports the package as absent. Publishing `tools/ptrcheck/vX.Y.Z`
alongside the root tag would enable it.

## Fixing a report

Type the field or parameter as `unsafe.Pointer` so the runtime tracks it, and
convert to `uintptr` only at the syscall call site. `unsafe.Pointer` and
`uintptr` are both pointer-width, so struct layout and the kernel ABI are
unchanged.

```go
type bpfAttr struct {
	fd   uint32
	_    uint32
	info unsafe.Pointer // was uintptr
}

attr := bpfAttr{info: unsafe.Pointer(&info)}
unix.Syscall(unix.SYS_BPF, op, uintptr(unsafe.Pointer(&attr)), size)
```

## Suppressing a report

Some addresses go into a struct declared in another repository whose field is
typed `uintptr`, so there is nothing to retype. `netlink.BPFAttr` in
`pkg/progs/loader.go` is the case in this repository. Keep the object alive across
the syscall with `runtime.KeepAlive` and mark the line:

```go
LogBuf: uintptr(unsafe.Pointer(&logBuf[0])), //ptrcheck:ignore third-party field type
```

A directive on its own line annotates the line below it. A trailing directive
annotates only the line it sits on, so two conversions on consecutive lines each
need their own justification. A directive sharing a line with the closing brace
or paren of a multi-line construct counts as trailing, since code precedes it on
that line. Always say why, so the next reader does not have to work it out.

Suppression is line-granular. A single directive covers every conversion on the
annotated line, so two conversions written on one line share one justification.
Split them across lines if each needs reviewing on its own.

Note what `runtime.KeepAlive` does and does not do here. From `unsafe`'s own
documentation on converting a Pointer to a uintptr: "the garbage collector will
not update that uintptr's value if the object moves, nor will that uintptr keep
the object from being reclaimed." So there are two separate hazards, and
`KeepAlive` addresses only the second. It keeps the referent reachable across the
syscall, but it does not stop the stack from moving, and a `uintptr` is not
rewritten when it does. Heap allocation is the mirror image: it removes the
stack-movement hazard but not the reachability one. Neither is a fix on its own,
which is why retyping to `unsafe.Pointer` is the remedy and suppression is
reserved for fields that cannot be retyped.

## What it does not report

- `uintptr(unsafe.Pointer(nil))`, which carries no address.
- `unsafe.Pointer(uintptr(unsafe.Pointer(p)) + off)`, the rule (3) round trip for
  pointer arithmetic, where the result stays inside the original object. A bare
  round trip with no arithmetic is not rule (3) and is reported.
- Conversions in a syscall argument list, including through parentheses or an
  offset, since the address goes straight to the kernel.
- `uintptr` values with no pointer behind them, such as `uintptr(fd)`.

Detection resolves types rather than matching identifiers, so it covers the
two-step form (`up := unsafe.Pointer(&x); p := uintptr(up)`), named and aliased
`uintptr` types, and aliased imports of `syscall` / `golang.org/x/sys/unix`. A
method on a receiver merely named `unix` is reported, because it carries none of
the compiler's guarantees.

## Tests

`analyzer_test.go` runs the pass over `testdata/src/a` using `analysistest`,
which checks both that every `want` comment is matched and that no other line
produces a diagnostic. Add a fixture for any behaviour change.

`suppress_test.go` covers `suppressedLines` directly, asserting that a directive
only silences the file it appears in. That property depends on specific line
numbers colliding across files, which fixtures can only express with pages of
padding, so it is tested as a unit instead.

```sh
cd tools/ptrcheck && go test ./...
```
