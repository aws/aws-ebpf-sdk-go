// ptrcheck is a separate module so that golang.org/x/tools stays out of the
// aws-ebpf-sdk-go dependency graph. Consumers of the SDK do not need the
// analysis framework to build.
module github.com/aws/aws-ebpf-sdk-go/tools/ptrcheck

go 1.26

require golang.org/x/tools v0.26.0

require (
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
)
