module github.com/jayanthvn/pure-gobpf/test

go 1.19

require (
	github.com/aws/aws-ebpf-sdk-go v0.0.0-20230616053809-009e64b9692e
	github.com/fatih/color v1.15.0
)

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/vishvananda/netlink v1.1.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.26.0 // indirect
	golang.org/x/sys v0.15.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace github.com/aws/aws-ebpf-sdk-go => ../
