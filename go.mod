module ebpf-demo

go 1.25

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.20.0
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/sirupsen/logrus v1.9.3
)

require golang.org/x/sys v0.38.0 // indirect
