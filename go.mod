module ebpf-demo

go 1.25

tool github.com/cilium/ebpf/cmd/bpf2go

require (
	github.com/cilium/ebpf v0.20.0
	github.com/containers/storage v1.59.1
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/docker/go-units v0.5.0 // indirect
	github.com/moby/sys/capability v0.4.0 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/user v0.4.0 // indirect
	golang.org/x/sys v0.38.0
)
