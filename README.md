Inspired from https://github.com/containers/oci-seccomp-bpf-hook

## Installation

### Prerequisites

- **Linux kernel > 6.12**
- Go **1.25+**
- `git`
- Linux (root privileges required for the OCI hook / eBPF parts)
- Kernel with eBPF + LSM support enabled

### Clone the repository

```bash
git clone https://github.com/axel7083/oci-hook-lsm-file-open
cd oci-hook-lsm-file-open
```

### Configure

```
go mod download
make install
```