Strongly inspired from https://github.com/containers/oci-seccomp-bpf-hook

## Setup

### Generate the `headers/vmlinux.h` file

```bash
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > headers/vmlinux.h
```

### Configure the oci-hook

Use the [](./)