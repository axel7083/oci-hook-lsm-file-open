## Description

```
/usr/share/containers/oci/hooks.d/oci-demo-hook.json
```

## See the logs of the oci-hook

journalctl -t /home/axel7083/github/go/ebpf-demo/cmd/oci-hook/oci-hook -f

## See the logs of the lsm-file-open

journalctl -t /home/axel7083/github/go/ebpf-demo/cmd/lsm-file-open/lsm-file-open -f

## Start a container

sudo podman run --annotation="oci-demo-hook=$(pwd)/dist/fedora.profiling.json" -it quay.io/fedora/fedora@sha256:062dfd4369440e87bf18d3748e1c0b9e1530833724de291d5f3714555f8418bf