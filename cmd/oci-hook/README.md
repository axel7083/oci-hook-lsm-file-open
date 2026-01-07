## Description

```
/usr/share/containers/oci/hooks.d/oci-demo-hook.json
```

## See the logs of the oci-hook

journalctl -t /home/axel7083/github/go/ebpf-demo/cmd/oci-hook/oci-hook -f

## See the logs of the lsm-file-open

journalctl -t /home/axel7083/github/go/ebpf-demo/cmd/lsm-file-open/lsm-file-open -f

## Start a container

sudo podman run --annotation="oci-demo-hook=foo" -it ubuntu