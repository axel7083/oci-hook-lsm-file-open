## Demo

This demo shows how to use eBPF to count sys call for a specific process.

```
$: go build && sudo ./tracepoint-sys-enter --target=<pid>
```