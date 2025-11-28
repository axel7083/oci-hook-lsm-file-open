//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") counting_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u64),
    .max_entries = 3,
};

// This struct is defined according to the following format file:
// /sys/kernel/debug/tracing/events/kmem/mm_page_alloc/format
struct alloc_info
{
    /* The first 8 bytes is not allowed to read */
    unsigned long pad;

    unsigned long pfn;
    unsigned int order;
    unsigned int gfp_flags;
    int migratetype;
};

// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/kmem/mm_page_alloc")
int mm_page_alloc(struct alloc_info *info)
{
    u32 key = 0;
    u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);
    return 0;
}


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// https://github.com/torvalds/linux/blob/master/samples/bpf/syscall_tp_kern.c
struct syscalls_enter_open_args
{
    unsigned long long unused;
    long syscall_nr;
    long filename_ptr;
    long flags;
    long mode;
};
struct syscalls_exit_open_args
{
    unsigned long long unused;
    long syscall_nr;
    long ret;
};


struct event_t {
    u64 pid;
    u64 syscall_nr;
    u64 flags;
    u64 mode;
    char filename[64];
};
inline int klog_event(struct syscalls_enter_open_args *ctx) {
    struct event_t *event;
    char *fname = (char *)(ctx->filename_ptr);
    event = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!event) {
        return -1;
    }
    event->pid = bpf_get_current_pid_tgid();
    event->syscall_nr = ctx->syscall_nr;
    event->flags = ctx->flags;
    event->mode = ctx->mode;
    if (fname) {
        bpf_probe_read_str(&event->filename, sizeof(event->filename), fname);
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscalls_enter_open_args *ctx)
{
    u32 key = 1;
    u64 initval = 1, *valp;

    klog_event(ctx);

    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscalls_enter_open_args *ctx)
{
    u32 key = 2;
    u64 initval = 1, *valp;

    klog_event(ctx);

    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        return 0;
    }
    __sync_fetch_and_add(valp, 1);
    return 0;
}