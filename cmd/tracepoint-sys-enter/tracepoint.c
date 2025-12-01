//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// https://github.com/torvalds/linux/blob/master/samples/bpf/syscall_tp_kern.c
struct syscalls_enter_open_args
{
    unsigned long long unused;
    long syscall_nr;
    long filename_ptr;
    long flags;
    long mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 3);
} counting_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// BPF_HASH used to store the PID namespace of the parent PID
// of the processes inside the container.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
} parent_namespace SEC(".maps");

struct event_t {
    u64 pid;
    u64 syscall_nr;
    u64 flags;
    u64 mode;
    char filename[64];
};

// logging util function
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

// return 1 if true 0 otherwise
inline int is_target() {
    u32 key = 0;
    // default value for parent_namespace
    unsigned int zero = 0;

    __u32 pid;
    u64 mntns_id;
    __u64 pid_tgid;
    struct task_struct *task;

    task = (struct task_struct*) bpf_get_current_task();
    mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    pid_tgid = bpf_get_current_pid_tgid();
    pid = pid_tgid >> 32;

    if(pid == 133042) {
        bpf_map_update_elem(&parent_namespace, &key, &mntns_id, BPF_ANY);
    }

    u32* parent_inum = bpf_map_lookup_elem(&parent_namespace, &key);
    if (parent_inum != NULL && *parent_inum != mntns_id) {
        return 0;
    }

    return 1;
}

inline void increment_count(u32 key) {
    u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp)
    {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        return;
    }
    __sync_fetch_and_add(valp, 1);
}

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

SEC("tracepoint/kmem/mm_page_alloc")
int mm_page_alloc(struct alloc_info *info)
{
    increment_count(0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscalls_enter_open_args *ctx)
{
    /* if(!is_target()) {
        return 0;
    } */

    klog_event(ctx);
    increment_count(1);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int sys_enter_open(struct syscalls_enter_open_args *ctx)
{
    /* if(!is_target()) {
        return 0;
    } */

    klog_event(ctx);
    increment_count(2);

    return 0;
}
