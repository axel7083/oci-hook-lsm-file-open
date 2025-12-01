//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define PATH_MAX        4096

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events_map SEC(".maps");

/**
    An array with data sent from user-space
    [0] => The pid of the container process
    [1] => The mnt namespace of the container
**/
u32 key_pid = 0;
u32 key_mnt_ns = 1;
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} target_map SEC(".maps");

struct event_t {
    char filename[PATH_MAX];
    // Stops tracing syscalls if true
    bool stop;
};

// return 0 if not found
u64 get_target_mnt_ns(void)
{
    // the variable that will hold the value of the target pid
    u64 *mntNS;

    // bpf_map_lookup_elem return 0, on success; negative error, otherwise
    // https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_elem/
    mntNS = bpf_map_lookup_elem(&target_map, &key_mnt_ns);

    // if unssuccessful, return 0
    if (!mntNS) {
        return 0;
    }
    return *mntNS;
}

// return 0 if not found
u64 get_target_pid(void)
{
    // the variable that will hold the value of the target pid
    u64 *target_pid;

    // bpf_map_lookup_elem return 0, on success; negative error, otherwise
    // https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_elem/
    target_pid = bpf_map_lookup_elem(&target_map, &key_pid);

    // if unssuccessful, return 0
    if (!target_pid) {
        return 0;
    }
    return *target_pid;
}

inline bool is_target_pid() {
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;

	u64 target_pid = get_target_pid();

    return target_pid == pid;
}

// return 1 if true 0 otherwise
inline int is_target_mnt_ns() {
    u32 key = 0;
    // default value for parent_namespace
    unsigned int zero = 0;

    __u32 pid;
    u64 mntns_id;
    __u64 pid_tgid;
    struct task_struct *task;

    task = (struct task_struct*) bpf_get_current_task();
    mntns_id = (u64) BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

    if(mntns_id != get_target_mnt_ns()) {
        return 0;
    }

    return 1;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
    char basename[256];
    struct dentry *d;
    struct qstr q;
    const unsigned char *name_ptr = NULL;
    int ret;

    if(!is_target_mnt_ns()) {
        return 0;
    }

    /* ---- Basename ---- */
    d = BPF_CORE_READ(file, f_path.dentry);
    if (d) {
        q = BPF_CORE_READ(d, d_name);
        name_ptr = q.name;
    }

    if (name_ptr) {
        ret = bpf_core_read_str(basename, sizeof(basename), name_ptr);
        if (ret <= 0) {
            return 0;
        }
    } else {
        return 0;
    }


    struct event_t *event;
    event = bpf_ringbuf_reserve(&events_map, sizeof(struct event_t), 0);
    if (!event) {
        // Discard the reserved data
        return 0;
    }

    // https://docs.ebpf.io/linux/kfuncs/bpf_path_d_path/
    // available from kernel 6.12
    ret = bpf_path_d_path(&file->f_path, event->filename, 4096);
    if (ret < 0) {
        // Discard the reserved data
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    bpf_printk("basename: %s | fullpath: %s\n", basename, event->filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
    if(!is_target_pid()) {
        return 0;
    }

    bpf_printk("current target pid exit\n");

    struct event_t *event;
    event = bpf_ringbuf_reserve(&events_map, sizeof(struct event_t), 0);
    if (!event) {
        // Discard the reserved data
        return 0;
    }
    event->stop = true;
    bpf_ringbuf_submit(event, 0);
    bpf_printk("submitted stop=true\n");

    return 0;
}