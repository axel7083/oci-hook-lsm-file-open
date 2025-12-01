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

struct event_t {
    char filename[PATH_MAX];
};

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

    if(mntns_id != 4026533383) {
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

    if(!is_target()) {
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