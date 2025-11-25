//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// data_t used to store the data received from the event
struct syscall_data {
    // PID of the process
    u32 pid;
    // the syscall number
    u32 id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} target_pid_map SEC(".maps");

/*
    https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_PERF_EVENT_ARRAY/
*/
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(value, struct syscall_data);
} events_map SEC(".maps");

// return 0 if not found
int get_target_pid(void)
{
    // the variable that will hold the value of the target pid
    u32 key_targed_pid = 0;
    u64 *valTargetPid;

    // bpf_map_lookup_elem return 0, on success; negative error, otherwise
    // https://docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_map_lookup_elem/
    valTargetPid = bpf_map_lookup_elem(&target_pid_map, &key_targed_pid);

    // if unssuccessful, return 0
    if (!valTargetPid) {
        return 99;
    }
    return *valTargetPid;
}

struct bpf_raw_tracepoint_args {
    __u64 args[0];
};

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_trace(struct bpf_raw_tracepoint_args* ctx)
{
    struct syscall_data data = {};

    // Get the syscall number
    unsigned long syscall_id = ctx->args[1];
    data.id = syscall_id;
    /*
    The bpf_get_current_pid_tgid helper function returns a 64-bit value containing
     the current task's PID in the lower 32 bits and TGID (thread group ID) in the upper 32 bits.
    */
    data.pid = bpf_get_current_pid_tgid();

    // let's get the target pid
    // if zero => ignore
    u64 target_pid = get_target_pid();
    if(target_pid != data.pid) {
        return 0;
    }

    // write the data to the perf event array
	bpf_perf_event_output(ctx, &events_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
	return 0;
}