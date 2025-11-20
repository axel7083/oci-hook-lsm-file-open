//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u64);
	__uint(max_entries, 1);
} counting_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} target_pid_map SEC(".maps");

// data_t used to store the data received from the event
struct syscall_data {
    // PID of the process
    u32 pid;
    // the syscall number
    u32 id;
};

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

SEC("tracepoint/raw_syscalls/sys_enter")
int enter_trace(struct tracepoint__raw_syscalls__sys_enter* args)
{
    struct syscall_data data = {};

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

    // the key of the counter on counting_map
	u32 key_counter     = 0;
	// if the counter doesn't exist, initialize it to 1'
	// u64 initval_counter = 50;
	// the pointer that will hold the value of the counter
	u64 *counterValuePointer;

	counterValuePointer = bpf_map_lookup_elem(&counting_map, &key_counter);
	/* if (!counterValuePointer) {
		// bpf_map_update_elem(&counting_map, &key_counter, &initval_counter, BPF_ANY);
		return 0;
	} */
	// bpf_map_update_elem(&counting_map, &key_counter, &target_pid, BPF_ANY);
	__sync_fetch_and_add(counterValuePointer, 1);
	return 0;
}