//go:build linux

// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/tracing/trace_pipe.
package main

//go:generate go tool bpf2go -tags linux bpf tracepoint.c -- -I./../../headers

func main() {

}
