//go:build linux

// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/debug/tracing/trace_pipe.
package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go tool bpf2go -tags linux bpf file-open.c -- -I./../../headers

var objs = bpfObjects{}

func syscallOpen() {

	sy, err := link.AttachLSM(link.LSMOptions{
		Program: objs.FileOpen,
	})
	if err != nil {
		panic(err)
	}
	defer sy.Close()

	ticker := time.NewTicker(1 * time.Second)
	log.Println("Waiting for events..")

	for range ticker.C {
		log.Printf("Tick")
	}
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	syscallOpen()
}
