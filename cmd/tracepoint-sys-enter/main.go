//go:build linux

// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/tracing/trace_pipe.
package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

//go:generate go tool bpf2go -tags linux bpf tracepoint.c -- -I./headers

const countingMapKey uint32 = 0
const targetPidMapKey uint32 = 0

func main() {
	targetPid := flag.Int("target", 0, "Trace the specified PID")
	flag.Parse()

	if targetPid == nil {
		logrus.Errorf("Should specify target PID")
		os.Exit(1)
	}

	if *targetPid <= 0 {
		logrus.Errorf("PID should greater than 0")
		os.Exit(1)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// update the target_pid_map with the target pid
	var target uint64 = uint64(*targetPid)
	err := objs.TargetPidMap.Update(targetPidMapKey, &target, 0)
	if err != nil {
		logrus.Errorf("Something went wrong while trying to update the target_pid_map: %v", err)
		os.Exit(1)
	}

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/tracing/events/kmem/mm_page_alloc
	kp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.EnterTrace, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		var value uint64
		if err := objs.CountingMap.Lookup(countingMapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%v times", value)
	}
}
