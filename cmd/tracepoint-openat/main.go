//go:build linux

// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/debug/tracing/trace_pipe.
package main

import (
	"errors"
	"fmt"
	"log"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go tool bpf2go -tags linux bpf tracepoint.c -- -I./../../headers

type Event struct {
	pid       uint64
	syscallNr uint64
	flags     uint64
	mode      uint64
	filename  [256]byte
}

func (e Event) String() string {
	return fmt.Sprintf("event { {tgid:%d, pid:%d}, syscallNr:%+#v, flags:%+#v, mode:%+#v, filename:%d}",
		e.pid>>32, e.pid&0xffff,
		e.syscallNr,
		e.flags,
		e.mode,
		len(e.filename),
	)
}

const __sz_event = unsafe.Sizeof(Event{})

func (e *Event) UnmarshalBinary(b []byte) {
	if len(b) != int(__sz_event) {
		log.Fatalf("expected %d got %d", __sz_event, len(b))
		return
	}
	*e = *(*Event)(unsafe.Pointer(&b[0]))
}

const mapKey uint32 = 0
const mapKey1 uint32 = 1
const mapKey2 uint32 = 2

var objs = bpfObjects{}

func syscallOpenAt() {
	var mapKey = mapKey1
	sy, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.SysEnterOpenat, nil)
	if err != nil {
		panic(err)
	}
	defer sy.Close()
	fmt.Printf("%+#v\n", sy)
	ticker := time.NewTicker(1 * time.Second)
	log.Println("Waiting for events..")
	for range ticker.C {
		var value uint64
		if err := objs.CountingMap.Lookup(mapKey, &value); err != nil {
			// log.Fatalf("reading map: %v", err)
			continue
		}
		log.Printf("key: %d - %v times", mapKey, value)
	}
}

func syscallOpen() {
	var mapKey = mapKey2
	sy, err := link.Tracepoint("syscalls", "sys_enter_open", objs.SysEnterOpen, nil)
	if err != nil {
		panic(err)
	}
	defer sy.Close()
	fmt.Printf("%+#v\n", sy)
	ticker := time.NewTicker(1 * time.Second)
	log.Println("Waiting for events..")
	go func() {
		rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
		if err != nil {
			log.Fatal(err)
		}
		defer rd.Close()
		var ev Event
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("received signal, exiting...")
					return
				}
				log.Printf("reading from reader: %s\n", err)
				continue
			}

			ev.UnmarshalBinary(rec.RawSample)
			log.Printf("events: %s\n", ev.String())
		}
	}()
	for range ticker.C {
		var value uint64
		if err := objs.CountingMap.Lookup(mapKey, &value); err != nil {
			// log.Fatalf("reading map: %v", err)
			continue
		}
		log.Printf("key: %d - %v times", mapKey, value)
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

	go syscallOpenAt()
	go syscallOpen()

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
	kp, err := link.Tracepoint("kmem", "mm_page_alloc", objs.MmPageAlloc, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	fmt.Printf("%+#v\n", kp)

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	log.Println("Waiting for events..")
	for range ticker.C {
		var value uint64
		if err := objs.CountingMap.Lookup(mapKey, &value); err != nil {
			// log.Fatalf("reading map: %v", err)
			continue
		}
		log.Printf("key: %d - %v times", mapKey, value)
	}
}
