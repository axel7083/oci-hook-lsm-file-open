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
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go tool bpf2go -tags linux bpf file-open.c -- -I./../../headers

type Event struct {
	filename [4096]byte
}

var objs = bpfObjects{}

const __sz_event = unsafe.Sizeof(Event{})

func (e Event) String() string {
	return fmt.Sprintf("event { {filename:%q}",
		unix.ByteSliceToString(e.filename[:]),
	)
}

func (e *Event) UnmarshalBinary(b []byte) {
	if len(b) != int(__sz_event) {
		log.Fatalf("expected %d got %d", __sz_event, len(b))
		return
	}
	*e = *(*Event)(unsafe.Pointer(&b[0]))
}

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
		rd, err := ringbuf.NewReader(objs.bpfMaps.EventsMap)
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
