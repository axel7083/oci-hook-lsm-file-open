//go:build linux

// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/debug/tracing/trace_pipe.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/syslog"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"golang.org/x/sys/unix"
)

//go:generate go tool bpf2go -tags linux bpf file-open.c -- -I./../../headers

type Event struct {
	filename [unix.PathMax]byte
	// Stops tracing syscalls if true
	stop bool
}

var objs = bpfObjects{}

const __sz_event = unsafe.Sizeof(Event{})

func (e Event) String() string {
	return fmt.Sprintf("{ filename:%s }",
		unix.ByteSliceToString(e.filename[:]),
	)
}

func (e *Event) UnmarshalBinary(b []byte) {
	if len(b) != int(__sz_event) {
		logrus.Fatalf("expected %d got %d", __sz_event, len(b))
		return
	}
	*e = *(*Event)(unsafe.Pointer(&b[0]))
}

func setTargetMap(pid uint64, mntNS uint64) error {
	const targetPidKey uint32 = 0
	const targetMntNsKey uint32 = 1
	if err := objs.TargetMap.Update(targetPidKey, &pid, 0); err != nil {
		return err
	}
	if err := objs.TargetMap.Update(targetMntNsKey, &mntNS, 0); err != nil {
		return err
	}
	return nil
}

/*
Attach the eBPF hooks
*/
func attach() error {
	var wg sync.WaitGroup

	tracepoint, err := link.Tracepoint("sched", "sched_process_exit", objs.SchedProcessExit, nil)
	if err != nil {
		return err
	}
	defer tracepoint.Close()

	sy, err := link.AttachLSM(link.LSMOptions{
		Program: objs.FileOpen,
	})
	if err != nil {
		return err
	}
	defer sy.Close()

	logrus.Printf("Waiting for events..")

	rd, err := ringbuf.NewReader(objs.bpfMaps.EventsMap)
	if err != nil {
		logrus.Fatal(err)
		return err
	}
	defer rd.Close()

	// Initialize the wait group used to wait for the tracing to be finished.
	wg.Add(1)
	go func() {
		defer wg.Done()

		var ev Event
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					logrus.Println("received signal, exiting...")
					return
				}
				logrus.Printf("reading from reader: %s\n", err)
				continue
			}

			ev.UnmarshalBinary(rec.RawSample)

			if ev.stop {
				logrus.Printf("received stop event, exiting..")
				return
			}

			logrus.Printf("events: %s", unix.ByteSliceToString(ev.filename[:]))
		}
	}()

	ppid := os.Getppid()
	parentProcess, err := os.FindProcess(ppid)
	if err != nil {
		return fmt.Errorf("cannot find parent process %d: %v", ppid, err)
	}

	// Send a signal to the parent process to indicate the compilation has
	// been completed.
	if err := parentProcess.Signal(syscall.SIGUSR1); err != nil {
		return err
	}

	// Waiting for the goroutine which is reading the perf buffer to be done
	// The goroutine will exit when the container exits
	wg.Wait()

	return nil
}

func MountNS(pid uint64) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	buf := make([]byte, 128)

	n, err := unix.Readlink(path, buf)
	if err != nil {
		return 0, err
	}

	link := string(buf[:n]) // link looks like: mnt:[4026532548]

	// extract number
	start := strings.Index(link, "[")
	end := strings.Index(link, "]")
	if start == -1 || end == -1 || start >= end {
		return 0, fmt.Errorf("unexpected format: %s", link)
	}

	return strconv.ParseUint(link[start+1:end], 10, 64)
}

func main() {
	// To facilitate debugging of the hook, write all logs to the syslog,
	// so we can inspect its output via `journalctl`.
	if hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, ""); err == nil {
		logrus.AddHook(hook)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		logrus.Fatal(err)
		os.Exit(1)
	}

	targetPid := flag.Uint64("target-pid", 0, "Trace the specified mnt namespace")
	flag.Parse()

	if targetPid == nil || *targetPid == 0 {
		logrus.Errorf("--mnt-ns is required")
		os.Exit(1)
	}

	// Load pre-compiled programs and maps into the kernel.
	if err := loadBpfObjects(&objs, nil); err != nil {
		logrus.Fatalf("loading objects: %v", err)
		os.Exit(1)
	}
	defer objs.Close()

	mntNS, err := MountNS(*targetPid)
	if err != nil {
		logrus.Errorf("cannot find mnt namespace: %v", err)
		os.Exit(1)
	}

	// Update the target_mnt_ns_map on the eBPF object
	if err := setTargetMap(*targetPid, mntNS); err != nil {
		logrus.Errorf("Something went wrong while trying to update the target_pid_map: %v", err)
		os.Exit(1)
	}

	// Attach on lsm/file_open
	if err := attach(); err != nil {
		logrus.Errorf("cannot attach lsm/file_open: %v", err)
		os.Exit(1)
	}
	logrus.Printf("finishing lsm/file_open gracefully")
}
