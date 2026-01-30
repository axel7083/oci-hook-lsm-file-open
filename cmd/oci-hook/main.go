package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/containers/storage/pkg/unshare"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

const (
	BPFTimeout = 10

	HookAnnotation = "oci-demo-hook"
)

// The OCI hook receives the State of the container (Pid, Annotation, etc.) through Stdin
func parseStdin() (*spec.State, error) {
	// Read the State spec from stdin and unmarshal it.
	var s spec.State
	reader := bufio.NewReader(os.Stdin)
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&s); err != nil {
		return nil, err
	}

	// Sanity check the PID.
	if s.Pid <= 0 {
		return nil, fmt.Errorf("invalid PID %d (must be greater than 0)", s.Pid)
	}

	return &s, nil
}

func initEBPF(pid int, output string) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1, syscall.SIGUSR2)

	attr := &os.ProcAttr{
		Dir: ".",
		Env: os.Environ(),
		Files: []*os.File{
			os.Stdin,
			nil,
			nil,
		},
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	execDir := filepath.Dir(self)
	exec := filepath.Join(execDir, "lsm-file-open")

	// Optional but very useful sanity check
	if _, err := os.Stat(exec); err != nil {
		return fmt.Errorf("lsm-file-open not found at %s: %w", exec, err)
	}

	process, err := os.StartProcess(
		exec,
		[]string{
			exec,
			"--target-pid",
			strconv.Itoa(pid),
			"--output",
			output,
		},
		attr,
	)
	if err != nil {
		return fmt.Errorf("cannot re-execute: %v", err)
	}
	defer func() {
		if err := process.Release(); err != nil {
			logrus.Errorf("Error releasing process: %v", err)
		}
	}()

	select {
	// Check which signal we received and act accordingly.
	case s := <-sig:
		logrus.Infof("Received signal (presumably from child): %v", s)
		switch s {
		case syscall.SIGUSR1:
			logrus.Infof("Child started tracing. We can safely detach.")
			break
		case syscall.SIGUSR2:
			logrus.Infof("Child signaled an error.")
			return errors.New("error while tracing")
		default:
			return fmt.Errorf("unexpected signal %v", s)
		}

	// The timeout kicked in. Kill the child and return the sad news.
	case <-time.After(BPFTimeout * time.Second):
		if err := process.Kill(); err != nil {
			logrus.Errorf("error killing child process: %v", err)
		}
		return fmt.Errorf("lsm-file-open didn't responded within %d seconds", BPFTimeout)
	}

	return nil
}

func main() {
	// To facilitate debugging of the hook, write all logs to the syslog,
	// so we can inspect its output via `journalctl`.
	if hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, ""); err == nil {
		logrus.AddHook(hook)
	}

	if os.Getuid() != 0 || unshare.IsRootless() {
		logrus.Errorf("running the hook requires root privileges")
		os.Exit(1)
	}

	logrus.Printf("Hello world from eBPF demo with %d", os.Getuid())

	state, err := parseStdin()
	if err != nil {
		logrus.Errorf("Something went wrong in start logic")
		os.Exit(1)
	}

	annotation := state.Annotations[HookAnnotation]

	logrus.Printf("[oci-hook] received pid %d", state.Pid)
	logrus.Printf("[oci-hook] received container status %s", state.Status)
	logrus.Printf("[oci-hook] annotation value %s", annotation)

	err = initEBPF(state.Pid, annotation)
	if err != nil {
		logrus.Errorf("init eBPF failed %v", err)
		os.Exit(1)
	}
	logrus.Printf("finishing oci-hook gracefully")
}
