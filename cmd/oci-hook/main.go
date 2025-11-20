package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"

	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
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

func main() {
	// To facilitate debugging of the hook, write all logs to the syslog,
	// so we can inspect its output via `journalctl`.
	if hook, err := logrus_syslog.NewSyslogHook("", "", syslog.LOG_INFO, ""); err == nil {
		logrus.AddHook(hook)
	}

	logrus.Printf("Hello world from eBPF demo")

	state, err := parseStdin()
	if err != nil {
		logrus.Errorf("Something went wrong in start logic")
		os.Exit(1)
	}

	logrus.Printf("[oci-hook] received pid %d", state.Pid)
	logrus.Printf("[oci-hook] received container status %s", state.Status)
}
