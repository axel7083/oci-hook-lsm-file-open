package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
)

type EBPFReport struct {
	Files []string `json:"files"`
}

func main() {
	image := flag.String("image", "", "OCI image")
	reportPath := flag.String("report", "", "JSON report")

	flag.Parse()

	if *image == "" || *reportPath == "" {
		log.Fatal("--image, --report and --output are required")
	}

	accessed, err := loadReport(*reportPath)
	if err != nil {
		log.Fatal(err)
	}

	files, err := listImageFilesystem(*image)
	if err != nil {
		log.Fatal(err)
	}

	report, err := BuildReport(files, accessed)
	if err != nil {
		log.Fatal(err)
	}

	p := tea.NewProgram(New(report))
	if err := p.Start(); err != nil {
		log.Fatal(err)
	}
}

func loadReport(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r EBPFReport
	if err := json.NewDecoder(f).Decode(&r); err != nil {
		return nil, err
	}

	m := make(map[string]struct{}, len(r.Files))
	for _, f := range r.Files {
		m[filepath.Clean(f)] = struct{}{}
	}
	return m, nil
}
