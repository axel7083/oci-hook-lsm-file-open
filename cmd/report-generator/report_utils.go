package main

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

type Node struct {
	Files       map[string]bool  `json:"files,omitempty"`
	Directories map[string]*Node `json:"directories,omitempty"`
}

type Report struct {
	Root *Node `json:"root"`
}

func newNode() *Node {
	return &Node{
		Files:       make(map[string]bool),
		Directories: make(map[string]*Node),
	}
}

func BuildReport(
	imageFiles map[string]int64,
	openedFiles map[string]struct{},
) (*Report, error) {

	root := newNode()

	// Filter openedFiles → only those that exist in imageFiles
	validOpened := make(map[string]struct{}, len(openedFiles))
	for p := range openedFiles {
		if _, ok := imageFiles[p]; ok {
			validOpened[p] = struct{}{}
		}
	}

	for p := range imageFiles {
		if err := insertPath(root, p, validOpened); err != nil {
			return nil, err
		}
	}

	return &Report{Root: root}, nil
}

func insertPath(root *Node, fullPath string, openedFiles map[string]struct{}) error {
	if fullPath == "" {
		return fmt.Errorf("empty path")
	}

	// POSIX clean: resolves //, /./, /../
	clean := path.Clean(fullPath)

	if !path.IsAbs(clean) {
		return fmt.Errorf("path must be absolute: %q", fullPath)
	}

	// Remove leading "/"
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" {
		// Path was "/" — nothing to insert
		return nil
	}

	parts := strings.Split(rel, "/")

	curr := root

	// Walk directories
	for i := 0; i < len(parts)-1; i++ {
		dir := parts[i]
		if dir == "" {
			continue
		}

		next, exists := curr.Directories[dir]
		if !exists {
			next = newNode()
			curr.Directories[dir] = next
		}
		curr = next
	}

	// Final path component is a file
	filename := parts[len(parts)-1]
	if filename == "" {
		return nil
	}

	_, accessed := openedFiles[clean]
	curr.Files[filename] = accessed

	return nil
}

func Marshal(report *Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
