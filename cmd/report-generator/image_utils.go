package main

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type manifest struct {
	Layers []struct {
		Digest string `json:"digest"`
	} `json:"layers"`
}

func listImageFilesystem(image string) (map[string]int64, error) {
	workDir, err := os.MkdirTemp("", "image-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(workDir)

	if err := podmanSave(image, workDir); err != nil {
		return nil, err
	}

	m, err := readManifest(filepath.Join(workDir, "manifest.json"))
	if err != nil {
		return nil, err
	}

	files := make(map[string]int64)
	for _, l := range m.Layers {
		layerPath := filepath.Join(workDir, trimDigest(l.Digest))
		if err := applyLayer(layerPath, files); err != nil {
			return nil, err
		}
	}

	return files, nil
}

func podmanSave(image, dir string) error {
	cmd := exec.Command("podman", "save", "-o", dir, image, "--format=docker-dir")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

func readManifest(path string) (*manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var m manifest
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return nil, err
	}
	return &m, nil
}

func applyLayer(path string, fs map[string]int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		name := filepath.Clean("/" + h.Name)
		base := filepath.Base(name)
		dir := filepath.Dir(name)

		// Whiteout: remove file
		if strings.HasPrefix(base, ".wh.") && base != ".wh..wh..opq" {
			target := filepath.Join(dir, strings.TrimPrefix(base, ".wh."))
			delete(fs, target)
			continue
		}

		// Opaque whiteout: clear directory
		if base == ".wh..wh..opq" {
			for f := range fs {
				if strings.HasPrefix(f, dir+"/") {
					delete(fs, f)
				}
			}
			continue
		}

		if h.Typeflag == tar.TypeReg {
			fs[name] = h.Size
		}
	}
}

func trimDigest(d string) string {
	const p = "sha256:"
	if strings.HasPrefix(d, p) {
		return d[len(p):]
	}
	return d
}
