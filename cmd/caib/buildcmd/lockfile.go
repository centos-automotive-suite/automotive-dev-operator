package buildcmd

import (
	"fmt"
	"io"
	"os"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

func (h *Handler) readLockfile() (string, error) {
	if h.opts.Lockfile == nil || *h.opts.Lockfile == "" {
		return "", nil
	}
	f, err := os.Open(*h.opts.Lockfile)
	if err != nil {
		return "", fmt.Errorf("reading lockfile: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, automotivev1alpha1.MaxAIBLockfileSize+1))
	if err != nil {
		_ = f.Close()
		return "", fmt.Errorf("reading lockfile: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing lockfile: %w", err)
	}
	if len(data) == 0 {
		return "", fmt.Errorf("lockfile is empty")
	}
	content := string(data)
	if err := automotivev1alpha1.ValidateAIBLockfile(content); err != nil {
		return "", err
	}
	return content, nil
}
