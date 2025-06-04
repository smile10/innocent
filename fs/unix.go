//go:build !windows
// +build !windows

package fs

import (
	"os"
	"path/filepath"
	"syscall"
)

func IsHidden(path string) (bool, error) {
	return filepath.Base(path)[0] == dotCharacter, nil
}

func SafeDeleteFileIfExists(path string) error {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	fd := int(f.Fd())
	err = syscall.Fallocate(fd, 0, 0, fileInfo.Size())
	if err != nil {
		return err
	}

	f.Close()

	return os.Remove(path)
}
