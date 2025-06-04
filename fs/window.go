//go:build windows
// +build windows

package fs

import (
	"os"
	"path/filepath"
	"syscall"
)

func IsHidden(path string) (bool, error) {
	// dotfiles also count as hidden (if you want)
	if path[0] == dotCharacter {
		return true, nil
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	// Appending `\\?\` to the absolute path helps with
	// preventing 'Path Not Specified Error' when accessing
	// long paths and filenames
	// https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation?tabs=cmd
	pointer, err := syscall.UTF16PtrFromString(`\\?\` + absPath)
	if err != nil {
		return false, err
	}

	attributes, err := syscall.GetFileAttributes(pointer)
	if err != nil {
		return false, err
	}

	return attributes&syscall.FILE_ATTRIBUTE_HIDDEN != 0, nil
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

	err = f.Truncate(fileInfo.Size())
	if err != nil {
		return err
	}

	f.Close()

	return os.Remove(path)
}
