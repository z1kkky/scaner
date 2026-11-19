//go:build windows

package web

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type dataDirLock interface {
	Close() error
}

type fileDataDirLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func lockDataDir(dir string) (dataDirLock, error) {
	file, err := os.OpenFile(filepath.Join(dir, ".service.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open local data lock: %w", err)
	}
	var overlapped windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	if err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &overlapped); err != nil {
		_ = file.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.New("local data directory is already in use by another Scaner service")
		}
		return nil, fmt.Errorf("lock local data directory: %w", err)
	}
	return &fileDataDirLock{file: file, overlapped: overlapped}, nil
}

func (l *fileDataDirLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}
