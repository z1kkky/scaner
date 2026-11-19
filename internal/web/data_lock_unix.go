//go:build darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd

package web

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type dataDirLock interface {
	Close() error
}

type fileDataDirLock struct {
	file *os.File
}

func lockDataDir(dir string) (dataDirLock, error) {
	file, err := os.OpenFile(filepath.Join(dir, ".service.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open local data lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errors.New("local data directory is already in use by another Scaner service")
		}
		return nil, fmt.Errorf("lock local data directory: %w", err)
	}
	return &fileDataDirLock{file: file}, nil
}

func (l *fileDataDirLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(unlockErr, closeErr)
}
