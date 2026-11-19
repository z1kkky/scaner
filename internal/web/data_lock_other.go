//go:build !(darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || windows)

package web

import "errors"

type dataDirLock interface {
	Close() error
}

func lockDataDir(string) (dataDirLock, error) {
	return nil, errors.New("exclusive local data directory locking is supported only on Linux")
}
