//go:build unix

// This file has no !unix companion on purpose. .goreleaser.yaml builds only
// linux and darwin, and CI runs ubuntu-latest and macos-latest -- both unix
// -- so a !unix fallback would compile on no platform this repo ships or
// tests, and would exist only to bit-rot unnoticed.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// Update runs mutate against the state Load returns, saves the result, and
// returns it -- with an exclusive cross-process lock held for the whole
// Load/mutate/Save cycle, so two processes calling Update at the same time
// cannot each load the same starting state and each save a version that
// undoes the other's change.
//
// The lock is advisory: it only ever excludes another call to Update. A
// process that calls Load and Save directly -- which every call site still
// does in this milestone, since converting them is the next one -- is
// unaffected and can still race. Nothing here can change that; flock only
// binds callers who ask for it.
//
// On a mutate error, the lock is released and the error is returned as-is,
// without saving: whatever mutate half-built on st is discarded along with
// it, exactly as if Update had never been called.
func (s *Store) Update(mutate func(*State) error) (*State, error) {
	if err := os.MkdirAll(s.ConfigDir, 0o755); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}

	lockPath := s.LockPath
	if lockPath == "" {
		lockPath = filepath.Join(s.ConfigDir, "state.lock")
	}

	unlock, err := acquireLock(lockPath)
	if err != nil {
		return nil, err
	}
	defer unlock()

	st, err := s.Load()
	if err != nil {
		return nil, err
	}
	if err := mutate(st); err != nil {
		return nil, err
	}
	// So `cleanup` removes the lock file along with everything else this
	// tool leaves in the config directory, the same way it already tracks
	// state.json's own directory. Added post-mutate and pre-Save so the
	// entry is itself part of what gets persisted.
	AddManagedFile(st, lockPath)
	if err := s.Save(st); err != nil {
		return nil, err
	}
	return st, nil
}

// acquireLock opens (creating if needed) the file at path, locks it
// exclusively with flock, and returns a function that unlocks and closes it.
// The caller is expected to defer the returned function immediately.
//
// A separate file, and not state.json itself: Save (state.go) publishes
// state.json by os.Rename-ing a temporary file over the name, so the inode a
// lock was taken on stops being the inode at that path the moment any writer
// saves. A second process that then locked "state.json" would lock the NEW
// inode left by that rename and get zero mutual exclusion from a process
// still holding a lock on the old one. A lock file that nothing ever renames
// over is the only way flock's guarantee -- which is about an inode, not a
// path -- holds across saves.
//
// Every choice below closes a specific hole that was demonstrated against
// this repo, not a theoretical one, and each is commented at the line it
// governs.
func acquireLock(path string) (unlock func(), err error) {
	// os.O_CREATE|os.O_RDWR, plus syscall.O_NOFOLLOW: this file lives in the
	// user's config directory, which kairos-lab's own privilege model treats
	// as attacker-writable input in several other places already (see the
	// comments on Store.Save and validateStoredInterfaceName) -- and running
	// the whole tool under sudo is blessed on macOS, where the stock sudoers
	// keeps HOME, so this open can happen as root against a path inside a
	// directory the invoking user controls.
	//
	// O_NOFOLLOW is what stops a symlink planted at path from being followed:
	// measured against a plain os.OpenFile(path, os.O_CREATE|os.O_RDWR, ...)
	// with a symlink already at path, the open followed the link and created
	// the attacker's chosen target -- as root, if the process was. With
	// O_NOFOLLOW the same open instead fails immediately with "too many
	// levels of symbolic links".
	//
	// O_RDWR and not O_WRONLY: a FIFO planted at path (mkfifo needs no
	// privilege beyond write access to the directory, which the user already
	// has) makes an O_WRONLY|O_CREATE open BLOCK until a reader opens the
	// other end -- which nothing here ever will, so every later invocation of
	// this tool, including the `reset` that would otherwise let a user clean
	// up the mess, hangs forever on this open. Measured: O_WRONLY blocked
	// indefinitely against a FIFO at path; O_RDWR on the same FIFO returned
	// immediately, because a reader/writer open on a FIFO does not wait for a
	// peer the way a read-only or write-only one does.
	//
	// os.OpenFile and not a raw syscall.Open: os.OpenFile always adds
	// O_CLOEXEC under the hood, and that is load-bearing here rather than
	// hygiene. `kairos-lab start` execs QEMU as a child process; a lock fd
	// that leaked across that exec would still be held open (and still
	// flocked) by the QEMU process for the VM's entire lifetime, so a second
	// `kairos-lab start` run against the same config dir would block on this
	// same flock until that VM exited -- silently, with no message pointing
	// at why. Do not swap this for syscall.Open even for a seemingly
	// equivalent flag set; it does not set O_CLOEXEC and a later refactor
	// that made that swap would reintroduce exactly this.
	//
	// 0o644 and not 0o600: the reason is the one already written at
	// state.go's Save, and it applies identically here. A file created 0o600
	// by a root-privileged run (sudo on macOS) could not be reopened by the
	// user's own later unprivileged runs -- every one of them, including
	// `reset` and `cleanup`, would fail EACCES with no way out but `sudo rm`.
	// At 0o644 the user can still open it read-write.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", path, err)
	}
	closed := false
	cleanup := func() {
		if !closed {
			_ = f.Close()
		}
	}
	defer func() {
		if err != nil {
			cleanup()
		}
	}()

	// fstat the DESCRIPTOR, not the path: a path-based stat could observe a
	// perfectly ordinary regular file and then race a swap before the flock
	// below is taken. Stat-ing the fd instead answers the only question that
	// matters -- what did this open actually hand back -- and cannot be
	// raced out from under it. A FIFO, socket or device sitting at this path
	// is not a lock file anyone legitimately created; it is refused rather
	// than locked.
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat lock file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("lock file %s is not a regular file (mode %s): refusing to lock it", path, fi.Mode())
	}

	// Best-effort ownership fix for the sudo-on-macOS case: a lock file this
	// open just created is owned by root when the process is, which would
	// otherwise leave a root-owned file inside a directory the invoking user
	// owns and expects to fully control. SUDO_UID/SUDO_GID are what sudo
	// itself sets to the invoking user's identity, so chown-ing to them
	// undoes exactly the ownership sudo introduced -- nothing more. Errors
	// here are ignored on purpose: this is a nicety, not a precondition for
	// the lock to work, and failing the whole operation over a chown that
	// could not complete would be a worse outcome than a root-owned lock
	// file. Unlike this, the open and fstat errors above are never ignored:
	// those are what decide whether path is safe to lock at all.
	if os.Geteuid() == 0 {
		uidStr, gidStr := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
		if uidStr != "" && gidStr != "" {
			if uid, uerr := strconv.Atoi(uidStr); uerr == nil {
				if gid, gerr := strconv.Atoi(gidStr); gerr == nil {
					_ = f.Chown(uid, gid)
				}
			}
		}
	}

	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock file %s: %w", path, err)
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closed = true
		_ = f.Close()
	}, nil
}
