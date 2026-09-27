//go:build unix

// This file has no !unix companion on purpose. .goreleaser.yaml builds only
// linux and darwin, and CI runs ubuntu-latest and macos-latest -- both unix
// -- so a !unix fallback would compile on no platform this repo ships or
// tests, and would exist only to bit-rot unnoticed.
package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
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
// Update must never be called from inside a mutate callback. acquireLock
// opens a fresh file descriptor on every call, and flock's exclusivity is
// per OPEN FILE DESCRIPTION, not per process or per path -- so a nested call
// would try to lock the same file a second time from the same process with a
// second descriptor, which blocks against the first exactly as it would
// against a different process. That is not a deadlock, though: the bounded
// retry loop below (see lockAcquireTimeout) means the nested call cannot
// succeed -- it burns the whole lockAcquireTimeout and then fails with a
// timeout error naming the lock path -- which makes the outer call fail too,
// since mutate's own error return propagates straight out of Update.
// Demonstrated with lockAcquireTimeout shortened to 300ms: an inner Update
// nested inside an outer one's mutate callback returned the timeout error,
// the outer Update then returned that same error, and a later, unnested
// Update acquired the lock in 6ms -- nothing was left wedged. This is not
// theoretical for this codebase specifically: milestone 3 gives runStart's
// IP-poller a reason to write state from a goroutine that runs concurrently
// with the main path holding this lock mid-cycle -- a separate goroutine
// calling Update, not a nested call from inside mutate. Two goroutines
// contending for this lock do not deadlock either; they serialise behind
// whichever one gets it first, or the loser times out under contention.
//
// On a mutate error, the lock is released and the error is returned as-is,
// without saving: whatever mutate half-built on the in-memory State is
// discarded along with it. That is only true of the State value, though --
// not of every side effect of the attempt. os.MkdirAll below and the lock
// file's create-if-absent open have already happened by the time mutate
// runs, so a failed Update can still leave a freshly created config
// directory or lock file behind; "as if Update had never been called" used
// to be the claim here, and it overstated what actually unwinds.
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
	// The lock path is deliberately NOT added to st.ManagedFiles. It used to
	// be, on the theory that `cleanup` should remove it along with everything
	// else this tool leaves behind -- but cleanup's removal loop is
	// os.Remove, and unlinking the lock path while another process holds it
	// open is exactly the swap the separate-lock-file design exists to avoid
	// (see acquireLock's own doc comment): the name stops pointing at the
	// locked inode, and the next Update's O_CREATE makes a fresh inode at
	// that name and locks THAT one instead, immediately, with zero mutual
	// exclusion from whoever still holds the old one. Demonstrated: process A
	// holding LOCK_EX, the path unlinked out from under it, and process B's
	// O_CREATE|LOCK_EX|LOCK_NB succeeding at once -- two writers inside the
	// critical section simultaneously. Nothing is lost by leaving it
	// untracked: cleanup already removes ConfigDir wholesale (it is in
	// ManagedDirs), which takes the lock file with it regardless of whether
	// it also appears in ManagedFiles.
	if err := s.Save(st); err != nil {
		return nil, err
	}
	return st, nil
}

// lockRetryInterval is how long acquireLock sleeps between LOCK_EX|LOCK_NB
// attempts while another process holds the lock, before checking the overall
// deadline again.
const lockRetryInterval = 100 * time.Millisecond

// lockAcquireTimeout bounds how long acquireLock will keep retrying an
// already-held lock before giving up, rather than blocking forever the way a
// bare LOCK_EX does. A plain LOCK_EX wedges every later Update -- including
// the `reset` that would otherwise let a user clean up the mess -- against
// any same-uid process that still holds the lock, with no message saying
// why; that is the exact FIFO-shaped failure this file's other comments
// already warn about, reached one syscall later than the FIFO gets to it.
// Demonstrated: a held lock blocked a second acquireLock for at least 15
// seconds with no output before the attempt was given up on.
//
// It is a var, not a const, only so a test can shorten it -- the same idiom
// internal/vm/network_linux.go uses for staleCleanupSettleDelay: nothing in
// production ever assigns it.
var lockAcquireTimeout = 5 * time.Second

// lockOpenAttempts bounds the retry across acquireLock's create/reopen race,
// documented at the loop itself: a concurrent unlink of the lock path between
// the O_EXCL attempt failing and the reopen succeeding fails the reopen with
// ENOENT, and this is what lets the loop go back for one more O_CREATE|O_EXCL
// attempt instead of failing the whole Update for a path that is trivially
// creatable again an instant later. 2, not unbounded: one retry is enough for
// the race this exists to cover (a single concurrent unlinker), and anything
// that keeps failing past it is a path that will not stop disappearing,
// which is a real error to surface rather than a reason to keep spinning.
const lockOpenAttempts = 2

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
	// O_NOFOLLOW: this file lives in the user's config directory, which
	// kairos-lab's own privilege model treats as attacker-writable input in
	// several other places already (see the comments on Store.Save and
	// validateStoredInterfaceName) -- and running the whole tool under sudo
	// is blessed on macOS, where the stock sudoers keeps HOME, so this open
	// can happen as root against a path inside a directory the invoking user
	// controls. It is what stops a symlink planted at path from being
	// followed: measured against a plain os.OpenFile(path, os.O_CREATE|
	// os.O_RDWR, ...) with a symlink already at path, the open followed the
	// link and created the attacker's chosen target -- as root, if the
	// process was. With O_NOFOLLOW the same open instead fails immediately
	// with "too many levels of symbolic links".
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
	// 0o644 and not 0o600: what actually saves a user from being locked out
	// of their own file after a root-privileged run (sudo on macOS) is the
	// chown below, made a hard precondition rather than best-effort -- NOT
	// the mode. A previous version of this comment claimed "at 0o644 the user
	// can still open it read-write", which is false: the mode's `other` class
	// is what a non-owning user gets, and 0644's other class is r--, while
	// this open is O_RDWR; measured directly, O_RDWR on a real root-owned
	// 0644 file this process did not own returned "permission denied", and
	// O_RDONLY on the same file succeeded. A second version of this same
	// comment then claimed a process with the same uid the file already has
	// "can still open it read-write regardless of mode", which is also
	// false: measured as the owning uid against its own file, O_RDWR
	// succeeded at 0644 but 0444, 0400 and 0000 all failed with permission
	// denied -- the owner-class bits bind the owner exactly as they read.
	// Root is the only thing exempt from a file's mode altogether, and that
	// is what a root-privileged run's own opens rely on regardless of what
	// this mode is set to. What 0644 actually buys the one case that
	// matters, correctly stated: nothing a tighter mode would not also buy
	// -- the chown below is what changes the owner away from root, and the
	// owning uid it hands the file to gets read-write from 0644's owner
	// class either way, the same as it would from 0600's.
	//
	// The open itself is two-phase, not one os.OpenFile call, and that is the
	// fix for a hard-link attack fchown lands on: `ln /etc/sudoers
	// ~/.config/kairos-lab/state.lock` plants a hard link whose inode is a
	// file the attacker does not own but the lock code would previously have
	// chowned anyway, because O_NOFOLLOW stops a SYMLINK and does nothing at
	// all about a hard link -- IsRegular() is true for one, and f.Chown is
	// fchown(2), which lands on the inode the fd points at regardless of how
	// many names lead to it. Demonstrated: with a hard link planted at the
	// lock path, the O_NOFOLLOW open succeeded, IsRegular was true, the fd's
	// inode equalled the victim's, and the victim's ownership changed.
	// Linux's fs.protected_hardlinks=1 confines the ordinary version of this
	// to files the attacker already owns, but macOS -- precisely where this
	// tool blesses running under sudo with HOME preserved -- has no
	// equivalent control at all.
	//
	// So: try O_CREATE|O_EXCL first. Success means this call is the one that
	// created the file, which is the only case chown below ever runs in --
	// a hard link or any other pre-existing name at path fails O_EXCL with
	// os.ErrExist and falls through to a plain reopen that never chowns
	// anything. The Nlink check just below is the second, independent half of
	// the same fix: even on the created branch, this refuses to lock (and
	// therefore never chowns) a file that already has more than one link,
	// which a file this call only just created cannot legitimately have.
	//
	// The reopen carries no O_CREATE -- it must not create a file the O_EXCL
	// attempt just proved already exists, or it would stop being the "only
	// case chown runs in is the one that created the file" guarantee above
	// depends on -- but that leaves a real window open: this process's own
	// `cleanup` (or another one running concurrently) can unlink path between
	// the two opens, and a lock path this steady-state, no-contention run IS
	// going to take -- the O_EXCL attempt failing EEXIST because a previous
	// run's lock file is still there is the ordinary case, not the rare one
	// -- would then fail the reopen with ENOENT and fail this Update
	// entirely, for a path that is, an instant later, perfectly creatable
	// again. lockOpenAttempts bounds a retry back to the top of this loop for
	// exactly that one race: ENOENT on the reopen loops back to another
	// O_CREATE|O_EXCL attempt, which this time succeeds and creates the file
	// itself (created flips true, and the chown below now correctly applies).
	// Bounded rather than unbounded, so a path that somehow never stops
	// disappearing fails loudly instead of spinning forever -- not a scenario
	// this codebase can reach, but not one this loop should trust either.
	created := true
	var f *os.File
	for attempt := 0; ; attempt++ {
		f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
		if err == nil {
			created = true
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("open lock file %s: %w", path, err)
		}
		created = false
		f, err = os.OpenFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
		if err == nil {
			break
		}
		if errors.Is(err, os.ErrNotExist) && attempt < lockOpenAttempts-1 {
			continue
		}
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
	// A second link to this inode is not a lock file anyone legitimately
	// created -- this function never itself names the file more than once --
	// so it is refused outright, on both branches above. On the reopen branch
	// this is the only defence against the hard-link attack described above
	// (chown never runs there at all); on the created branch it is a second,
	// independent one, in case anything ever links to the file in the window
	// between this open and this stat.
	//
	// The type assertion failing is treated as a refusal too, not as "the
	// check does not apply here": failing open is what a defence is supposed
	// to do when it cannot tell whether the thing it defends against is
	// present, and the alternative -- ok == false silently skipping the only
	// guard the reopen branch has -- is a fail-OPEN shape that would lock a
	// hard-linked file the moment this assertion ever stopped holding. It is
	// unreachable on every GOOS this //go:build unix file compiles for today
	// (fi.Sys() is always *syscall.Stat_t on linux and darwin alike), which is
	// exactly why it must fail closed rather than silently trust that fact
	// forever.
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("lock file %s: could not determine its hard link count (fi.Sys() did not return *syscall.Stat_t): refusing to lock it", path)
	}
	if st.Nlink != 1 {
		return nil, fmt.Errorf("lock file %s has %d hard links, want exactly 1: refusing to lock a file that may alias another path", path, st.Nlink)
	}

	// The chown is a hard precondition when it applies, not a best-effort
	// nicety: it is the only thing that stops a root-privileged run (sudo on
	// macOS) from leaving a root-owned file inside a directory the invoking
	// user owns and expects to fully control -- see the mode comment above
	// for why 0o644 does not do this on its own. It applies only when this
	// call created the file (created, above): a file that already existed
	// was not created by this euid-0 run, and chowning it would be changing
	// the ownership of someone else's file rather than fixing this run's
	// own. SUDO_UID/SUDO_GID are what sudo itself sets to the invoking user's
	// identity, so chowning to them undoes exactly the ownership sudo
	// introduced -- nothing more. When they are absent (running as real root,
	// not via sudo) there is no invoking user to hand the file back to, so
	// nothing here is attempted or required.
	//
	// Both failure branches below unlink path before returning: created is
	// true here, so this call is the one that just put a root-owned file at
	// path, and leaving it there hands the very next unprivileged run (this
	// tool never suggests running as root except for this one euid-0 path) a
	// bare "permission denied" on that file with no remedy at all -- exactly
	// the lockout the chown exists to prevent, self-inflicted by the attempt
	// to prevent it. Unlinking it here is what closes the loop the previous
	// version of this error asked the user to close by hand ("remove the
	// file and try again"); this does that removal itself instead of asking.
	if created && os.Geteuid() == 0 {
		uidStr, gidStr := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
		if uidStr != "" && gidStr != "" {
			uid, uerr := strconv.Atoi(uidStr)
			gid, gerr := strconv.Atoi(gidStr)
			// Absent SUDO_UID/SUDO_GID is fine (real root, not via sudo --
			// nothing to hand the file back to, above). Present but
			// unparsable is a different case entirely: sudo did set them, so
			// there IS an invoking user this file should belong to, and
			// silently skipping the chown here used to take the lock anyway
			// and leave exactly the root-owned file the chown exists to
			// prevent -- with nothing in the error path ever telling anyone
			// that happened, because there was no error path; this branch did
			// not return one.
			if uerr != nil || gerr != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("lock file %s was created owned by root, but SUDO_UID=%q / SUDO_GID=%q could not be parsed as integers (%v / %v): the file has been removed rather than left root-owned -- try again", path, uidStr, gidStr, uerr, gerr)
			}
			if cerr := f.Chown(uid, gid); cerr != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("lock file %s was created owned by root and could not be chowned to the invoking user (uid %d, gid %d): %w -- the file has been removed rather than left root-owned; try again", path, uid, gid, cerr)
			}
		}
	}

	// LOCK_EX|LOCK_NB in a bounded retry loop, not a bare blocking LOCK_EX:
	// see lockAcquireTimeout's own comment for why a plain LOCK_EX is a
	// silent, indefinite hang the moment any same-uid process already holds
	// this lock.
	deadline := time.Now().Add(lockAcquireTimeout)
	for {
		flockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if flockErr == nil {
			break
		}
		if !errors.Is(flockErr, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("lock file %s: %w", path, flockErr)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out after %s waiting for the lock on %s: another kairos-lab process is holding it -- wait for it to finish and try again", lockAcquireTimeout, path)
		}
		time.Sleep(lockRetryInterval)
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closed = true
		_ = f.Close()
	}, nil
}
