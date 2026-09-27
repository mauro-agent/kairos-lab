//go:build unix

// This file has no !unix companion on purpose. .goreleaser.yaml builds only
// linux and darwin, and CI runs ubuntu-latest and macos-latest -- both unix
// -- so a !unix fallback would compile on no platform this repo ships or
// tests, and would exist only to bit-rot unnoticed.
package state

import (
	"crypto/rand"
	"encoding/hex"
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
// not of every side effect of the attempt. os.MkdirAll below and acquireLock
// itself -- which, on the ordinary path, creates a private temporary file
// with O_CREATE|O_EXCL and links it into place at the lock path, not a
// create-if-absent open of the lock path itself; see acquireLockOnce's own
// doc comment -- have already happened by the time mutate runs, so a failed
// Update can still leave a freshly created config directory or lock file
// behind; "as if Update had never been called" used to be the claim here,
// and it overstated what actually unwinds.
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
	// (see acquireLockOnce's own doc comment): the name stops pointing at the
	// locked inode, and the next Update's create makes a fresh inode at
	// that name and locks THAT one instead, immediately, with zero mutual
	// exclusion from whoever still holds the old one. Demonstrated: process A
	// holding LOCK_EX, the path unlinked out from under it, and process B's
	// create-and-lock succeeding at once -- two writers inside the
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

// lockOpenAttempts bounds how many times acquireLock restarts the whole
// open/validate/lock sequence from the top, across four distinct races that
// all have the same shape: something removed, replaced, or is momentarily
// mid-replacing whatever path names while this call was partway through
// locking it, leaving this call holding (or about to hold) a lock on an
// inode nobody can reach by path any more -- which guards nothing, since
// every other process still finds path, opens whatever inode is there now,
// and locks THAT one, with zero mutual exclusion from this one.
//
// None of the four below is triggered by anything acquireLockOnce does to
// path itself any more on its ordinary route: it creates its file under a
// private temporary name and links that into place, never unlinking path
// (see acquireLockOnce's own doc comment for the reasoning, and for why that
// is not the same as eliminating the race). The one exception is the
// link(2)-unsupported fallback, which creates directly AT path rather than
// under a private name first -- so if its own chown then fails, its own
// cleanup removes what it just created there; see chownToInvokingUser's call
// site inside that fallback for why that is a narrow, near-immediate failure
// of a precondition already checked once earlier in the same call, not a
// race with anything external, and so does not add a fifth trigger to the
// four below. Three of the four triggers below are external: a user's
// manual `rm` of the lock file, or `cleanup`'s os.RemoveAll(ConfigDir)
// running concurrently with another command's Update. The fourth needs no
// external actor at all -- it is another kairos-lab process's own
// acquireLockOnce, mid-publish on this same path.
//
//  1. The create/reopen race, documented at the point it is detected below: a
//     concurrent replace of the lock path between this call's own link()
//     failing EEXIST and the reopen succeeding fails the reopen with ENOENT.
//  2. A concurrent unlink that instead lands strictly between an open
//     (either branch) and the fstat that follows it: the descriptor is still
//     open on an inode whose Nlink has already dropped to 0, meaning every
//     name that inode had -- including this one -- is already gone. Also
//     documented at the point it is detected below.
//  3. A concurrent replace -- an unlink followed by a fresh create at the
//     same name -- that lands AFTER this call's own flock succeeds: caught
//     by comparing a stat of the descriptor (taken before the flock) against
//     a stat of the PATH (taken after), since flock's exclusivity binds the
//     inode this descriptor points at and says nothing about what the name
//     currently resolves to. This check narrows the window in which the name
//     and the locked inode can come apart; it does not eliminate it -- see
//     the comment at the check itself for exactly what it does and does not
//     catch.
//  4. A concurrent acquireLockOnce reaching the same reopen branch as case 1,
//     but landing between a DIFFERENT call's own link() succeeding and that
//     other call's own removal of its temporary name: this call's reopen
//     then observes Nlink == 2 -- the other call's own temporary name and
//     path itself, briefly both pointing at the same inode (this call's own
//     temporary name was already removed by cleanupTmp() before this reopen
//     ran, so it never pointed at that inode and plays no part in this
//     count). That resolves itself the instant the other call finishes its
//     own cleanup -- a gap measured elsewhere in this file at microseconds.
//     A pre-existing hard link planted at path produces the identical Nlink
//     == 2 shape and reaches this exact same reopen branch (its link(2)
//     fails EEXIST against the hard link exactly as it would against
//     another call's temporary name), so it is restarted here too, not
//     refused outright by some other arm of the check: the outright
//     "refuse, do not restart" arm is reached only when THIS call's own
//     link or O_CREATE|O_EXCL create succeeded, which requires path not to
//     have existed beforehand -- so it can never observe a hard link
//     planted in advance at all. Only the restart bound (lockOpenAttempts)
//     below, and the deadline in acquireLock's own loop, eventually convert
//     a hard link that never resolves into the give-up error (see
//     errLockHardLinkAmbiguous's own comment, and the Nlink check itself for
//     the fuller version of this reasoning).
//
// The fix in every case is the same: close the stale descriptor and start
// over from the open, on the theory that a path this volatile will
// eventually hold still for one full attempt. 2, not unbounded: one retry
// was already enough for case 1 alone (a single concurrent unlinker,
// measured), and cases 2, 3 and 4 are instances of the identical race rather
// than a reason to add headroom per case -- a real deployment is not
// expected to hit more than one of the four in a row. Anything that keeps
// failing past this bound is a path that will not stop changing, which is a
// real error to surface (see the give-up error acquireLock returns when this
// bound is spent, and the separate timeout error when lockAcquireTimeout
// itself is) rather than a reason to keep spinning.
const lockOpenAttempts = 2

// errLockHardLinkAmbiguous marks the Nlink > 1 error the reopen branch below
// returns when it cannot yet tell a concurrent kairos-lab process's own
// mid-publish (case 4 in lockOpenAttempts's own comment) apart from a real,
// persistent hard link planted at path -- both produce the identical
// Nlink == 2 shape on a single attempt, and only time (a bounded number of
// restarts, or the restart bound being spent without it resolving) tells
// them apart. It exists so acquireLock's own give-up message, once that
// bound IS spent, can be worded around a real hard-link refusal with a real
// remedy, rather than around the "kept being replaced or removed ... try
// again" narrative that fits the other three races in lockOpenAttempts's
// comment but not this one: a completely static hard link replaces nothing,
// is removed by nobody, and "try again" is advice that can never clear it.
var errLockHardLinkAmbiguous = errors.New("ambiguous between a concurrent publish and a persistent hard link")

// openLockFile is os.OpenFile, linkLockFile is os.Link, statLockFile is
// (*os.File).Stat, and geteuid is os.Geteuid, each a var only so a test can
// substitute it -- the same idiom lockAcquireTimeout already uses in this
// file ("a var only so a test can shorten it; nothing in production assigns
// it").
//
// openLockFile is called from two places below, both reached only once
// linkLockFile has already failed: reopenAtPath's own reopen of path itself,
// once creating a fresh file under path has been ruled out because path
// already names something (see acquireLockOnce's own doc comment for why
// creation goes through a temporary name and linkLockFile instead of opening
// path directly); and the isLinkUnsupported fallback's own O_CREATE|O_EXCL
// at path, taken only on a filesystem where link(2) itself does not work. A
// test can use it to intervene between the reopenAtPath call and the
// subsequent flock -- swapping the file at path out from under it -- to
// drive the post-flock inode check (case 3 in lockOpenAttempts's comment) on
// demand, rather than racing a real concurrent goroutine against a timing
// window measured in microseconds.
//
// linkLockFile is called once creating the temporary file has succeeded, to
// publish it at path. A test can use it to intervene between that link
// succeeding and this call's own cleanup of the temporary name, to drive the
// Nlink == 0 restart (case 2 in lockOpenAttempts's comment) on demand.
//
// statLockFile exists for a narrower reason than the other three: not to
// change what is returned, but to give a test a reliable signal for exactly
// when the fstat/Nlink snapshot below has been taken. That snapshot reads
// the descriptor, so it is unaffected by anything done to path afterward --
// but only if "afterward" is actually after; gating a test's own swap of
// path on this call having already returned, rather than on the open
// (openLockFile) having merely been issued, is what turns "the swap happens
// between the open and the flock" from a very likely ordering into a
// guaranteed one. Measured: without this seam, a test synchronising only on
// openLockFile passed against a mutant with the post-flock check deleted in
// roughly 1 run out of 5 under an injected scheduling delay -- the fstat
// below and the test's own unlink of path could still land either side of
// each other, occasionally routing the same run through the Nlink == 0 path
// (case 2) instead of the post-flock path (case 3) the test exists to pin,
// which passes on the mutant because case 2 does not depend on the deleted
// check at all. Gating on statLockFile instead closed that gap; the same
// mutation then reddened every run.
//
// geteuid lets a test simulate running as euid 0 -- which the chown branch
// below is gated on -- without the test process actually needing to run as
// root. The chown syscall itself is not faked: fchown still runs for real
// against the test's real (non-root) privileges, which is what lets a test
// drive a genuine chown failure deterministically (chown to a uid that is
// not the test's own euid fails with EPERM when not actually privileged)
// without a fifth seam.
var (
	openLockFile = os.OpenFile
	linkLockFile = os.Link
	statLockFile = func(f *os.File) (os.FileInfo, error) { return f.Stat() }
	geteuid      = os.Geteuid
)

// lockTempFileAttempts bounds the search createTempLockFile makes for an
// unused temporary name -- the same idiom, and the same bound, as
// state.go's tempStateFileAttempts (see its own comment for why the bound
// exists at all: crypto/rand makes an actual collision negligible, so this
// is about a directory that answers "that name exists" forever, not about
// retrying collisions).
const lockTempFileAttempts = 10

// createTempLockFile creates a new, empty, private file in the same
// directory as path -- which is what lets acquireLockOnce's later
// linkLockFile call succeed; link(2) fails EXDEV across filesystems, the
// same constraint that puts createTempStateFile's own temporary file next to
// state.json rather than in the system temp dir -- under a name of the form
// <base of path>.tmp-<hex>, and returns it together with the name it was
// created at.
//
// This reproduces createTempStateFile's idiom (crypto/rand suffix, O_EXCL, a
// bounded search) rather than calling that function directly: that
// function's name is hardcoded to "state.json.tmp-*" regardless of dir,
// which would be a misleading name for a lock file's temporary, and it lives
// in state.go, which carries no unix build tag -- this file is unix-only on
// purpose (see the top of this file), and duplicating a dozen lines here
// keeps that boundary intact rather than pulling an unrelated, cross-platform
// file's naming convention across it for a difference of one string.
//
// No O_NOFOLLOW: unlike the reopen of path itself in acquireLockOnce, this
// name is not predictable in advance -- nothing can pre-plant a symlink (or
// anything else) at a filename drawn fresh from crypto/rand -- so O_EXCL
// alone makes the name safe, the same reasoning createTempStateFile's own
// comment already makes for the identical construction.
func createTempLockFile(path string) (f *os.File, name string, err error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	for i := 0; i < lockTempFileAttempts; i++ {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", fmt.Errorf("generate a temporary name: %w", err)
		}
		candidate := filepath.Join(dir, base+".tmp-"+hex.EncodeToString(suffix[:]))
		f, err := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o644)
		if err == nil {
			return f, candidate, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("no unused temporary name next to %s after %d attempts", path, lockTempFileAttempts)
}

// lockTempSibling looks for a leftover <path>.tmp-* next to path -- the exact
// name shape createTempLockFile above creates -- and returns the first match,
// or "" if there is none. It exists only to make an otherwise-mysterious
// refusal diagnosable: a hard-link refusal or a give-up error can, in the
// cases documented at their own call sites, be CAUSED by such a leftover (an
// earlier run's publish that never got to remove its own temporary name, or
// cleanup's os.RemoveAll(ConfigDir) unlinking it mid-walk), and naming it
// turns "refusing to lock a file that may alias another path" from a dead
// end into "remove this specific file and try again". A glob, not a
// directory read acquireLockOnce's own callers already have open: this is
// only ever reached on a failure path, where one extra directory scan is
// immaterial, and a glob is the simplest thing that answers "is there a
// tmp-* sibling" without this function needing to know the directory's
// other contents.
func lockTempSibling(path string) string {
	matches, err := filepath.Glob(path + ".tmp-*")
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}

// acquireLock opens (creating if needed) the file at path, locks it
// exclusively with flock, and returns a function that unlocks and closes it.
// The caller is expected to defer the returned function immediately.
//
// This is a thin restart wrapper around acquireLockOnce, which is where
// every actual open/validate/lock decision (and the reasoning behind each
// one) lives; see its own doc comment for that. What lives here is only the
// bound on how many times, and for how long, this will restart the whole
// sequence when acquireLockOnce reports the path was replaced or removed out
// from under a single attempt (see lockOpenAttempts's own comment for the
// four specific races that can trigger a restart).
func acquireLock(path string) (unlock func(), err error) {
	// One deadline, computed once here and threaded through every attempt
	// below (both the flock-wait loop inside acquireLockOnce and the
	// restart bound in this loop): lockAcquireTimeout is documented as the
	// OVERALL limit on how long acquireLock keeps trying, and computing a
	// fresh deadline per attempt would let a path that keeps getting
	// replaced (lockOpenAttempts's cases 2 and 3) rearm a full fresh
	// lockAcquireTimeout of flock-wait budget on every restart, silently
	// turning a bounded wait into an unbounded one.
	deadline := time.Now().Add(lockAcquireTimeout)
	var lastErr error
	for attempt := 0; ; attempt++ {
		unlockFn, retry, aerr := acquireLockOnce(path, deadline)
		if aerr == nil {
			return unlockFn, nil
		}
		if !retry {
			return nil, aerr
		}
		lastErr = aerr
		// Give up, rather than restart again, once EITHER bound is spent --
		// and say which one, rather than reusing one "timed out" message for
		// both: they are reached by different races. lockOpenAttempts is
		// reached by a path that keeps getting replaced on every single
		// attempt (or, since the hard-link defence stopped refusing the
		// reopen branch outright, by a persistent hard link that never
		// resolves either -- see errLockHardLinkAmbiguous's own comment),
		// which the message below says -- rather than a timeout, since it
		// does not itself check whether lockAcquireTimeout has also elapsed
		// by this point; with the retry sleep just below in the loop, it can
		// have, so the message must not claim it has not. The deadline is
		// checked separately, just below, and gets its own, genuinely
		// distinct message when IT is what ends the loop. lastErr is wrapped
		// into every variant below rather than discarded, so the specific
		// race that was hit -- ENOENT on the reopen, Nlink == 0, the
		// post-flock path/inode mismatch, or a persistent Nlink > 1 -- is
		// still visible to whoever reads the error, and the wording built
		// around it is chosen to match rather than guessed at: see the
		// branch on errLockHardLinkAmbiguous immediately below for why a
		// static hard link gets its own message rather than the "kept being
		// replaced or removed ... try again" one that fits the other three.
		if attempt >= lockOpenAttempts-1 {
			// See lockTempSibling's own comment: a leftover <path>.tmp-* is a
			// real, demonstrated cause of this give-up, and it is a cause in
			// BOTH of the shapes below -- which is why the lookup is done
			// once, here, rather than inside the churn branch alone.
			//
			// For the churn shape it is an earlier publish's temporary name
			// outliving its own removal, or cleanup's os.RemoveAll(ConfigDir)
			// racing this one. For the hard-link shape it can be the second
			// link itself: a publish killed between its link(tmp, path) and
			// its own os.Remove(tmpPath) leaves that sibling pointing at this
			// very inode, so Nlink stays at 2 for good and removing the
			// sibling by hand is exactly what clears it. An earlier version
			// of this code reasoned that THIS call's own temporary name is
			// always gone by the time the reopen observes a hard link --
			// which is true, cleanupTmp() removed it -- and then generalised
			// from that to every sibling, which is not. The one it cannot be
			// is this call's own; any other call's is fair game.
			//
			// %q, not %s: sib comes from a glob over ConfigDir, which this
			// file's own comments already treat as attacker-writable, and
			// this string reaches a terminal via cmd/kairos-lab/main.go's
			// unfiltered error printing.
			sib := lockTempSibling(path)
			if errors.Is(lastErr, errLockHardLinkAmbiguous) {
				// The last attempt found more than one hard link rather than
				// a name that had been replaced or removed, so the churn
				// narrative below would describe a cause this attempt is not.
				//
				// Scoped to that attempt deliberately, in the comment as
				// well as in the message: lastErr is overwritten every
				// iteration and nothing here records the earlier ones, so a
				// run whose first attempt failed its reopen with ENOENT and
				// whose second found the link did have something removed
				// under it -- this branch simply has no evidence of it and
				// must not narrate one way or the other. Saying "nothing was
				// replaced, nothing was removed" would be the same overreach
				// as the "every attempt" this replaced, one line above the
				// fix for it.
				giveUp := fmt.Errorf("gave up after %d attempt(s) trying to get a stable lock on %s: the restart bound (lockOpenAttempts) was spent, and the last attempt still found more than one hard link on it -- %w", attempt+1, path, lastErr)
				if sib != "" {
					giveUp = fmt.Errorf("%w -- there is also a leftover temporary file %q next to it, of the shape a publish that never removed its own temporary name leaves behind; that file may be the second link itself, in which case removing it by hand is what clears this", giveUp, sib)
				}
				return nil, giveUp
			}
			giveUp := fmt.Errorf("gave up after %d attempt(s) trying to get a stable lock on %s: the restart bound (lockOpenAttempts) was spent -- the file kept being replaced or removed out from under this process; if this persists, another process may be repeatedly recreating it; try again (%w)", attempt+1, path, lastErr)
			if sib != "" {
				giveUp = fmt.Errorf("%w -- found %q next to it, a leftover temporary file from an unfinished publish; removing that by hand is likely what clears this", giveUp, sib)
			}
			return nil, giveUp
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("timed out after %s trying to get a stable lock on %s: the file kept being replaced or removed out from under this process -- if this persists, another process may be repeatedly recreating it; try again (%w)", lockAcquireTimeout, path, lastErr)
		}
		// Sleep before restarting, the same lockRetryInterval the flock-wait
		// loop inside acquireLockOnce already sleeps between LOCK_NB
		// attempts, so this bound and lockAcquireTimeout actually compose:
		// without this, both attempts together were measured at ~81us,
		// leaving essentially all of a 5s lockAcquireTimeout unused budget
		// on the table the instant something slower than that (a concurrent
		// os.RemoveAll(ConfigDir) walking a tree, say) causes a replace --
		// failing the whole Update over a transient that a few hundred
		// milliseconds of patience would have ridden out.
		time.Sleep(lockRetryInterval)
	}
}

// acquireLockOnce is the single-attempt body acquireLock's restart loop
// calls: it opens (creating if needed) the file at path, validates it, locks
// it exclusively with flock (waiting, bounded by deadline, if someone else
// already holds it), and returns a function that unlocks and closes it.
//
// The retry return distinguishes two kinds of failure. false means the
// failure is a real, non-transient problem (a FIFO or socket at path, a
// symlink, an unparseable SUDO_UID/SUDO_GID, a chown failure, a hard link
// observed on the branch that itself just published the file, or the lock
// genuinely still held past deadline) and acquireLock should return it
// as-is. true means path was observed to have been replaced or removed out
// from under this attempt, or a second hard link was observed on the reopen
// branch, where it cannot yet be told apart from another kairos-lab process
// still mid-publish -- see lockOpenAttempts's own comment for the four
// specific races this covers -- and acquireLock should close this attempt's
// descriptor (already done here before returning) and start over from the
// open, on the theory that a path this volatile, or a publish this recent,
// will eventually hold still (or finish) for one full attempt.
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
func acquireLockOnce(path string, deadline time.Time) (unlock func(), retry bool, err error) {
	// Creation goes through a private temporary name and linkLockFile, not
	// straight to O_CREATE|O_EXCL on path itself, and that is the fix for a
	// hard-link attack fchown lands on: `ln /etc/sudoers
	// ~/.config/kairos-lab/state.lock` plants a hard link whose inode is a
	// file the attacker does not own but the lock code would previously have
	// chowned anyway, because O_NOFOLLOW stops a SYMLINK and does nothing at
	// all about a hard link -- IsRegular() is true for one, and f.Chown is
	// fchown(2), which lands on the inode the fd points at regardless of how
	// many names lead to it. The old two-phase open (O_CREATE|O_EXCL on path,
	// then a plain reopen on os.ErrExist) closed the common case of that -- a
	// pre-existing hard link at path fails O_EXCL and falls through to a
	// reopen that never chowns anything -- but the created branch still
	// chowned a file reachable by path, a name every other process on the
	// system already knows, before this call had finished validating it.
	// Creating under a name nothing but this call knows about, chowning
	// THERE, and only linking the result into path afterward removes that
	// window rather than narrowing it: nothing can hard-link to, or race,
	// a name it has never seen.
	//
	// createTempLockFile creates that temporary file; see its own comment
	// for why it duplicates createTempStateFile's idiom rather than calling
	// it, and why O_NOFOLLOW is not needed on this particular open.
	tmpFile, tmpPath, terr := createTempLockFile(path)
	if terr != nil {
		return nil, false, fmt.Errorf("create a temporary file next to lock file %s: %w", path, terr)
	}
	tmpClosed := false
	// cleanupTmp removes ONLY tmpPath, never path. path may not even exist
	// yet at this point (linkLockFile below has not been attempted), and
	// even where it does -- another process's lock file already there --
	// this call did not create it and has no business unlinking it. tmpPath,
	// by contrast, is a name nothing but this call has ever seen or opened,
	// so removing it can never hand a concurrent waiter a lock on an inode
	// it must then notice has moved on -- unlike unlinking path, which is
	// exactly the shape of change that used to break mutual exclusion for a
	// concurrent waiter (see Update's own doc comment in this file, and the
	// post-flock check below, for what that used to look like and what, from
	// outside this call, still can).
	cleanupTmp := func() {
		if !tmpClosed {
			_ = tmpFile.Close()
			tmpClosed = true
		}
		_ = os.Remove(tmpPath)
	}

	// The chown is a hard precondition when it applies, not a best-effort
	// nicety: it is the only thing that stops a root-privileged run (sudo on
	// macOS) from leaving a root-owned file inside a directory the invoking
	// user owns and expects to fully control -- mode alone cannot do that:
	// 0o644 governs who may read or write the file, which says nothing about
	// who OWNS it, so a file created 0o644 by this euid-0 run would still be
	// owned by root regardless. It applies unconditionally here, with no
	// "did this call create the file" gate the old single-open version
	// needed: every call reaches this point via its own createTempLockFile
	// just above, so the temporary file this chown targets was always
	// created by this euid-0 run, never left behind by an earlier one.
	// chownToInvokingUser (defined below, after this function, so it can be
	// reused by the link(2)-unsupported fallback further down) is where
	// SUDO_UID/SUDO_GID -- what sudo itself sets to the invoking user's
	// identity, so chowning to them undoes exactly the ownership sudo
	// introduced, nothing more -- and their absence (real root, not via
	// sudo: no invoking user to hand the file back to) are handled.
	if cerr := chownToInvokingUser(path, tmpFile, "the temporary file", cleanupTmp); cerr != nil {
		return nil, false, cerr
	}

	// link(2), not rename(2), to publish the temporary file at path: rename
	// would replace whatever is already there, silently orphaning its inode
	// -- exactly the swap this whole design exists to avoid, just moved one
	// call earlier. link fails EEXIST when path is already taken, which is
	// exactly the O_EXCL semantics the old direct-create relied on, so an
	// EEXIST here falls through to the same reopenAtPath a failed O_EXCL
	// used to: see lockOpenAttempts's comment, case 1, for the ENOENT race
	// that reopen can still hit.
	//
	// link(2) can also fail for a reason that has nothing to do with
	// contention at all: EPERM, EOPNOTSUPP, ENOSYS or EXDEV, on a
	// filesystem with no hardlink support (FAT, exFAT, SMB1 without Unix
	// extensions, some FUSE-backed object stores) or across a filesystem
	// boundary. KAIROS_LAB_CONFIG_DIR lets a user point the config
	// directory at exactly such a place, and no CI leg here can see it, so
	// isLinkUnsupported's branch below falls all the way back to creating
	// the file directly at its final name -- what this whole function did
	// before the temp-file design existed -- rather than leaving every
	// Update permanently broken wherever link(2) itself does not work.
	var f *os.File
	reopened := false
	switch lerr := linkLockFile(tmpPath, path); {
	case lerr == nil:
		// The link succeeded: path now names the same inode tmpFile already
		// has open, so there is no need to reopen anything -- f is simply
		// tmpFile from here on. tmpPath is removed so the only surviving
		// name is path, rather than two names for one inode, which the
		// Nlink check just below would otherwise -- correctly -- refuse to
		// distinguish from a hard-link attack. ErrNotExist is tolerated: a
		// demonstrated cause is `cleanup`'s own os.RemoveAll(ConfigDir)
		// walking this same directory concurrently and unlinking a
		// state.lock.tmp-* it finds mid-walk -- and the outcome this call
		// cares about, path naming exactly the Nlink == 1 file tmpFile
		// already has open, holds either way; failing this call over a
		// race that already left tmpPath in the state this call wanted
		// would send a user to remove by hand a file that does not exist.
		f = tmpFile
		if rerr := os.Remove(tmpPath); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
			_ = f.Close()
			return nil, false, fmt.Errorf("lock file %s was linked into place but its temporary name %s could not be removed: %w -- remove it by hand and try again", path, tmpPath, rerr)
		}

	case errors.Is(lerr, os.ErrExist):
		cleanupTmp()
		var oerr error
		var rtr bool
		f, rtr, oerr = reopenAtPath(path)
		if oerr != nil {
			return nil, rtr, oerr
		}
		reopened = true

	case isLinkUnsupported(lerr):
		cleanupTmp()
		// See reopenAtPath's own doc comment for the open flags used both
		// here and there; this differs only in adding O_CREATE|O_EXCL,
		// since -- unlike the EEXIST case above -- nothing has yet proved
		// path is taken. This is the fallback the comment above the switch
		// describes: it gives up the chown-while-private window the
		// temp-file design exists for, since there is no separate publish
		// step here -- the file is reachable by path from the instant it is
		// created, and the chown below runs after that, not before it -- and
		// it is taken only because the alternative, on a filesystem where
		// link(2) does not work at all, is that this branch never succeeds.
		// The Nlink check and the post-flock identity check below still
		// cover this file exactly as they cover every other branch.
		var operr error
		f, operr = openLockFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
		switch {
		case operr == nil:
			if cerr := chownToInvokingUser(path, f, "the lock file", func() {
				_ = f.Close()
				_ = os.Remove(path)
			}); cerr != nil {
				return nil, false, cerr
			}
		case errors.Is(operr, os.ErrExist):
			// Ordinary contention on a filesystem link(2) does not work on:
			// something is already at path, the identical situation the
			// EEXIST case above handles, so fall through to the identical
			// reopen -- no O_CREATE, so this cannot have created anything,
			// and therefore never chowns.
			var oerr error
			var rtr bool
			f, rtr, oerr = reopenAtPath(path)
			if oerr != nil {
				return nil, rtr, oerr
			}
			reopened = true
		default:
			return nil, false, fmt.Errorf("create lock file %s: %w", path, operr)
		}

	default:
		cleanupTmp()
		return nil, false, fmt.Errorf("create lock file %s: %w", path, lerr)
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
	fi, err := statLockFile(f)
	if err != nil {
		return nil, false, fmt.Errorf("stat lock file %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("lock file %s is not a regular file (mode %s): refusing to lock it", path, fi.Mode())
	}
	// The Nlink field this checks below distinguishes three states, not two:
	//
	//   Nlink == 1: an ordinary lock file with exactly the one name this
	//   call now reaches it by -- path, on every branch above (on the
	//   linked and fallback-created branches, only once tmpPath has already
	//   been removed, or was never created at all). Proceed.
	//
	//   Nlink == 0: this descriptor's inode has already been unlinked from
	//   every name it had, including path -- case 2 of the four races
	//   lockOpenAttempts's own comment describes. This is "the file was
	//   deleted under us", not "the file aliases another path", and it gets
	//   retry == true and a message that says so, exactly like case 1 above:
	//   there is nothing wrong with the file this call is holding open other
	//   than that path no longer names it, which the next attempt's open
	//   trivially fixes.
	//
	//   Nlink > 1: a second name for this inode this call did not expect --
	//   but "expect" splits by branch, which is what the reopened bool set
	//   above records and this check reads. On the reopen branch(es)
	//   (reopened == true: linkLockFile's own EEXIST, or the
	//   isLinkUnsupported fallback's own EEXIST), Nlink > 1 cannot yet be
	//   told apart from a genuine, persistent hard-link attack (chown never
	//   runs on this branch at all, which is why it is the attack's only
	//   remaining target) -- but the demonstrated, ordinary cause is case 4
	//   of lockOpenAttempts's own comment: another kairos-lab process's own
	//   acquireLockOnce landed its own link() at path and has not yet
	//   reached its own removal of ITS OWN temporary name, so path
	//   momentarily has two names -- that other call's tmpPath, and path
	//   itself -- for one inode, which resolves itself as soon as that
	//   other call finishes. That is transient, so it is retry == true here;
	//   the restart bound (lockOpenAttempts) and the deadline in
	//   acquireLock's own loop still convert a persistent second link (the
	//   real attack) into the give-up error once the budget is spent, so
	//   this does not weaken the defence, only delays it by a bounded
	//   number of restarts. On every OTHER branch (reopened == false: this
	//   call's own successful link, or its own successful fallback create),
	//   this call is the only one that has ever named this inode by path,
	//   so a second name on it now is not explained by that race at all --
	//   it means either the removal of tmpPath silently failed (case 2 in
	//   this file's own comment on that os.Remove, above) or something
	//   entirely unaccounted for added a name to it. Either way, unlike
	//   Nlink == 0 or the reopen-branch case above, that is a real,
	//   persistent problem with whatever is at path, not a transient one an
	//   instant will fix, so it is refused outright with retry == false.
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
		return nil, false, fmt.Errorf("lock file %s: could not determine its hard link count (fi.Sys() did not return *syscall.Stat_t): refusing to lock it", path)
	}
	if st.Nlink == 0 {
		// No manual close here: err is set on the way out, so the deferred
		// cleanup above closes f. Nothing has been locked yet at this point,
		// so a plain close is all this branch ever needs.
		return nil, true, fmt.Errorf("lock file %s was deleted while this process was opening it (0 hard links)", path)
	}
	if st.Nlink > 1 {
		if reopened {
			// Worded around errLockHardLinkAmbiguous rather than asserting a
			// single cause: this branch genuinely cannot tell a concurrent
			// kairos-lab process's own mid-publish apart from a persistent
			// hard link on a single attempt (see errLockHardLinkAmbiguous's
			// own comment, and lockOpenAttempts's case 4), so it names both,
			// rather than stating the transient one as fact and then saying
			// "retrying" -- whether this attempt actually gets to retry is
			// acquireLock's call, made after the restart budget is checked,
			// not a fact this line is in a position to promise.
			return nil, true, fmt.Errorf("lock file %s has %d hard links, want exactly 1 (%w): could be another kairos-lab process still mid-publish (between its own link and its own removal of its temporary name), which clears on its own within a restart or two, or could be a real hard link left at this path, which does not -- if this keeps recurring, identify and remove the second link (find %s -samefile %s, or ls -li %s and look for another name with this one's inode number)", path, st.Nlink, errLockHardLinkAmbiguous, filepath.Dir(path), path, filepath.Dir(path))
		}
		refusal := fmt.Errorf("lock file %s has %d hard links, want exactly 1: refusing to lock a file that may alias another path", path, st.Nlink)
		// %q, not %s: sib comes from a glob over ConfigDir, which this
		// file's own comments already treat as attacker-writable, and this
		// string reaches a terminal via cmd/kairos-lab/main.go's unfiltered
		// error printing (see lockTempSibling's own comment).
		if sib := lockTempSibling(path); sib != "" {
			refusal = fmt.Errorf("%w -- found %q next to it, a leftover temporary file; removing that by hand is likely what clears this", refusal, sib)
		}
		return nil, false, refusal
	}

	// LOCK_EX|LOCK_NB in a bounded retry loop, not a bare blocking LOCK_EX:
	// see lockAcquireTimeout's own comment for why a plain LOCK_EX is a
	// silent, indefinite hang the moment any same-uid process already holds
	// this lock. deadline is the caller's, not a fresh one computed here --
	// see acquireLock's own comment for why it must not be recomputed per
	// attempt.
	for {
		flockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if flockErr == nil {
			break
		}
		if !errors.Is(flockErr, syscall.EWOULDBLOCK) {
			return nil, false, fmt.Errorf("lock file %s: %w", path, flockErr)
		}
		if !time.Now().Before(deadline) {
			return nil, false, fmt.Errorf("timed out after %s waiting for the lock on %s: another kairos-lab process, or another part of this one, is holding it -- wait for it to finish and try again", lockAcquireTimeout, path)
		}
		time.Sleep(lockRetryInterval)
	}

	// The standard lockfile-validation check, and the reason every one of
	// this function's callers -- not just this one -- has to run it: flock's
	// exclusivity is a property of the INODE this descriptor points at, not
	// of path, and path is the name every OTHER process still finds this
	// lock by. The two can come apart -- a concurrent unlink-then-recreate
	// at path, landing anywhere from just after this call's own open to
	// just after this very flock succeeded -- and when they do, this
	// descriptor is holding a lock on an orphaned inode that guards nothing:
	// every other process opens the name, gets the NEW inode now sitting at
	// path, and locks that one immediately, with zero mutual exclusion from
	// this call. Comparing a stat of path against a stat of the descriptor
	// is what tells the two apart: st (from the fstat above, unaffected by
	// the chown, which changes ownership, not device or inode) is this
	// descriptor's identity; pathStat is a fresh Lstat of the name, not a
	// Stat, on the same not-attacker-controlled-input reasoning as the
	// O_NOFOLLOW open above -- a symlink now sitting at path should not be
	// followed even just to compare, since its own device+inode will simply
	// (and correctly) fail to match this descriptor's either way. A path
	// that no longer exists at all (ENOENT) is folded into the same
	// mismatch, for the same reason as Nlink == 0 above: this descriptor's
	// lock does not guard whatever is or is not at path any more, and that
	// is the whole of what this check exists to catch.
	//
	// What this check is worth, stated as what was actually measured rather
	// than in either direction overstated: on the ordinary route,
	// acquireLockOnce never unlinks path (see the top of this function), so
	// that route is not itself a way for the name and the locked inode to
	// come apart. The link(2)-unsupported fallback is a narrow exception --
	// it creates directly at path, and its own cleanup removes exactly that
	// if its own chown then fails (see lockOpenAttempts's own comment for why
	// that is near-unreachable in practice: the identical chown precondition
	// already succeeded once, against the temporary file, earlier in this
	// same call, on every route including this one) -- but neither route is
	// the only way the name and inode can come apart either way, and this
	// check does not close that off. It catches a replacement that lands
	// BEFORE it runs --
	// measured, that took the maximum number of simultaneous holders of the
	// critical section in that case from 2 down to 1, a real fix -- and it
	// catches nothing after: Update holds this lock for the whole
	// Load/mutate/Save cycle, essentially all of a holder's wall time, and
	// nothing revalidates for the rest of it once this one check has
	// passed. Two ways still land a replacement after this point: a user's
	// manual `rm` of the lock file, and `cleanup`'s
	// os.RemoveAll(ConfigDir) running concurrently with another command's
	// Update. Measured, both left the maximum number of simultaneous holders
	// at 2, unchanged by this check either way. The consequence of that is
	// a lost update to state.json, not anything privileged -- the chown
	// above is the only place this file's contents or ownership matter
	// beyond flock's own bookkeeping, and neither of those two remaining
	// paths touches it.
	//
	// On mismatch this is folded into the same retry as cases 1 and 2 above
	// (see lockOpenAttempts's comment): the lock this attempt holds is
	// unlocked and closed, and the caller starts over from the open.
	var pathStat syscall.Stat_t
	if serr := syscall.Lstat(path, &pathStat); serr != nil || pathStat.Dev != st.Dev || pathStat.Ino != st.Ino {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		cleanup()
		closed = true
		return nil, true, fmt.Errorf("lock file %s was replaced or removed while this process held its lock (path now resolves to a different inode, or none)", path)
	}

	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closed = true
		_ = f.Close()
	}, false, nil
}

// isLinkUnsupported reports whether err is the shape of failure link(2)
// produces when hardlinks themselves do not work here at all, rather than
// when path is merely already taken (os.ErrExist, handled separately by
// every caller of this function): EPERM, EOPNOTSUPP or ENOSYS on a
// filesystem with no hardlink support (FAT, exFAT, SMB1 without Unix
// extensions, some FUSE-backed object stores), or EXDEV, when tmpPath and
// path -- always siblings in the same directory, see createTempLockFile's
// own comment -- nonetheless resolve to different filesystems, which a bind
// mount or a network filesystem presented as a single directory tree can
// still do. Deliberately narrow: only these four, not a blanket "anything
// that is not ErrExist", so a link(2) failure for an unrelated reason (a
// permissions problem on the directory itself, say) still surfaces as the
// ordinary non-retryable error acquireLockOnce's caller of linkLockFile
// already returns for it, rather than being swallowed into a fallback that
// gives up this file's chown-while-private protection for no reason.
func isLinkUnsupported(err error) bool {
	return errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.ENOSYS) ||
		errors.Is(err, syscall.EXDEV)
}

// chownToInvokingUser runs the euid-0 chown-back-to-the-invoking-user
// precondition against f, which must already be open at, or about to be
// treated as, its final published identity -- acquireLockOnce calls this
// once against its temporary file, before that file is linked into place,
// and once more against the file a link(2)-unsupported fallback creates
// directly at its final name, where there is no separate temporary file left
// to chown instead.
//
// It is a hard precondition when it applies, not a best-effort nicety: see
// the call site inside acquireLockOnce for why leaving a root-owned file in
// the invoking user's config directory is a real problem mode alone cannot
// prevent. noun names f in the error messages below ("the temporary file" or
// "the lock file"), and cleanup is run, removing the file rather than
// leaving it behind in a state this call does not want, on either failure.
//
// Absent SUDO_UID/SUDO_GID is fine (real root, not via sudo -- nothing to
// hand the file back to) and returns nil without running cleanup. Present
// but unparsable is a different case entirely: sudo did set them, so there
// IS an invoking user this file should belong to, and silently skipping the
// chown here used to take the lock anyway and leave exactly the root-owned
// file this function exists to prevent -- with nothing in the error path
// ever telling anyone that happened, because there was no error path; this
// branch did not return one.
func chownToInvokingUser(path string, f *os.File, noun string, cleanup func()) error {
	if geteuid() != 0 {
		return nil
	}
	uidStr, gidStr := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID")
	if uidStr == "" || gidStr == "" {
		return nil
	}
	uid, uerr := strconv.Atoi(uidStr)
	gid, gerr := strconv.Atoi(gidStr)
	if uerr != nil || gerr != nil {
		cleanup()
		return fmt.Errorf("lock file %s could not be prepared: SUDO_UID=%q / SUDO_GID=%q could not be parsed as integers (%v / %v): %s has been removed rather than left root-owned -- try again", path, uidStr, gidStr, uerr, gerr, noun)
	}
	if cerr := f.Chown(uid, gid); cerr != nil {
		cleanup()
		return fmt.Errorf("lock file %s could not be prepared: %s could not be chowned to the invoking user (uid %d, gid %d): %w -- it has been removed rather than left root-owned; try again", path, noun, uid, gid, cerr)
	}
	return nil
}

// reopenAtPath re-opens an already-existing file at path, deliberately with
// no O_CREATE, for the two callers that reach it only because something has
// already proved path is taken: linkLockFile failing EEXIST, and (on a
// filesystem where link(2) itself does not work) the isLinkUnsupported
// fallback's own O_CREATE|O_EXCL failing EEXIST for the identical reason.
// Both treat retry as this function returns it, and both set their own
// local reopened = true on success, since the Nlink > 1 check further down
// reads that to tell a transient concurrent-publish race (case 4 in
// lockOpenAttempts's own comment) apart from a persistent hard link.
//
// O_NOFOLLOW: this file lives in the user's config directory, which
// kairos-lab's own privilege model treats as attacker-writable input in
// several other places already (see the comments on Store.Save and
// validateStoredInterfaceName) -- and running the whole tool under sudo is
// blessed on macOS, where the stock sudoers keeps HOME, so this open can
// happen as root against a path inside a directory the invoking user
// controls. It is what stops a symlink planted at path from being followed:
// measured against a plain os.OpenFile(path, os.O_RDWR, ...) with a symlink
// already at path, the open followed the link -- as root, if the process
// was. With O_NOFOLLOW the same open instead fails immediately with "too
// many levels of symbolic links".
//
// O_RDWR and not O_WRONLY: a FIFO planted at path (mkfifo needs no privilege
// beyond write access to the directory, which the user already has) makes an
// O_WRONLY open BLOCK until a reader opens the other end -- which nothing
// here ever will, so every later invocation of this tool, including the
// `reset` that would otherwise let a user clean up the mess, hangs forever
// on this open. Measured: O_WRONLY blocked indefinitely against a FIFO at
// path; O_RDWR on the same FIFO returned immediately, because a
// reader/writer open on a FIFO does not wait for a peer the way a read-only
// or write-only one does.
//
// os.OpenFile (via the openLockFile seam) and not a raw syscall.Open:
// os.OpenFile always adds O_CLOEXEC under the hood, and that is load-bearing
// here rather than hygiene. `kairos-lab start` execs QEMU as a child
// process; a lock fd that leaked across that exec would still be held open
// (and still flocked) by the QEMU process for the VM's entire lifetime, so a
// second `kairos-lab start` run against the same config dir would block on
// this same flock until that VM exited -- silently, with no message pointing
// at why. Do not swap this for syscall.Open even for a seemingly equivalent
// flag set; it does not set O_CLOEXEC and a later refactor that made that
// swap would reintroduce exactly this.
//
// No O_CREATE: it must not create a file the failed link (or failed
// O_CREATE|O_EXCL) just proved already exists at path -- but that leaves a
// real window open: this process's own `cleanup` (or another one running
// concurrently) can unlink path between that failure and this open, and a
// lock path this steady-state, no-contention run IS going to take -- the
// prior failure because a previous run's lock file is still there is the
// ordinary case, not the rare one -- would then fail this open with ENOENT.
// That is case 1 of the four races lockOpenAttempts's own comment describes:
// retry is returned true rather than failing this attempt's caller outright,
// for a path that is, an instant later, perfectly creatable again.
func reopenAtPath(path string) (f *os.File, retry bool, err error) {
	f, oerr := openLockFile(path, os.O_RDWR|syscall.O_NOFOLLOW, 0o644)
	if oerr != nil {
		if errors.Is(oerr, os.ErrNotExist) {
			return nil, true, fmt.Errorf("open lock file %s: %w", path, oerr)
		}
		return nil, false, fmt.Errorf("open lock file %s: %w", path, oerr)
	}
	return f, false, nil
}
