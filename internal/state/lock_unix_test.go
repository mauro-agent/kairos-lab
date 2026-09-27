//go:build unix

package state

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestUpdateSerialisesConcurrentMutators is the test the whole lock exists to
// satisfy: two goroutines calling Update on the same store at the same time
// must both survive, rather than one silently overwriting the other's write.
//
// Without mutual exclusion, the race goes like this: both goroutines Load the
// same starting file (no VMs yet), each appends its own VM to its own
// in-memory copy, and both call Save -- whichever Rename lands second
// publishes a file with only its own VM, discarding the other's entirely. To
// give that race the best chance of actually happening rather than merely
// being possible, both goroutines are released from a closed channel at
// once -- so their first filesystem call, the Load, is what races -- and the
// whole thing is repeated across several attempts against a freshly reset
// state file, since a single attempt can get lucky even when unsynchronised.
//
// This test was confirmed to redden the way the plan asked: with the
// syscall.Flock call in acquireLock commented out, this test failed on
// multiple attempts (one of the two VMs from a given attempt missing), every
// run tried; restoring the Flock call brought it back to a clean pass every
// time. That confirms the assertions below are actually exercising the lock
// and not just decorating a test that would pass unconditionally.
func TestUpdateSerialisesConcurrentMutators(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 20
	for attempt := 0; attempt < attempts; attempt++ {
		if err := store.Save(NewState(store)); err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, name := range []string{"vm-a", "vm-b"} {
			name := name
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if _, err := store.Update(func(st *State) error {
					UpsertVM(st, VM{Name: name})
					return nil
				}); err != nil {
					errs <- err
				}
			}()
		}
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatalf("attempt %d: Update failed: %v", attempt, err)
		}

		final, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		if FindVM(final, "vm-a") == nil || FindVM(final, "vm-b") == nil {
			t.Fatalf("attempt %d: both concurrent Updates should survive, got VMs %+v -- one Update overwrote the other, so the lock did not serialise them", attempt, final.VMs)
		}
	}
}

// TestUpdateRefusesAFIFOAtTheLockPath pins the O_RDWR half of acquireLock's
// open call. mkfifo needs no privilege beyond write access to the config
// directory, which the user running kairos-lab already has, so this is a
// realistic obstacle and not a contrived one. An O_WRONLY open of a FIFO
// blocks until a reader opens the other end, which nothing here ever does; if
// acquireLock regressed to O_WRONLY this test would hang rather than fail,
// which is why it is bounded by a timeout instead of relying on the test
// process's own default deadline.
func TestUpdateRefusesAFIFOAtTheLockPath(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(store.LockPath, 0o644); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := store.Update(func(*State) error { return nil })
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Update against a FIFO lock path should fail, not lock and use it")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Update blocked on a FIFO at the lock path instead of refusing it -- an O_WRONLY open would hang here forever")
	}
}

// TestUpdateRefusesASymlinkAtTheLockPath pins the O_NOFOLLOW half of
// acquireLock's open call: a symlink planted at the lock path must be
// refused, not followed and locked (or worse, created) at whatever it points
// to.
func TestUpdateRefusesASymlinkAtTheLockPath(t *testing.T) {
	t.Setenv("KAIROS_LAB_CONFIG_DIR", t.TempDir())
	t.Setenv("KAIROS_LAB_CACHE_DIR", t.TempDir())
	store, err := DefaultStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(store.ConfigDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// The symlink's target directory is its own t.TempDir() and not
	// store.ConfigDir, so the assertion below -- that nothing was created at
	// the target -- cannot be confused by directories Update itself is
	// entitled to create (ConfigDir, via MkdirAll).
	target := filepath.Join(t.TempDir(), "attacker-target")
	if err := os.Symlink(target, store.LockPath); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Update(func(*State) error { return nil }); err == nil {
		t.Fatal("Update against a symlinked lock path should fail, not follow the link")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("the symlink target should not exist, lstat returned: %v", err)
	}
}
