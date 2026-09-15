package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tuna-os/fisherman/internal/disk"
	"github.com/tuna-os/fisherman/internal/runner"
)

type retagCall struct {
	name  string
	args  []string
	stdin string
}

// recordRetag intercepts every command retagRoot runs. closeErr is what a
// luksClose returns; onClose, when set, is what closing the container does to
// its node — removing the file is what a close that worked leaves behind.
func recordRetag(t *testing.T, closeErr error, onClose func()) *[]retagCall {
	t.Helper()
	calls := &[]retagCall{}
	runner.RunFn = func(stdin io.Reader, name string, args ...string) error {
		call := retagCall{name: name, args: args}
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			call.stdin = string(b)
		}
		*calls = append(*calls, call)
		if name == "cryptsetup" && len(args) > 0 && args[0] == "luksClose" {
			if onClose != nil {
				onClose()
			}
			return closeErr
		}
		return nil
	}
	t.Cleanup(func() { runner.RunFn = runner.DefaultRun })
	return calls
}

func fakeMounts(t *testing.T, lines string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mounts")
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	old := disk.GetProcMountsPath()
	disk.SetProcMountsPath(path)
	t.Cleanup(func() { disk.SetProcMountsPath(old) })
}

// sequence is the calls that change the disk or its mapping, in order.
func sequence(calls []retagCall) []string {
	var seq []string
	for _, call := range calls {
		switch {
		case call.name == "cryptsetup":
			seq = append(seq, call.args[0])
		case call.name == "sfdisk" || call.name == "mount":
			seq = append(seq, call.name)
		}
	}
	return seq
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for at := range got {
		if got[at] != want[at] {
			return false
		}
	}
	return true
}

// The encrypted retag is the whole of block A: release the mapper mount, close
// the container, write the partition type, open the container with the key it
// was formatted with and mount the mapper. One wrong step here aborts the
// install after bootc install has already run.
func TestRetagRoot_EncryptedReleasesAndReopensTheContainer(t *testing.T) {
	mapper := filepath.Join(t.TempDir(), "fisherman-root")
	if err := os.WriteFile(mapper, []byte("open"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	fakeMounts(t, "/dev/mapper/fisherman-root "+target+" ext4 rw 0 0\n")
	calls := recordRetag(t, nil, func() { os.Remove(mapper) })

	if err := retagRoot("/dev/vda", "/dev/vda2", 2, mapper, "hunter2", target); err != nil {
		t.Fatalf("retagRoot: %v", err)
	}

	if got, want := sequence(*calls), []string{"luksClose", "sfdisk", "luksOpen", "mount"}; !equalStrings(got, want) {
		t.Errorf("command order = %v, want %v; all calls: %v", got, want, *calls)
	}
	for _, call := range *calls {
		if call.name != "cryptsetup" || len(call.args) == 0 {
			continue
		}
		switch call.args[0] {
		case "luksClose":
			if want := []string{"luksClose", "fisherman-root"}; !equalStrings(call.args, want) {
				t.Errorf("close args = %v, want %v", call.args, want)
			}
		case "luksOpen":
			if want := []string{"luksOpen", "--key-file=-", "/dev/vda2", "fisherman-root"}; !equalStrings(call.args, want) {
				t.Errorf("open args = %v, want %v", call.args, want)
			}
			if call.stdin != "hunter2" {
				t.Errorf("open stdin = %q, want the passphrase", call.stdin)
			}
		}
	}
	// The remount is the mapper. Mounting the raw partition finds the LUKS
	// header and fails after the disk is already written.
	for _, call := range *calls {
		if call.name == "mount" && !equalStrings(call.args, []string{mapper, target}) {
			t.Errorf("mount args = %v, want %v", call.args, []string{mapper, target})
		}
	}
}

func TestRetagRoot_UnencryptedMountsThePartitionBack(t *testing.T) {
	target := t.TempDir()
	fakeMounts(t, "/dev/vda2 "+target+" ext4 rw 0 0\n")
	calls := recordRetag(t, nil, nil)

	if err := retagRoot("/dev/vda", "/dev/vda2", 2, "", "", target); err != nil {
		t.Fatalf("retagRoot: %v", err)
	}

	if got, want := sequence(*calls), []string{"sfdisk", "mount"}; !equalStrings(got, want) {
		t.Errorf("command order = %v, want %v; all calls: %v", got, want, *calls)
	}
	if calls := *calls; len(calls) > 0 {
		for _, call := range calls {
			if call.name == "cryptsetup" {
				t.Errorf("an unencrypted retag ran cryptsetup %v", call.args)
			}
		}
	}
}

// A close that did not work leaves the container open, and opening it a
// second time would fail with the mapper name in use. The close failing is
// warned about, not fatal: the install continues on the container that is
// still there.
func TestRetagRoot_KeepsAContainerWhoseCloseFailed(t *testing.T) {
	mapper := filepath.Join(t.TempDir(), "fisherman-root")
	if err := os.WriteFile(mapper, []byte("open"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	fakeMounts(t, "/dev/mapper/fisherman-root "+target+" ext4 rw 0 0\n")
	calls := recordRetag(t, errors.New("still busy"), nil)

	if err := retagRoot("/dev/vda", "/dev/vda2", 2, mapper, "hunter2", target); err != nil {
		t.Fatalf("retagRoot: %v", err)
	}

	if got, want := sequence(*calls), []string{"luksClose", "sfdisk", "mount"}; !equalStrings(got, want) {
		t.Errorf("command order = %v, want %v; all calls: %v", got, want, *calls)
	}
}
