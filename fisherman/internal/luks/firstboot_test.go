package luks

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
)

// The image is asked, not the target: a composefs-native deployment has no
// walkable /usr. A probe that cannot run is false, which is the PCR 7 shape.
func TestImageHasPcrPolicy(t *testing.T) {
	orig := runner.RunFn
	t.Cleanup(func() { runner.RunFn = orig })

	var got []string
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		got = append([]string{name}, args...)
		return nil
	}
	if !ImageHasPcrPolicy("example.invalid/image:1") {
		t.Error("ImageHasPcrPolicy: a succeeding probe was read as no policy")
	}
	want := []string{
		"podman", "run", "--rm", "--pull=never", "--net=none",
		"--security-opt", "label=disable", "--entrypoint", "",
		"example.invalid/image:1", "/usr/bin/test", "-s",
		"/usr/share/tectonic/pcr-policy.pem",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("probe = %q, want %q", got, want)
	}

	runner.RunFn = func(_ io.Reader, _ string, _ ...string) error { return errors.New("no such image") }
	if ImageHasPcrPolicy("example.invalid/image:1") {
		t.Error("ImageHasPcrPolicy: a failing probe was read as carrying a policy")
	}
	if ImageHasPcrPolicy("") {
		t.Error("ImageHasPcrPolicy: an empty image was read as carrying a policy")
	}
}

func TestStageFirstBootEnrollment(t *testing.T) {
	target := t.TempDir()
	uuid := "abcd-1234-uuid"
	if err := StageFirstBootEnrollment(target, uuid, "secret-recovery-key", false); err != nil {
		t.Fatal(err)
	}
	// transient key: present, 0600, correct content
	kp := filepath.Join(target, "etc/fisherman/tpm2-enroll.key")
	fi, err := os.Stat(kp)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("key perm %o, want 600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(kp); string(b) != "secret-recovery-key" {
		t.Errorf("key content mismatch")
	}
	// unit: references the UUID device, shreds the key, self-disables
	up := filepath.Join(target, "usr/lib/systemd/system/fisherman-tpm2-enroll.service")
	u, err := os.ReadFile(up)
	if err != nil {
		t.Fatalf("unit: %v", err)
	}
	us := string(u)
	for _, want := range []string{
		"/dev/disk/by-uuid/" + uuid,
		"--tpm2-pcrs=7",
		"shred -u /etc/fisherman/tpm2-enroll.key",
		"systemctl disable fisherman-tpm2-enroll.service",
		"ConditionPathExists=/etc/fisherman/tpm2-enroll.key",
	} {
		if !strings.Contains(us, want) {
			t.Errorf("unit missing %q", want)
		}
	}
	// enabled via wants symlink
	link := filepath.Join(target, "etc/systemd/system/multi-user.target.wants/fisherman-tpm2-enroll.service")
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("wants symlink missing: %v", err)
	}
	// empty UUID is rejected
	if err := StageFirstBootEnrollment(t.TempDir(), "", "k", false); err == nil {
		t.Error("expected error for empty UUID")
	}
}

// With the signed PCR 11 policy the oneshot binds to it as well as PCR 7: a
// missing policy must fail instead of silently sealing the token to no PCRs,
// and the Secure Boot state stays in the lock too.
func TestStageFirstBootEnrollmentPcrPolicy(t *testing.T) {
	target := t.TempDir()
	if err := StageFirstBootEnrollment(target, "abcd-1234-uuid", "k", true); err != nil {
		t.Fatal(err)
	}
	u, err := os.ReadFile(filepath.Join(target, "usr/lib/systemd/system/fisherman-tpm2-enroll.service"))
	if err != nil {
		t.Fatalf("unit: %v", err)
	}
	us := string(u)
	for _, want := range []string{
		"--tpm2-pcrs=7",
		"--tpm2-public-key=/run/systemd/tpm2-pcr-public-key.pem",
		"--tpm2-signature=/run/systemd/tpm2-pcr-signature.json",
		"/dev/disk/by-uuid/abcd-1234-uuid",
	} {
		if !strings.Contains(us, want) {
			t.Errorf("unit missing %q", want)
		}
	}
}
