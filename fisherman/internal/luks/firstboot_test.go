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
	etc := t.TempDir()
	uuid := "abcd-1234-uuid"
	if err := StageFirstBootEnrollment(etc, uuid, "secret-recovery-key", false); err != nil {
		t.Fatal(err)
	}
	// transient key: present, 0600, correct content
	kp := filepath.Join(etc, "fisherman/tpm2-enroll.key")
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
	up := filepath.Join(etc, "systemd/system/fisherman-tpm2-enroll.service")
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
	// Enabled via wants symlink. The target is absolute — the booted system's
	// /etc/systemd/system — so Lstat asserts the link and Readlink its target;
	// a relative form such as "../fisherman-tpm2-enroll.service" fails here.
	link := filepath.Join(etc, "systemd/system/multi-user.target.wants/fisherman-tpm2-enroll.service")
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("wants symlink missing: %v", err)
	}
	if target, err := os.Readlink(link); err != nil || target != "/etc/systemd/system/fisherman-tpm2-enroll.service" {
		t.Errorf("wants symlink target %q (%v), want /etc/systemd/system/fisherman-tpm2-enroll.service", target, err)
	}
	// empty UUID or /etc is rejected
	if err := StageFirstBootEnrollment(etc, "", "k", false); err == nil {
		t.Error("expected error for empty UUID")
	}
	if err := StageFirstBootEnrollment("", uuid, "k", false); err == nil {
		t.Error("expected error for empty etc dir")
	}
}

// The deployment's /etc is what the booted system reads. A unit staged under
// the physical root's /usr never appears at /usr/lib/systemd/system on the
// machine, and no token is enrolled (measured 2026-09-16: the unit was absent
// and `cryptsetup luksDump` showed the recovery keyslot alone).
func TestStageFirstBootEnrollment_WritesTheDeploymentEtcOnly(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "state", "deploy", "e720b196", "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := StageFirstBootEnrollment(etc, "abcd-1234-uuid", "k", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "usr", "lib", "systemd", "system", "fisherman-tpm2-enroll.service")); !os.IsNotExist(err) {
		t.Errorf("unit reached the physical root's /usr: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "etc")); !os.IsNotExist(err) {
		t.Errorf("key or unit reached the physical root's /etc: %v", err)
	}
}

// With the signed PCR 11 policy the oneshot binds to it as well as PCR 7: a
// missing policy must fail instead of silently sealing the token to no PCRs,
// and the Secure Boot state stays in the lock too.
func TestStageFirstBootEnrollmentPcrPolicy(t *testing.T) {
	etc := t.TempDir()
	if err := StageFirstBootEnrollment(etc, "abcd-1234-uuid", "k", true); err != nil {
		t.Fatal(err)
	}
	u, err := os.ReadFile(filepath.Join(etc, "systemd/system/fisherman-tpm2-enroll.service"))
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
