package post

import (
	"fmt"
	"path/filepath"

	"github.com/tuna-os/fisherman/internal/runner"
)

// menuRenderer is where an image that needs one ships its BLS-to-GRUB-menu
// renderer, relative to the deployment root.
const menuRenderer = "usr/libexec/grub-menu-from-bls"

// RenderGrubMenu runs the deployment's own menu renderer against the target
// that is still mounted, and reports whether it ran.
//
// A GRUB that cannot read BLS entries has an empty menu until something
// renders them, and on the composefs backend nothing does during the install:
// bootc installs the bootloader through bootupd before it writes the entries,
// so bootupd — the only in-target code that runs at install time — runs too
// early. An image can watch /boot/loader/entries for every later upgrade, but
// there is no first boot to watch from. This is that first render, done from
// the one place the target is still writable.
//
// The renderer is the image's, not fisherman's: it is versioned with the boot
// payload it renders and with the entry format bootc writes, and a fisherman
// that reimplemented it would have to be updated in step with both.
//
// Guarded on the file, never on the family — fisherman has no business knowing
// which distributions ship a GRUB with blscfg. An image that needs no render
// ships no renderer and is skipped, which covers every Fedora target and every
// deb image built before the renderer existed.
//
// Errors are non-fatal in the sense that the caller should warn rather than
// abort: the disk is already installed by this point, and a machine that boots
// to a GRUB prompt is recoverable where a half-installed one is not.
func RenderGrubMenu(target string) (bool, error) {
	var deploy string
	if isComposeFsNative(target) {
		etcDir, err := ComposeFsDeployEtcDirFn(target)
		if err != nil {
			return false, fmt.Errorf("finding composefs deploy root: %w", err)
		}
		deploy = filepath.Dir(etcDir)
	} else {
		deployDir, err := DeploymentDirFn(target)
		if err != nil {
			return false, fmt.Errorf("finding deployment dir: %w", err)
		}
		deploy = deployDir
	}

	// `test` through the runner and not os.Stat, for the same reason
	// isComposeFsNative uses `ls`: the check has to happen in the host mount
	// namespace, and a sandbox that hid the target would otherwise report the
	// renderer missing and skip the one call that makes the disk bootable.
	script := filepath.Join(deploy, menuRenderer)
	if err := runner.Run("test", "-f", script); err != nil {
		return false, nil
	}

	// POSIX shell run by the live environment's own /bin/sh, so no chroot and
	// no interpreter out of the deployment. The renderer takes the target root
	// as its one argument for exactly this call.
	if err := runner.Run("sh", script, target); err != nil {
		return false, fmt.Errorf("rendering GRUB menu: %w", err)
	}
	return true, nil
}
