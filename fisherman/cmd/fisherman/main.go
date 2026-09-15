package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/tuna-os/fisherman/internal/disk"
	"github.com/tuna-os/fisherman/internal/install"
	"github.com/tuna-os/fisherman/internal/luks"
	"github.com/tuna-os/fisherman/internal/post"
	"github.com/tuna-os/fisherman/internal/progress"
	"github.com/tuna-os/fisherman/internal/recipe"
	"github.com/tuna-os/fisherman/internal/slurp"
)

const (
	defaultTargetMount = "/mnt/fisherman-target"
	defaultLuksMapper  = "fisherman-root"
)

// These are resolved from the recipe in main(); package-level vars rather than
// constants so the rest of this file (which references them by short name)
// stays readable. Tests don't touch these directly — they exercise the helper
// functions in disk/, luks/, post/ which take the paths as arguments.
var (
	targetMount = defaultTargetMount
	luksMapper  = defaultLuksMapper
)

// cleanup is global so fatal() can tear everything down on any error path.
var cleanup = &post.Cleanup{}

// bindMount is disk.BindMount by default; tests replace it to avoid real mounts.
var bindMount = disk.BindMount

type stepProfile struct {
	cumulativePct int
	weightPct     int
}

// buildProfile returns per-step weight profiles based on timing data from a
// yellowfin gnome-hwe loop-device install (264s uncached, ~111s cached).
// Weights sum to 100. cumulativePct is the bar position at step start.
func buildProfile(needsPull, hasLUKS, hasTPM2enrolment, hasVarDiskFormat bool) []stepProfile {
	osWeight := 87
	flatpakWeight := 11
	if !needsPull {
		osWeight = 68
		flatpakWeight = 29
	}
	if hasLUKS {
		osWeight--
	}
	if hasTPM2enrolment {
		osWeight--
	}

	weights := []int{0, 1} // partition, format EFI
	if hasLUKS {
		weights = append(weights, 1) // LUKS setup
	}
	weights = append(weights, 0, 0) // format root, mount
	if hasVarDiskFormat {
		weights = append(weights, 0) // format /var disk (fast)
	}
	weights = append(weights, osWeight) // install OS
	if hasTPM2enrolment {
		weights = append(weights, 1) // TPM2 enrolment
	}
	weights = append(weights, flatpakWeight, 0) // flatpaks, configure
	sum := 0
	for _, w := range weights {
		sum += w
	}
	weights = append(weights, 100-sum) // finalize

	profile := make([]stepProfile, len(weights))
	cumulative := 0
	for i, w := range weights {
		profile[i] = stepProfile{cumulative, w}
		cumulative += w
	}
	return profile
}

func fatal(format string, args ...any) {
	cleanup.Run()
	fmt.Fprintf(os.Stderr, "fisherman: fatal: "+format+"\n", args...)
	os.Exit(1)
}

// lookPath is exec.LookPath by default; replaced in tests.
var lookPath = exec.LookPath

// isSpaceConstrained reports whether the given path is on a filesystem that is
// too small for multi-gigabyte scratch I/O. This covers:
//   - tmpfs: RAM-backed, used by some live ISOs for /var
//   - overlayfs: used by dmsquash-live (dracut) live ISOs where / and /var
//     are an overlay on top of a squashfs; the writable upper layer has only
//     a few GiB available
func isSpaceConstrained(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	const (
		tmpfsMagic   = 0x01021994
		overlayMagic = 0x794c7630
	)
	return st.Type == tmpfsMagic || st.Type == overlayMagic
}

func prepareScratchDir(activeTargetMount string, liveISO bool) (string, error) {
	scratchDir := "/var/fisherman-tmp"
	if liveISO {
		scratchDir = filepath.Join(activeTargetMount, ".fisherman-scratch")
		progress.Info("Live environment detected (/var is space-constrained) — using target disk for scratch I/O")
	}
	if err := os.MkdirAll(scratchDir, 0o700); err != nil {
		return "", err
	}
	if liveISO {
		// Self-bind so bootc sees a mount point, not a plain directory.
		if err := bindMount(scratchDir, scratchDir); err != nil {
			return "", err
		}
		cleanup.AddMount(scratchDir)
		// Removal is registered as a post-removal so it runs *after* the
		// unmount above and after the LUKS close — and crucially it still
		// fires on the fatal() error path, where os.Exit(1) would otherwise
		// skip a deferred RemoveAll and leak the OCI cache on the target disk.
		cleanup.AddPostRemoval(scratchDir)
	}
	return scratchDir, nil
}

// expandPath prepends standard sbin directories and any tools staged alongside
// this binary to PATH.  pkexec strips the user's PATH to a minimal safe set
// that omits /usr/sbin and /sbin on many immutable distros (e.g. GnomeOS).
func expandPath() {
	current := os.Getenv("PATH")
	// Build candidate prefix: staged tools dir (sibling of this binary) first,
	// then the standard sbin locations that pkexec commonly strips.
	prefix := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if exe, err := os.Executable(); err == nil {
		toolsDir := filepath.Join(filepath.Dir(exe), "tools")
		if info, err := os.Stat(toolsDir); err == nil && info.IsDir() {
			prefix = toolsDir + ":" + prefix
		}
	}
	if current != "" {
		prefix = prefix + ":" + current
	}
	os.Setenv("PATH", prefix)
}

// checkRequiredTools verifies that every host binary needed by this recipe
// is reachable on PATH before we touch any disks, and returns a clear error
// naming the missing tool and the package that provides it.
func checkRequiredTools(r *recipe.Recipe) error {
	type requirement struct {
		tool string
		pkg  string
		when bool
	}
	reqs := []requirement{
		{"sfdisk", "util-linux", true},
		{"mkfs.fat", "dosfstools", true},
		{"mkfs.ext4", "e2fsprogs", true},
		{"mkfs.xfs", "xfsprogs", r.Filesystem == "xfs"},
		{"mkfs.btrfs", "btrfs-progs", r.Filesystem == "btrfs"},
		{"zpool", "zfsutils-linux", r.Filesystem == "zfs"},
		{"zfs", "zfsutils-linux", r.Filesystem == "zfs"},
		{"cryptsetup", "cryptsetup", r.Encryption.Type != "" && r.Encryption.Type != "none"},
		// systemd-cryptenroll is required for TPM2 auto-unlock enrolment.
		// Check before touching any disks — a missing tool at step 9 (after
		// partitioning and OS install) would leave the disk partially modified.
		{"systemd-cryptenroll", "systemd", r.Encryption.Type == "tpm2-luks" || r.Encryption.Type == "tpm2-luks-passphrase"},
		{"skopeo", "skopeo", true},
		{"podman", "podman", true},
	}
	for _, req := range reqs {
		if !req.when {
			continue
		}
		if _, err := lookPath(req.tool); err != nil {
			return fmt.Errorf("%q not found in PATH — install the %q package on the host", req.tool, req.pkg)
		}
	}
	return nil
}

var version = "dev"

// retagRoot releases the installed root, puts its partition on the Linux root
// GUID, and mounts it back at targetMount. That GUID is what
// systemd-gpt-auto-generator looks for when no root= reaches it, which is the
// sealed UKI's only route to an encrypted root and what a composefs install
// wants either way.
//
// A non-empty mapperPath means the root filesystem is inside a dm-crypt
// container: the mount is the mapper node and the container is closed before
// sfdisk writes the table and opened again after. Releasing the raw partition
// by number finds no mount to release, and mounting the raw partition back up
// finds the crypto_LUKS header rather than a filesystem.
func retagRoot(diskDev, rootPart string, rootPartNum int, mapperPath, passphrase, targetMount string) error {
	encrypted := mapperPath != ""
	if encrypted {
		if err := disk.UnmountDevice(mapperPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not fully clean container references: %v\n", err)
		}
		// A close that fails leaves the container open; the mount below then
		// uses the node that is still there rather than opening it twice.
		if _, err := os.Stat(mapperPath); err == nil {
			if err := luks.Close(luksMapper); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not close %s before retag: %v\n", mapperPath, err)
			}
		}
	} else if err := disk.UnmountPartition(diskDev, rootPartNum); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not fully clean partition references: %v\n", err)
	}
	if err := disk.SetPartitionType(diskDev, rootPartNum, disk.GPTPartTypeLinuxRootX86_64); err != nil {
		return fmt.Errorf("retagging root partition: %w", err)
	}
	// Remount root so finalization and post-install writes can proceed.
	// udisksctl unmount (used above) removes the mountpoint directory it
	// manages, and disk.Mount — unlike MountTmpfs/BindMount — does not create
	// its target, so recreate it or the plain `mount` syscall below fails with
	// ENOENT.
	if err := os.MkdirAll(targetMount, 0o755); err != nil {
		return fmt.Errorf("recreating target mountpoint before remount: %w", err)
	}
	rootDev := rootPart
	if encrypted {
		// Only an absent node means the container is closed; a stat that
		// failed for any other reason must not lead to opening it twice.
		if _, err := os.Stat(mapperPath); errors.Is(err, fs.ErrNotExist) {
			if err := luks.Open(rootPart, passphrase, luksMapper); err != nil {
				return fmt.Errorf("reopening the root container after retagging: %w", err)
			}
		}
		rootDev = mapperPath
	}
	if err := disk.Mount(rootDev, targetMount, ""); err != nil {
		return fmt.Errorf("remounting root partition after retagging: %w", err)
	}
	return nil
}

func printHelp() {
	fmt.Printf(`fisherman — bootc disk installer backend

Usage:
  fisherman <recipe.json>          run an installation from a recipe file
  fisherman validate <recipe.json> validate a recipe without installing
  fisherman images [<query>]       list or search the image catalog
  fisherman scan <disk>            scan disk for Windows data available to migrate
  fisherman version                print version information
  fisherman help                   show this help

Options for 'images':
  --file <path>   use a specific images.json instead of auto-detecting
  --plain         plain text output (no ANSI color or tree characters)

Examples:
  fisherman /tmp/recipe.json
  fisherman validate /tmp/recipe.json
  fisherman images
  fisherman images Bluefin
  fisherman images "GNOME 50"
  fisherman images --plain yellowfin
  fisherman scan /dev/nvme0n1
`)
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help", "--help", "-h":
		printHelp()
		return
	case "version", "--version":
		fmt.Printf("fisherman %s\n", version)
		return
	case "images":
		runImages(os.Args[2:])
		return
	case "validate":
		runValidate(os.Args[2:])
		return
	case "scan":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: fisherman scan <disk>\n")
			os.Exit(1)
		}
		output, err := slurp.ScanJSON(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(output)
		return
	}

	r, err := recipe.Load(os.Args[1])
	if err != nil {
		fatal("loading recipe: %v", err)
	}
	if err := r.Validate(); err != nil {
		fatal("invalid recipe: %v", err)
	}

	// Recipe-level overrides for the otherwise-shared global mount paths.
	// Keeps two parallel installs on the same host from colliding.
	if r.TargetMount != "" {
		targetMount = r.TargetMount
	}
	if r.LuksMapperName != "" {
		luksMapper = r.LuksMapperName
	}

	// Log fisherman version for CI diagnostics
	fmt.Fprintf(os.Stderr, "[fisherman] version: %s\n", version)

	// Expand PATH to cover all standard sbin locations and any tools staged
	// alongside this binary (e.g. by the tuna-installer Flatpak).  pkexec
	// strips the calling user's PATH to a minimal safe set which often omits
	// /usr/sbin and /sbin on some immutable distros.
	expandPath()

	// Pre-flight: verify that every host tool required for this recipe is
	// present before we touch any disks.
	if err := checkRequiredTools(r); err != nil {
		fatal("missing required host tool: %v", err)
	}

	hasEncryption := r.Encryption.Type != "" && r.Encryption.Type != "none"
	hasTPM2 := r.Encryption.Type == "tpm2-luks" || r.Encryption.Type == "tpm2-luks-passphrase"
	isManual := len(r.CustomMounts) > 0
	isSystemdBoot := r.Bootloader == "systemd" || r.Filesystem == "zfs"

	// ── Pre-flight: check image cache ─────────────────────────────────────────
	var imageCheck install.ImageCheck
	if r.Image != "" {
		progress.Info("Checking image cache...")
		imageCheck = install.CheckImage(r.Image)
		if imageCheck.NeedsPull {
			progress.Info(fmt.Sprintf("Image pull required (%d layers)", imageCheck.LayerCount))
		} else if imageCheck.Offline {
			progress.Info("Offline: registry unreachable, using locally cached image")
		} else {
			progress.Info("Image already up to date in local cache")
		}
	}

	profile := buildProfile(imageCheck.NeedsPull, hasEncryption, hasTPM2, r.VarDisk != nil && !r.VarDisk.KeepExisting)
	pi := 0 // profile index, incremented at each progress.Step call

	// Compute total step count up front so the GUI can show accurate progress.
	// Manual layouts collapse the 4 auto disk-setup steps into a single step.
	totalSteps := 8
	if isManual {
		totalSteps -= 3 // partition + format EFI + format root collapse into one step
	}
	if hasEncryption && !isManual {
		totalSteps++ // extra step for LUKS setup (auto mode only)
	}
	if hasTPM2 {
		totalSteps++ // extra step for TPM2 enrolment (both tpm2-luks and tpm2-luks-passphrase)
	}
	hasVarDisk := r.VarDisk != nil
	if hasVarDisk && !r.VarDisk.KeepExisting {
		totalSteps++ // extra step to format the /var disk
	}
	step := 1

	// ── Immediate: Apply friendly audio names to live session ─────────────
	// Detect hardware, rename ugly ALSA names, hide S/PDIF etc. Takes effect
	// immediately via WirePlumber restart. Non-fatal.
	if err := post.ApplyAudioConfigLive(); err != nil {
		progress.Info(fmt.Sprintf("Live audio config skipped: %v", err))
	}

	// ── Pre-partition: Wallpaper slurp (easter egg) ──────────────────────────
	// Extract Windows wallpapers from any NTFS partition on the target disk
	// before partitioning destroys them. Held in RAM (/run). Entirely non-fatal.
	var wallpaperResult *slurp.WallpaperResult
	var dataResult *slurp.DataSlurpResult

	if r.Slurp != nil && !isManual {
		// Full data slurp: user selected specific categories in the GUI
		progress.Info("Migrating Windows user data before partitioning...")
		cfg := &slurp.SlurpConfig{
			SourcePartition: r.Slurp.SourcePartition,
		}
		for _, u := range r.Slurp.Users {
			cfg.Users = append(cfg.Users, slurp.SlurpUserConfig{
				Name:       u.Name,
				Categories: u.Categories,
			})
		}
		result, err := slurp.ExtractData(cfg)
		if err != nil {
			progress.Info(fmt.Sprintf("Data migration skipped: %v", err))
		} else {
			dataResult = result
		}
	} else if r.SlurpWallpapers && !isManual {
		// Wallpaper-only easter egg (no explicit slurp config)
		progress.Info("Checking for Windows wallpapers to migrate...")
		ntfsPartitions, err := slurp.DetectNTFS(r.Disk)
		if err != nil {
			progress.Info(fmt.Sprintf("NTFS detection skipped: %v", err))
		} else if len(ntfsPartitions) > 0 {
			progress.Info(fmt.Sprintf("Found %d NTFS partition(s), extracting wallpapers", len(ntfsPartitions)))
			for _, part := range ntfsPartitions {
				result, err := slurp.ExtractWallpapers(part)
				if err != nil {
					progress.Info(fmt.Sprintf("Wallpaper extraction from %s skipped: %v", part, err))
					continue
				}
				if result.Found {
					wallpaperResult = result
					break // take first successful extraction
				}
			}
		}
		if wallpaperResult == nil {
			progress.Info("No Windows wallpapers found — continuing normally")
		}
	}

	var activeTargetMount string
	var activeEfiPart string
	var activeRootPart string  // only used for TPM2 enrolment, empty in manual mode
	var activeRootPartNum int  // GPT number of the root partition, 0 in manual mode
	var activeLuksUUID string  // LUKS partition UUID for boot entry injection; empty if no encryption
	var rootPassphrase string  // what opens the root container; the /var one gets the same
	var luksRecoveryKey string // random passphrase for tpm2-luks (emitted as recovery key)

	// The encrypted /var, when the recipe asks for one: the device /var is
	// actually mounted from (the mapper), the container's LUKS UUID and the key
	// the installed system opens it with, written into the deployment's /etc
	// after the install.
	var activeVarMount string
	var varLuksUUID string
	var varKey []byte

	if isManual {
		// ── Step 1 (manual): Format and mount user-specified partitions ────────
		progress.Step(step, totalSteps, "Preparing disk", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		specs := make([]disk.MountSpec, 0, len(r.CustomMounts))
		for _, cm := range r.CustomMounts {
			specs = append(specs, disk.MountSpec{
				Partition: cm.Partition,
				Target:    cm.Target,
				Fstype:    cm.Fstype,
			})
		}

		var mountedPaths []string
		var applyErr error
		activeTargetMount, activeEfiPart, mountedPaths, applyErr = disk.ApplyCustomLayout(specs, targetMount)
		if applyErr != nil {
			fatal("manual disk layout: %v", applyErr)
		}
		for _, p := range mountedPaths {
			cleanup.AddMount(p)
		}
	} else {
		// ── Step 1: Partition disk ────────────────────────────────────────────
		progress.Step(step, totalSteps, "Partitioning disk", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		// A varDisk carrying a size is cut out of this disk, ahead of the root.
		varSize := ""
		if r.VarDisk != nil {
			varSize = r.VarDisk.Size
		}

		if r.Filesystem == "zfs" {
			if err := disk.PartitionZFS(r.Disk); err != nil {
				fatal("partitioning disk for ZFS: %v", err)
			}
		} else if isSystemdBoot {
			// systemd-boot always uses a 2-partition layout regardless of encryption.
			// LUKS (if requested) wraps the root; the FAT32 ESP stays unencrypted.
			if err := disk.PartitionSystemdBoot(r.Disk, varSize); err != nil {
				fatal("partitioning disk: %v", err)
			}
		} else if hasEncryption {
			if err := disk.PartitionEncrypted(r.Disk, varSize); err != nil {
				fatal("partitioning disk: %v", err)
			}
		} else {
			if err := disk.Partition(r.Disk, varSize); err != nil {
				fatal("partitioning disk: %v", err)
			}
		}

		var efiPart, bootPart, rootPart string
		partNum := 2
		if isSystemdBoot {
			// 2-partition layout: p1=EFI (1 GiB FAT32), p2=root (or ZFS pool).
			// No separate ext4 /boot needed — systemd-boot reads directly from
			// the FAT32 ESP. LUKS (if any) wraps the root.
			efiPart = disk.PartName(r.Disk, 1)
		} else {
			// 3-partition layout: p1=EFI, p2=/boot (ext4), p3=root.
			// The separate ext4 /boot keeps GRUB away from modern XFS features.
			efiPart = disk.PartName(r.Disk, 1)
			bootPart = disk.PartName(r.Disk, 2)
			partNum = 3
		}
		// A sized /var sits between them and the root, so the root moves down one.
		if varSize != "" {
			r.VarDisk.Disk = disk.PartName(r.Disk, partNum)
			partNum++
		}
		rootPart = disk.PartName(r.Disk, partNum)
		rootDev := rootPart // may be replaced by /dev/mapper/fisherman-root if LUKS
		activeRootPart = rootPart
		activeRootPartNum = partNum
		poolName := disk.PoolName(r.ZFSPoolName) // only used when r.Filesystem == "zfs"

		// ── Step 2: Format EFI ───────────────────────────────────────────────
		progress.Step(step, totalSteps, "Formatting EFI partition", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		if err := disk.FormatEFI(efiPart); err != nil {
			fatal("formatting EFI: %v", err)
		}
		// grub2 installs need a separate ext4 /boot so GRUB never has to parse
		// XFS (GRUB's built-in XFS driver lacks support for modern XFS features).
		// systemd-boot reads the FAT32 ESP directly, so no separate /boot needed.
		if !isSystemdBoot {
			if err := disk.FormatBoot(bootPart); err != nil {
				fatal("formatting /boot: %v", err)
			}
		}

		// ── Step 3: Disk encryption (optional) ──────────────────────────────
		if hasEncryption {
			progress.Step(step, totalSteps, "Setting up disk encryption", profile[pi].cumulativePct, profile[pi].weightPct)
			pi++
			step++

			var passphrase string
			switch r.Encryption.Type {
			case "luks-passphrase", "tpm2-luks-passphrase":
				passphrase = r.Encryption.Passphrase
			case "tpm2-luks":
				passphrase = luks.RandomPassphrase()
				luksRecoveryKey = passphrase // emitted later so user can write it down
				progress.Info("TPM2-LUKS: generated random recovery passphrase; TPM2 will be enrolled after install")
			}
			rootPassphrase = passphrase

			// A previous interrupted run may have left the mapper open. Close it
			// before formatting so luksFormat and luksOpen succeed cleanly.
			if _, err := os.Stat(luks.MapperPath(luksMapper)); err == nil {
				progress.Info(fmt.Sprintf("Closing stale mapper %s from previous run", luksMapper))
				_ = luks.Close(luksMapper)
			}

			if err := luks.Format(rootPart, passphrase); err != nil {
				fatal("LUKS format: %v", err)
			}
			if err := luks.Open(rootPart, passphrase, luksMapper); err != nil {
				fatal("LUKS open: %v", err)
			}
			cleanup.SetLUKS(luksMapper)
			rootDev = luks.MapperPath(luksMapper)
			activeLuksUUID = luks.UUID(rootPart)
		}

		// ── Step 4: Format root filesystem ──────────────────────────────────
		progress.Step(step, totalSteps, "Formatting root filesystem", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		if r.Filesystem == "zfs" {
			if err := disk.CreateZFSPool(poolName, rootPart, targetMount); err != nil {
				fatal("creating ZFS pool: %v", err)
			}
			if err := disk.CreateZFSRootDataset(poolName); err != nil {
				fatal("creating ZFS root dataset: %v", err)
			}
		} else {
			if err := disk.FormatRoot(rootDev, r.Filesystem); err != nil {
				fatal("formatting root filesystem: %v", err)
			}
		}

		// ── Step 5: Mount filesystem ─────────────────────────────────────────
		progress.Step(step, totalSteps, "Mounting filesystem", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		if err := os.MkdirAll(targetMount, 0o755); err != nil {
			fatal("creating mount point %s: %v", targetMount, err)
		}

		if r.Filesystem == "zfs" {
			// Pool is already imported with -R altroot; root dataset is already
			// mounted. Ensure the mount point exists and call MountZFSRoot in
			// case the automount didn't fire (e.g. in a container environment).
			if err := disk.MountZFSRoot(poolName, targetMount); err != nil {
				fatal("mounting ZFS root: %v", err)
			}
		} else if r.BtrfsSubvolumes {
			if err := disk.SetupBtrfsSubvolumes(rootDev, targetMount); err != nil {
				fatal("setting up btrfs subvolumes: %v", err)
			}
		} else {
			if err := disk.MountType(rootDev, targetMount, r.Filesystem, ""); err != nil {
				fatal("mounting root: %v", err)
			}
		}
		cleanup.AddMount(targetMount)

		// Mount the unencrypted /boot partition before the EFI partition.
		// bootupctl reads /boot's block device UUID from the raw partition.
		// Not needed for systemd-boot installs (no separate /boot partition).
		if !isSystemdBoot {
			if err := disk.MountBoot(targetMount, bootPart); err != nil {
				fatal("mounting /boot: %v", err)
			}
			cleanup.AddMount(targetMount + "/boot")
		}

		// Mount the EFI partition at /boot/efi inside the target.
		if err := disk.MountEFI(targetMount, efiPart); err != nil {
			fatal("mounting EFI: %v", err)
		}
		cleanup.AddMount(targetMount + "/boot/efi")

		activeTargetMount = targetMount
		activeEfiPart = efiPart
	}

	// ── Step 5.5: Mount /var disk (optional) ─────────────────────────────────
	// Must happen before bootc install so bootc populates /var on the right disk.
	if hasVarDisk {
		varDir := filepath.Join(activeTargetMount, "var")
		if err := os.MkdirAll(varDir, 0o755); err != nil {
			fatal("creating /var mount point: %v", err)
		}
		activeVarMount = r.VarDisk.Disk
		if r.VarDisk.Encrypt {
			progress.Step(step, totalSteps, "Encrypting data disk (/var)", profile[pi].cumulativePct, profile[pi].weightPct)
			pi++
			step++

			// The same passphrase in both headers: a reinstall that keeps the
			// data disk can open it before any key file exists, and one thing
			// is asked of the person. Only the auto path has a root
			// passphrase, which validation refuses an encrypted /var without.
			if rootPassphrase == "" {
				fatal("encrypting /var needs the root's passphrase, and this install path has none")
			}
			key := []byte(luks.RandomPassphrase())
			varMapperName := luksMapper + "-var"
			if _, err := os.Stat(luks.MapperPath(varMapperName)); err == nil {
				progress.Info(fmt.Sprintf("Closing stale mapper %s from previous run", varMapperName))
				_ = luks.Close(varMapperName)
			}
			if err := luks.Format(r.VarDisk.Disk, rootPassphrase); err != nil {
				fatal("LUKS format of the /var disk: %v", err)
			}
			if err := luks.AddKey(r.VarDisk.Disk, rootPassphrase, string(key)); err != nil {
				fatal("adding the /var key file slot: %v", err)
			}
			if err := luks.Open(r.VarDisk.Disk, string(key), varMapperName); err != nil {
				fatal("LUKS open of the /var disk: %v", err)
			}
			cleanup.AddLUKS(varMapperName)
			varLuksUUID = luks.UUID(r.VarDisk.Disk)
			if varLuksUUID == "" {
				fatal("reading the /var container's LUKS UUID: cryptsetup luksUUID said nothing")
			}
			varKey = key
			activeVarMount = luks.MapperPath(varMapperName)
			if err := disk.FormatVar(activeVarMount); err != nil {
				fatal("formatting /var disk: %v", err)
			}
		} else if !r.VarDisk.KeepExisting {
			progress.Step(step, totalSteps, "Formatting data disk (/var)", profile[pi].cumulativePct, profile[pi].weightPct)
			pi++
			step++
			if err := disk.FormatVar(r.VarDisk.Disk); err != nil {
				fatal("formatting /var disk: %v", err)
			}
		} else {
			progress.Info(fmt.Sprintf("Keeping existing data on /var disk %s", r.VarDisk.Disk))
		}
		if err := disk.Mount(activeVarMount, varDir, ""); err != nil {
			fatal("mounting /var disk: %v", err)
		}
		cleanup.AddMount(varDir)
		progress.Info(fmt.Sprintf("Mounted /var (%s) at /var", activeVarMount))
	}

	// Bind-mount a host-side scratch directory at /var/tmp so bootc has
	// disk-backed space for layer blobs. We deliberately use a path OUTSIDE
	// the target tree so bootc's "empty rootfs" check doesn't find stray
	// directories inside /mnt/fisherman-target.
	//
	// On installed (ostree/conventional) systems /var is always disk-backed,
	// so /var/fisherman-tmp gives us plenty of space. On live ISOs, however,
	// /var lives on a tmpfs that is far too small for multi-gigabyte image
	// blobs. Detect that case and place scratch on the already-formatted
	// target disk instead. A self-bind mount makes bootc's empty-rootdir
	// check see a mount point (which it tolerates) rather than a plain
	// directory (which it rejects).
	liveISO := isSpaceConstrained("/var") && activeTargetMount != ""
	scratchDir, err := prepareScratchDir(activeTargetMount, liveISO)
	if err != nil {
		fatal("preparing scratch dir: %v", err)
	}
	// Note: bootc container gets this directory mounted at /var/tmp via -v flag in podman call.
	// The container runs in its own mount namespace, so the host-level /var/tmp mount is not
	// necessary. We skip it here to avoid conflicts when /var/tmp is already a separate
	// filesystem on the host.
	//
	// For the live-ISO path scratchDir is on the target disk and removal is
	// handled by cleanup.AddPostRemoval (registered in prepareScratchDir),
	// which also fires on the fatal() error path. For the non-live path the
	// directory is /var/fisherman-tmp on the host and is cleaned up here
	// AND via cleanup.AddPostRemoval so it also fires on fatal() paths
	// (os.Exit bypasses defers).
	if !liveISO {
		cleanup.AddPostRemoval(scratchDir)
		defer os.RemoveAll(scratchDir)
	}

	// ── Step 6: Install OS ────────────────────────────────────────────────────
	progress.Step(step, totalSteps, "Installing OS", profile[pi].cumulativePct, profile[pi].weightPct)
	pi++
	step++

	// Only pass --target-imgref when it is non-empty and differs from the source.
	targetImgref := r.TargetImgref
	if targetImgref == r.Image {
		targetImgref = ""
	}

	// ZFS installs must use composefs-backend because bootc's ostree path checks
	// the filesystem type and rejects ZFS; composefs-native bypasses that check.
	composeFsBackend := r.ComposeFsBackend
	if r.Filesystem == "zfs" {
		composeFsBackend = true
	}

	if err := install.BootcInstall(install.Options{
		SourceImgref:          r.Image,
		TargetImgref:          targetImgref,
		SelinuxDisabled:       r.SelinuxDisabled,
		UnifiedStorage:        r.UnifiedStorage,
		ComposeFsBackend:      composeFsBackend,
		GenericImage:          r.GenericImage,
		Bootloader:            r.Bootloader,
		Target:                activeTargetMount,
		ScratchDir:            scratchDir,
		NeedsPull:             imageCheck.NeedsPull,
		LayerCount:            imageCheck.LayerCount,
		AdditionalImageStores: r.AdditionalImageStores,
	}); err != nil {
		fatal("bootc install: %v", err)
	}

	// systemd-boot composefs installs rely on GPT auto-discovery for the root
	// filesystem. Keep the auto-partitioned root on the architecture-specific
	// Linux root GUID so the installed system can find /sysroot on first boot.
	// An encrypted root needs this most: a sealed UKI carries its own command
	// line and has no BLS entry for `rd.luks.name`, so the generator opening
	// the container is the only way in. The `rd.luks` injection below may only
	// stand down where this ran, because it is what makes a UKI's root reachable.
	retagsRoot := !isManual && isSystemdBoot && r.ComposeFsBackend
	if retagsRoot {
		progress.Info("Retagging root partition for systemd GPT auto-discovery")

		// Ensure BOOTX64.EFI is on the ESP before we touch the mount stack.
		// Newer bootctl (e.g. arch-bootc systemd ≥ v255) enables --graceful when
		// running in a container and silently skips writing to the ESP. Copying
		// directly from the ostree deployment is a reliable fallback and a no-op
		// when bootctl ran correctly (EFI/BOOT/BOOTX64.EFI already present).
		if err := install.InstallSystemdBoot(activeTargetMount); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not ensure systemd-boot EFI binary: %v", err))
		}

		// Unmount the EFI partition explicitly so the FAT32 state is flushed to
		// the page cache before the root lazy-unmount below orphans the submount.
		if err := disk.UnmountPartition(r.Disk, 1); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not unmount EFI partition before retag: %v\n", err)
		}

		// Release kernel and userspace references to the root before modifying
		// its GPT type. bootc install may have left active references. The
		// container is opened again with the same key it was formatted with.
		passphrase := rootPassphrase
		mapperPath := ""
		if hasEncryption {
			mapperPath = luks.MapperPath(luksMapper)
		}
		if err := retagRoot(r.Disk, activeRootPart, activeRootPartNum, mapperPath, passphrase, activeTargetMount); err != nil {
			fatal("%v", err)
		}
		// Remount EFI so that Plymouth/LUKS arg writes land on the real ESP
		// instead of the empty /boot/efi directory in the XFS root.
		if err := disk.MountEFI(activeTargetMount, activeEfiPart); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not remount EFI partition after retag: %v\n", err)
		}
		// Remount /var for the same reason. /home is /var/home, so with the
		// device gone the user, flatpak and OEM writes below land on the root
		// filesystem and vanish behind the fstab mount at first boot.
		if hasVarDisk {
			if err := disk.Mount(activeVarMount, filepath.Join(activeTargetMount, "var"), ""); err != nil {
				fatal("remounting /var disk after retagging: %v", err)
			}
		}
	}

	// ── TPM2 enrolment ────────────────────────────────────────────────────────
	// Both tpm2-luks and tpm2-luks-passphrase add a TPM2 auto-unlock token so
	// the system boots without a passphrase prompt. The difference:
	//   tpm2-luks:            random passphrase (recovery key) + TPM2
	//   tpm2-luks-passphrase: user passphrase (fallback) + TPM2
	if hasTPM2 && activeRootPart != "" {
		progress.Step(step, totalSteps, "Enrolling TPM2 auto-unlock", profile[pi].cumulativePct, profile[pi].weightPct)
		pi++
		step++

		unlockPassphrase := rootPassphrase
		// Enroll TPM2 on the FIRST BOOT of the installed system, not here:
		// --tpm2-pcrs=7 seals against PCR 7 as measured in the live
		// installer, but the installed system boots a different chain and
		// measures a different PCR 7 — so an install-time enrollment can
		// never unseal on first boot. Staging a first-boot oneshot captures
		// the correct PCR 7. The recovery/passphrase key unlocks until then.
		if err := luks.StageFirstBootEnrollment(activeTargetMount, activeLuksUUID, unlockPassphrase); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not stage first-boot TPM2 enrollment (recovery key unlock still works): %v", err))
		} else {
			progress.Info("TPM2 auto-unlock will be enrolled on first boot")
		}

		// For tpm2-luks the user never chose a passphrase, so we emit the
		// random one as a recovery key they must save before rebooting.
		if luksRecoveryKey != "" {
			progress.RecoveryKey(luksRecoveryKey)
		}
	}

	// ── Step 7: Copy system flatpaks ──────────────────────────────────────────
	progress.Step(step, totalSteps, "Copying system Flatpaks", profile[pi].cumulativePct, profile[pi].weightPct)
	pi++
	step++

	if err := post.CopyFlatpaks(activeTargetMount, r.Flatpaks, r.FlatpakVarPath); err != nil {
		// Non-fatal — the system will work without pre-installed flatpaks.
		progress.Info(fmt.Sprintf("Warning: could not copy flatpaks: %v", err))
	}

	// ── Step 8: Post-install configuration ───────────────────────────────────
	progress.Step(step, totalSteps, "Configuring installed system", profile[pi].cumulativePct, profile[pi].weightPct)
	pi++
	step++

	progress.Info(fmt.Sprintf("Writing hostname: %s", r.Hostname))
	if err := post.WriteHostname(activeTargetMount, r.Hostname); err != nil {
		fatal("writing hostname: %v", err)
	}

	// Write /var fstab entry if a separate /var disk was used. Under LUKS the
	// UUID is the filesystem inside the mapper: the container is opened from
	// the crypttab entry below before the mount is attempted.
	if hasVarDisk {
		encrypted := varLuksUUID != ""
		varUUID := disk.UUID(activeVarMount)
		switch {
		case varUUID == "" && encrypted:
			// An opened container nothing mounts is a stranded volume, so the
			// two halves of the mechanism fail together.
			fatal("reading the /var filesystem UUID: blkid said nothing, and the machine would open a container nothing mounts")
		case varUUID == "":
			progress.Info(fmt.Sprintf("Warning: could not determine UUID for /var disk %s — skipping fstab entry", activeVarMount))
		default:
			if err := post.AppendFstabEntry(activeTargetMount, varUUID, "/var", "xfs", "defaults"); err != nil {
				if encrypted {
					fatal("writing the /var fstab entry: %v", err)
				}
				progress.Info(fmt.Sprintf("Warning: could not write /var fstab entry: %v", err))
			} else {
				progress.Info(fmt.Sprintf("Added /var fstab entry (UUID=%s)", varUUID))
			}
		}
		// The installed system opens the container itself, with the key file
		// the second slot was given, so nothing is typed for /var at boot.
		if encrypted {
			if err := post.InstallVarCrypt(activeTargetMount, "var", varLuksUUID, varKey); err != nil {
				fatal("installing the /var key file: %v", err)
			}
		}
	}

	// Create a user account if the recipe requests one (e.g. Bazzite has no OOBE).
	if r.User.Username != "" {
		progress.Info(fmt.Sprintf("Creating user: %s", r.User.Username))
		if err := post.CreateUser(activeTargetMount, post.UserConfig{
			Username: r.User.Username,
			Fullname: r.User.Fullname,
			Password: r.User.Password,
			Groups:   r.User.Groups,
		}); err != nil {
			fatal("creating user: %v", err)
		}
	}

	// Ensure rhgb and quiet are in every BLS loader entry so Plymouth shows
	// the graphical boot splash. Non-fatal: the system boots fine without it.
	n, err := post.EnsurePlymouthArgs(activeTargetMount)
	if err != nil {
		progress.Info(fmt.Sprintf("Warning: could not set Plymouth kernel args: %v", err))
	} else if n > 0 {
		progress.Info(fmt.Sprintf("Added Plymouth boot args to %d loader entr%s", n, map[bool]string{true: "y", false: "ies"}[n == 1]))
	}

	// Inject rd.luks.name=<UUID>=root into every BLS entry so the initrd
	// unlocks the LUKS container and maps it to /dev/mapper/root before
	// mounting the root filesystem. bootc install to-filesystem only sees the
	// open mapper device and never writes LUKS parameters itself.
	//
	// A sealed UKI is the exception: its command line is inside the signed PE
	// and the retag above leaves systemd-gpt-auto-generator to open the
	// container, so there is no entry to patch and none is needed.
	if activeLuksUUID != "" {
		if retagsRoot && post.HasUki(activeTargetMount) {
			progress.Info("Root unlocks through GPT auto-discovery; the sealed UKI carries no BLS entry to patch")
		} else if n, err := post.EnsureLuksArgs(activeTargetMount, activeLuksUUID); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not inject LUKS boot args: %v", err))
		} else if n > 0 {
			progress.Info(fmt.Sprintf("Injected rd.luks.name into %d boot entr%s", n, map[bool]string{true: "y", false: "ies"}[n == 1]))
		} else {
			progress.Info("Warning: no BLS loader entries to inject rd.luks.name into — an installed system that unlocks from the kernel command line will not boot")
		}
	}

	// Render the GRUB menu from the BLS entries, for an image whose GRUB
	// cannot read them itself. Last of the boot-entry steps deliberately: the
	// menu bakes each entry's `options` line into its `linux` command, so it
	// has to run after the Plymouth and LUKS arguments above are in place or
	// it would render a menu that boots without them. Non-fatal, and skipped
	// entirely by an image that ships no renderer.
	if rendered, err := post.RenderGrubMenu(activeTargetMount); err != nil {
		progress.Info(fmt.Sprintf("Warning: could not render GRUB menu: %v", err))
	} else if rendered {
		progress.Info("Rendered the GRUB menu from the BLS entries")
	}

	// Copy Bluetooth pairings from live session so paired keyboards/mice
	// reconnect on first boot without re-pairing. Non-fatal.
	if err := post.CopyBluetoothPairings(activeTargetMount); err != nil {
		progress.Info(fmt.Sprintf("Warning: could not copy Bluetooth pairings: %v", err))
	}

	// Copy WiFi connections from live session so network reconnects on first boot. Non-fatal.
	if err := post.CopyWiFiConnections(activeTargetMount); err != nil {
		progress.Info(fmt.Sprintf("Warning: could not copy WiFi connections: %v", err))
	}

	// Generate friendly audio device names and hide useless outputs (S/PDIF,
	// Pro Audio, monitor loopbacks). Writes WirePlumber rules to /etc/ so no
	// GNOME extensions are needed. Non-fatal.
	if err := post.GenerateAudioConfig(activeTargetMount); err != nil {
		progress.Info(fmt.Sprintf("Warning: could not configure audio devices: %v", err))
	}

	// Inject slurped Windows data into the installed system. Non-fatal.
	if dataResult != nil && dataResult.Found {
		composefs := post.IsComposeFsNativeExported(activeTargetMount)
		if err := slurp.InjectData(activeTargetMount, dataResult, composefs); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not inject user data: %v", err))
		}
	}
	if wallpaperResult != nil && wallpaperResult.Found {
		composefs := post.IsComposeFsNativeExported(activeTargetMount)
		if err := slurp.InjectWallpapers(activeTargetMount, wallpaperResult, composefs); err != nil {
			progress.Info(fmt.Sprintf("Warning: could not inject wallpapers: %v", err))
		}
	}
	// Cleanup scratch space (both data and wallpaper slurps use /run/fisherman-slurp)
	if dataResult != nil || wallpaperResult != nil {
		slurp.CleanupScratch()
	}

	// Pre-generate thumbnails for ALL wallpapers (system + user-injected) so
	// the GNOME wallpaper capplet opens instantly on first boot. Non-fatal.
	{
		composefs := post.IsComposeFsNativeExported(activeTargetMount)
		progress.Substep("Pre-generating wallpaper thumbnails")
		n := slurp.GenerateSystemThumbnails(activeTargetMount, composefs)
		if n > 0 {
			progress.Info(fmt.Sprintf("Pre-generated %d wallpaper thumbnail(s)", n))
		}
	}

	// Detect OEM hardware (ASUS, Framework) and queue vendor-specific packages
	// for first-login install via brew. Also enables required system services. Non-fatal.
	if err := post.InstallOEMPackages(activeTargetMount, r.DistroID, r.BrewTap); err != nil {
		progress.Info(fmt.Sprintf("Warning: OEM package setup: %v", err))
	}

	// Enable print auto-discovery services (cups-browsed, avahi-daemon, ipp-usb)
	// so USB and network printers are found on first boot without configuration.
	// Non-fatal: services are skipped if their unit files are absent from the image.
	post.EnablePrintServices(activeTargetMount)

	// Warm all system caches (fonts, icons, schemas, pixbuf, ldconfig, man-db,
	// flatpak appstream) so first boot is instant. Non-fatal.
	progress.Substep("Pre-warming system caches for first boot")
	post.WarmCaches(activeTargetMount)

	// ── Step 9: Finalize ─────────────────────────────────────────────────────
	// bootc's --skip-finalize kept the target writable for post-install writes.
	// Now replicate what bootc's finalize_filesystem() does internally:
	//   1. fstrim  — discard unused blocks (SSD optimization)
	//   2. remount ro — flush writeback, lock the deployment read-only
	//   3. fsfreeze/thaw — flush the journal for a clean first boot
	// ZFS handles this internally; fstrim/remount-ro/fsfreeze do not apply.
	progress.Step(step, totalSteps, "Finalizing installation", profile[pi].cumulativePct, profile[pi].weightPct)
	if r.Filesystem != "zfs" {
		if err := disk.FinalizeFilesystem(activeTargetMount); err != nil {
			fatal("finalizing target filesystem: %v", err)
		}
	}

	// ZFS post-install: write host ID and zpool.cache so the installed system
	// can import the pool at boot. Must be done before unmounting.
	if r.Filesystem == "zfs" {
		poolName := disk.PoolName(r.ZFSPoolName)
		progress.Info("ZFS post-install: writing hostid and zpool.cache")
		if err := disk.WriteHostID(activeTargetMount); err != nil {
			progress.Info(fmt.Sprintf("Warning: ZFS host ID: %v", err))
		}
		if err := disk.SetZFSCachefile(poolName, activeTargetMount); err != nil {
			progress.Info(fmt.Sprintf("Warning: ZFS cachefile: %v", err))
		}
	}

	// Tear down mounts and LUKS before declaring success.
	cleanup.Run()

	// Find the EFI boot entry so the frontend can set BootNext before rebooting.
	// Non-fatal: on VMs or systems without efibootmgr this may return empty.
	bootID, err := post.FindBootNextID(activeEfiPart)
	if err != nil {
		progress.Info(fmt.Sprintf("Warning: could not determine EFI boot entry: %v", err))
		bootID = ""
	} else if bootID != "" {
		progress.Info(fmt.Sprintf("EFI boot entry for installed system: Boot%s", bootID))
	}

	progress.Complete("Installation complete!", bootID)
}
