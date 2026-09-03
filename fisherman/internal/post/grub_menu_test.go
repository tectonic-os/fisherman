package post

// The three outcomes RenderGrubMenu has: an image that ships a renderer runs
// it against the mounted target, an image that ships none is skipped without
// error, and a renderer that fails says so rather than reporting a render.

import (
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/tuna-os/fisherman/internal/runner"
)

// stubRun records every command and answers `ls`/`test` from a set of paths
// that are taken to exist, which is the whole of what RenderGrubMenu probes.
func stubRun(t *testing.T, exists map[string]bool, renderErr error) *[][]string {
	t.Helper()
	var calls [][]string
	orig := runner.RunFn
	t.Cleanup(func() { runner.RunFn = orig })
	runner.RunFn = func(_ io.Reader, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		switch name {
		case "ls":
			if exists[args[0]] {
				return nil
			}
			return errors.New("no such file or directory")
		case "test":
			if exists[args[1]] {
				return nil
			}
			return errors.New("not found")
		case "sh":
			return renderErr
		}
		return nil
	}
	return &calls
}

const target = "/mnt/fisherman-target"

var (
	deploy = filepath.Join(target, "state", "deploy", "abc123")
	script = filepath.Join(deploy, menuRenderer)
)

// composefsTarget makes isComposeFsNative say yes and pins the deploy root, so
// the test never depends on a real BLS entry or a real filesystem.
func composefsTarget(t *testing.T) map[string]bool {
	t.Helper()
	orig := ComposeFsDeployEtcDirFn
	t.Cleanup(func() { ComposeFsDeployEtcDirFn = orig })
	ComposeFsDeployEtcDirFn = func(string) (string, error) {
		return filepath.Join(deploy, "etc"), nil
	}
	return map[string]bool{filepath.Join(target, "state", "deploy"): true}
}

func TestRenderGrubMenuRunsTheImagesRenderer(t *testing.T) {
	exists := composefsTarget(t)
	exists[script] = true
	calls := stubRun(t, exists, nil)

	rendered, err := RenderGrubMenu(target)
	if err != nil || !rendered {
		t.Fatalf("rendered=%v err=%v, want true and no error", rendered, err)
	}

	// The renderer is run by the live environment's sh, from the deployment,
	// and takes the mounted target as its one argument. A render that passed
	// no target would silently write this machine's own menu instead.
	var ran []string
	for _, c := range *calls {
		if c[0] == "sh" {
			ran = c
		}
	}
	want := []string{"sh", script, target}
	if len(ran) != len(want) {
		t.Fatalf("sh call = %v, want %v", ran, want)
	}
	for i := range want {
		if ran[i] != want[i] {
			t.Fatalf("sh call = %v, want %v", ran, want)
		}
	}
}

// An image with no renderer is the Fedora target and every deb image built
// before the renderer existed. Guarded on the file and never on the family.
func TestRenderGrubMenuSkipsAnImageThatShipsNoRenderer(t *testing.T) {
	exists := composefsTarget(t)
	calls := stubRun(t, exists, nil)

	rendered, err := RenderGrubMenu(target)
	if err != nil {
		t.Fatalf("a missing renderer is not an error, got %v", err)
	}
	if rendered {
		t.Fatal("reported a render with no renderer to run")
	}
	for _, c := range *calls {
		if c[0] == "sh" {
			t.Fatalf("ran %v with no renderer present", c)
		}
	}
}

// A renderer that fails leaves an empty menu, so it has to be reported rather
// than counted as a render.
func TestRenderGrubMenuReportsAFailedRender(t *testing.T) {
	exists := composefsTarget(t)
	exists[script] = true
	stubRun(t, exists, errors.New("no usable BLS entry"))

	rendered, err := RenderGrubMenu(target)
	if err == nil {
		t.Fatal("a failed render reported no error")
	}
	if rendered {
		t.Fatal("a failed render reported a render")
	}
}
