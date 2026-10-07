package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/faraga1/mendix-userlib-cleaner/internal/analysis"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAndRestore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "App")
	write(t, filepath.Join(dir, "App.mpr"), "")
	write(t, filepath.Join(dir, "userlib", "old-1.0.jar"), "jar")
	write(t, filepath.Join(dir, "userlib", "old-1.0.jar.M.RequiredLib"), "")
	write(t, filepath.Join(dir, "userlib", "keep.jar"), "jar")
	entry := analysis.PlanEntry{Path: "userlib/old-1.0.jar", Tier: "safe", Markers: []string{"userlib/old-1.0.jar.M.RequiredLib"}}

	backup, err := Apply(dir, analysis.Plan{}, []analysis.PlanEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(backup), "App-userlib-backup-") {
		t.Errorf("backup folder %s should sit next to the app", backup)
	}
	for _, f := range []string{"userlib/old-1.0.jar", "userlib/old-1.0.jar.M.RequiredLib"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Errorf("%s should be moved out", f)
		}
		if _, err := os.Stat(filepath.Join(backup, f)); err != nil {
			t.Errorf("%s should be in the backup", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "userlib", "keep.jar")); err != nil {
		t.Error("unselected jar must stay")
	}
	if got := FindBackups(dir); len(got) != 1 || got[0] != backup {
		t.Errorf("FindBackups = %v", got)
	}

	appDir, n, err := Restore(backup)
	if err != nil || n != 2 || filepath.Clean(appDir) != filepath.Clean(mustAbs(dir)) {
		t.Fatalf("Restore = %s, %d, %v", appDir, n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "userlib", "old-1.0.jar")); err != nil {
		t.Error("jar should be back")
	}
}

func TestApplyRefusesWhileOpenInStudioPro(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "App.mpr.lock"), "")
	write(t, filepath.Join(dir, "userlib", "x.jar"), "jar")
	if _, err := Apply(dir, analysis.Plan{}, []analysis.PlanEntry{{Path: "userlib/x.jar"}}); err == nil || !strings.Contains(err.Error(), "Studio Pro") {
		t.Fatalf("expected a Studio Pro lock error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "userlib", "x.jar")); err != nil {
		t.Error("nothing may move when refused")
	}
}

func TestApplyRollsBackWhenAFileIsMissing(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "userlib", "a.jar"), "jar")
	_, err := Apply(dir, analysis.Plan{}, []analysis.PlanEntry{{Path: "userlib/a.jar"}, {Path: "userlib/missing.jar"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(filepath.Join(dir, "userlib", "a.jar")); err != nil {
		t.Error("a.jar should have been put back")
	}
}

func mustAbs(p string) string { a, _ := filepath.Abs(p); return a }
