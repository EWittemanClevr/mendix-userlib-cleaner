package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/faraga1/mendix-userlib-cleaner/internal/analysis"
)

// The manifest records where every file came from, so --restore can put it back.
const Manifest = "userlib-cleaner.json"

type manifest struct {
	AppDir string        `json:"appDir"`
	At     string        `json:"at"`
	Files  []string      `json:"files"`
	Plan   analysis.Plan `json:"plan"`
}

// CheckSafeToApply refuses when the app is open in Studio Pro or userlib/ has
// uncommitted changes (so the cleanup can always be undone with git).
func CheckSafeToApply(dir string) error {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(strings.ToLower(e.Name()), ".mpr.lock") {
			return fmt.Errorf("%s exists: the app looks open in Studio Pro. Close it first (or remove a stale lock after checking no Studio Pro runs)", e.Name())
		}
	}
	cmd := exec.Command("git", "-C", dir, "status", "--porcelain", "--", "userlib")
	hideWindow(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil // not a git checkout, or no git: nothing to check
	}
	if dirty := strings.TrimSpace(string(out)); dirty != "" {
		return fmt.Errorf("userlib/ has uncommitted changes; commit or revert them first so this cleanup can be undone with git:\n%s", dirty)
	}
	return nil
}

func move(from, to string) error {
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	// Different drive: copy, then delete.
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	out, err := os.Create(to)
	if err != nil {
		in.Close()
		return err
	}
	_, err = io.Copy(out, in)
	in.Close()
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Remove(from)
}

// Apply moves the given plan entries (jars + RequiredLib markers) to a backup folder next
// to the app folder and returns that folder.
func Apply(dir string, plan analysis.Plan, entries []analysis.PlanEntry) (string, error) {
	if len(entries) == 0 {
		return "", errors.New("nothing selected")
	}
	if err := CheckSafeToApply(dir); err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(dir)
	backup := fmt.Sprintf("%s-userlib-backup-%s", abs, time.Now().Format("20060102-150405"))
	var files []string
	for _, e := range entries {
		files = append(files, e.Path)
		files = append(files, e.Markers...)
	}
	var moved []string
	for _, f := range files {
		if err := move(filepath.Join(abs, filepath.FromSlash(f)), filepath.Join(backup, filepath.FromSlash(f))); err != nil {
			// Put back what was already moved, so the app is never left half-cleaned.
			for _, m := range moved {
				_ = move(filepath.Join(backup, filepath.FromSlash(m)), filepath.Join(abs, filepath.FromSlash(m)))
			}
			return "", fmt.Errorf("moving %s: %w (nothing was changed)", f, err)
		}
		moved = append(moved, f)
	}
	plan.Remove = entries
	m, _ := json.MarshalIndent(manifest{AppDir: abs, At: time.Now().UTC().Format(time.RFC3339), Files: files, Plan: plan}, "", "  ")
	return backup, os.WriteFile(filepath.Join(backup, Manifest), m, 0o644)
}

// Restore moves the files of a backup folder back into the app it came from.
func Restore(backup string) (appDir string, restored int, err error) {
	raw, err := os.ReadFile(filepath.Join(backup, Manifest))
	if err != nil {
		return "", 0, fmt.Errorf("%s has no %s: not a userlib cleaner backup", backup, Manifest)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", 0, err
	}
	for _, f := range m.Files {
		target := filepath.Join(m.AppDir, filepath.FromSlash(f))
		if _, err := os.Stat(target); err == nil {
			continue // already back
		}
		if err := move(filepath.Join(backup, filepath.FromSlash(f)), target); err != nil {
			return m.AppDir, restored, err
		}
		restored++
	}
	return m.AppDir, restored, nil
}

// FindBackups lists backup folders of this app (newest first).
func FindBackups(dir string) []string {
	abs, _ := filepath.Abs(dir)
	matches, _ := filepath.Glob(abs + "-userlib-backup-*")
	var out []string
	for i := len(matches) - 1; i >= 0; i-- {
		if _, err := os.Stat(filepath.Join(matches[i], Manifest)); err == nil {
			out = append(out, matches[i])
		}
	}
	return out
}
