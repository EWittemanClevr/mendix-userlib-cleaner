// Mendix userlib cleaner: finds jars in userlib/ that the app doesn't use and moves them
// to a backup folder next to the app. See README.md.
//
// Double-click (no arguments): a small window for the app folder the exe sits in.
// Command line:
//
//	userlib-cleaner <app folder>                       dry run (exit code 2 = something to remove)
//	userlib-cleaner <app folder> --apply [--include-orphans]
//	userlib-cleaner --restore <backup folder>
//	add --json for machine-readable output
package main

import (
	"encoding/json"

	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/EWittemanClevr/mendix-userlib-cleaner/internal/analysis"
	"github.com/EWittemanClevr/mendix-userlib-cleaner/internal/app"
)

var version = "dev" // set at build time: -ldflags "-X main.version=…"

func main() {
	if len(os.Args) == 1 {
		runGUI() // falls back to the console flow where there's no GUI (non-Windows)
		return
	}
	attachConsole()
	os.Exit(runCLI(os.Args[1:]))
}

// startDir: the folder the exe sits in, so it can be dropped into an app folder.
func startDir() string {
	if exe, err := os.Executable(); err == nil {
		if d := filepath.Dir(exe); app.FindMpr(d) != "" {
			return d
		}
	}
	if wd, err := os.Getwd(); err == nil && app.FindMpr(wd) != "" {
		return wd
	}
	return ""
}

type result struct {
	App      *app.App
	Libs     []*analysis.Lib
	Plan     analysis.Plan
	JavaRead int
}

func analyse(dir string, includeOrphans bool) (*result, error) {
	a, err := app.Read(dir)
	if err != nil {
		return nil, err
	}
	libs := analysis.Analyse(a.Input)
	return &result{App: a, Libs: libs, Plan: analysis.MakePlan(libs, a.Input.RequiredLibs, a.Sha256, includeOrphans)}, nil
}

func runCLI(args []string) int {
	fs := flag.NewFlagSet("userlib-cleaner", flag.ContinueOnError)
	apply := fs.Bool("apply", false, "move the jars out (default: dry run)")
	orphans := fs.Bool("include-orphans", false, "also move jars nothing refers to")
	asJSON := fs.Bool("json", false, "machine-readable output")
	restore := fs.String("restore", "", "put the files of this backup folder back")
	showVersion := fs.Bool("version", false, "print the version")
	// Accept the folder before or after the flags.
	var dir string
	var rest []string
	for _, a := range args {
		if dir == "" && len(a) > 0 && a[0] != '-' && (len(rest) == 0 || rest[len(rest)-1] != "--restore") {
			dir = a
			continue
		}
		rest = append(rest, a)
	}
	if err := fs.Parse(rest); err != nil {
		return 1
	}
	if *showVersion {
		fmt.Println("userlib-cleaner", version)
		return 0
	}
	if *restore != "" {
		appDir, n, err := app.Restore(*restore)
		if err != nil {
			fmt.Fprintln(os.Stderr, "userlib-cleaner:", err)
			return 1
		}
		fmt.Printf("Restored %d file(s) to %s\n", n, appDir)
		return 0
	}
	if dir == "" {
		dir = startDir()
	}
	if dir == "" {
		fmt.Fprintln(os.Stderr, "usage: userlib-cleaner <app folder> [--apply] [--include-orphans] [--json] | --restore <backup folder>")
		return 1
	}
	r, err := analyse(dir, *orphans)
	if err != nil {
		fmt.Fprintln(os.Stderr, "userlib-cleaner:", err)
		return 1
	}
	backup := ""
	if *apply && len(r.Plan.Remove) > 0 {
		if backup, err = app.Apply(dir, r.Plan, r.Plan.Remove); err != nil {
			fmt.Fprintln(os.Stderr, "userlib-cleaner:", err)
			return 1
		}
	}
	if *asJSON {
		abs, _ := filepath.Abs(dir)
		out := map[string]any{"app": map[string]any{"dir": abs, "mpr": r.App.MprFile, "mendixVersion": r.App.MendixVersion},
			"applied": *apply, "remove": r.Plan.Remove, "keep": r.Plan.Keep, "vendorlib": r.Plan.Vendorlib}
		if backup != "" {
			out["backupDir"] = backup
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		printPlan(r, *apply, *orphans)
		switch {
		case backup != "":
			fmt.Printf("\nBackup: %s\n", backup)
			fmt.Println("Next: clean deployment directory + run the app locally in Studio Pro, then review and commit.")
			fmt.Printf("Undo: userlib-cleaner --restore \"%s\"   (or: git checkout -- userlib)\n", backup)
		case len(r.Plan.Remove) > 0:
			fmt.Println("\nDry run: nothing changed. Add --apply to move these out (to a backup folder next to the app).")
		}
	}
	if !*apply && len(r.Plan.Remove) > 0 {
		return 2
	}
	return 0
}

var tierLabel = map[string]string{"safe": "SAFE  ", "check": "CHECK ", "orphan": "ORPHAN"}

func printPlan(r *result, applied, includeOrphans bool) {
	fmt.Printf("\n%s (Studio Pro %s): %d jars, %d Java files\n\n", r.App.MprFile, orQ(r.App.MendixVersion), len(r.App.Input.Jars), len(r.App.Input.JavaFiles))
	if len(r.Plan.Remove) > 0 {
		if applied {
			fmt.Println("Moved out of userlib:")
		} else {
			fmt.Println("Would remove from userlib:")
		}
		for _, e := range r.Plan.Remove {
			fmt.Printf("  %s %s\n         %s\n", tierLabel[e.Tier], e.Path, e.Why)
			if len(e.Markers) > 0 {
				fmt.Printf("         + %s\n", joinComma(e.Markers))
			}
		}
	} else {
		fmt.Println("Nothing to remove from userlib.")
	}
	if len(r.Plan.Keep) > 0 {
		fmt.Println("\nLeft alone (look at these yourself):")
		for _, k := range r.Plan.Keep {
			fmt.Printf("  %s %s\n         %s\n", tierLabel[k.Tier], k.Path, k.Why)
			if k.Tier == "orphan" {
				fmt.Println("         remove with --include-orphans, then test the app (reflection-only use isn't visible)")
			}
		}
	}
	if len(r.Plan.Vendorlib) > 0 {
		fmt.Println("\nvendorlib (managed by Studio Pro, not touched):")
		for _, v := range r.Plan.Vendorlib {
			fmt.Printf("  %s\n         %s\n         fix: %s\n", v.Path, v.Why, v.Fix)
		}
	}
}

func orQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
