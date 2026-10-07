//go:build !windows

package main

import "os"

// No window outside Windows: a double-click runs the dry run for the folder the binary sits in.
func runGUI()        { os.Exit(runCLI(nil)) }
func attachConsole() {}
