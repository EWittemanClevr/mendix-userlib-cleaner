//go:build !windows

package app

import "os/exec"

func hideWindow(*exec.Cmd) {}
