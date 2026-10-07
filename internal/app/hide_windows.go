package app

import (
	"os/exec"
	"syscall"
)

// hideWindow keeps `git` from flashing a console window when run from the GUI.
func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}
