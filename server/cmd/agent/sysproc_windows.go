//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// sysProcAttrDetach returns SysProcAttr that detaches the child from the
// parent's console so it keeps running after the launcher exits.
func sysProcAttrDetach() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}

// setSysProcAttr applies detach attributes to the given command.
func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = sysProcAttrDetach()
}
