//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func sysProcAttrDetach() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true, // new session, fully detached on Unix
	}
}

func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = sysProcAttrDetach()
}
