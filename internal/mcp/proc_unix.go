//go:build !windows

package mcp

import (
	"os/exec"
	"syscall"
	"time"
)

// setupProc runs the command in its own process group and, on timeout, kills the
// whole group, so children it started do not survive or keep the output pipe open.
func setupProc(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	c.WaitDelay = 2 * time.Second
}
