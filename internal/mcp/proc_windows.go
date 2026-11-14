//go:build windows

package mcp

import (
	"os/exec"
	"time"
)

func setupProc(c *exec.Cmd) { c.WaitDelay = 2 * time.Second }
