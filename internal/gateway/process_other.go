//go:build !windows

package gateway

import "os/exec"

func attachChildLifetime(_ *exec.Cmd) {}
