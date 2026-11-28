//go:build !windows && !unix

package desktop

import "os/exec"

func configureCommand(*exec.Cmd) {}

func attachProcessControl(cmd *exec.Cmd) (killTree func(), cleanup func()) {
	if cmd == nil || cmd.Process == nil {
		return func() {}, func() {}
	}
	return func() { _ = cmd.Process.Kill() }, func() {}
}
