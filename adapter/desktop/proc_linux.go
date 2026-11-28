//go:build linux

package desktop

import (
	"os/exec"
	"syscall"
)

func configureCommand(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
}

func attachProcessControl(cmd *exec.Cmd) (killTree func(), cleanup func()) {
	if cmd == nil || cmd.Process == nil {
		return func() {}, func() {}
	}
	pgid := -cmd.Process.Pid
	killTree = func() {
		if syscall.Kill(pgid, syscall.SIGKILL) != nil {
			_ = cmd.Process.Kill()
		}
	}
	return killTree, func() {}
}
