//go:build unix && !android && !ios

package cftunnel

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

func launchProcess(cmd *exec.Cmd, writer *os.File) (processControl, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = writer, writer
	if err := cmd.Start(); err != nil {
		return processControl{}, err
	}
	group := -cmd.Process.Pid
	return processControl{
		wait: func() { _ = cmd.Wait() },
		stop: func(exited <-chan struct{}, grace time.Duration) {
			if syscall.Kill(group, syscall.SIGTERM) != nil {
				_ = cmd.Process.Kill()
				return
			}
			timer := time.NewTimer(grace)
			defer timer.Stop()
			select {
			case <-exited:
			case <-timer.C:
			}
			_ = syscall.Kill(group, syscall.SIGKILL)
		},
	}, nil
}
