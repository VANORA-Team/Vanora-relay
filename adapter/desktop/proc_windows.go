//go:build windows

package desktop

import (
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configureCommand(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NO_WINDOW
}

func attachProcessControl(cmd *exec.Cmd) (killTree func(), cleanup func()) {
	if cmd == nil || cmd.Process == nil {
		return func() {}, func() {}
	}
	var job windows.Handle
	if h, err := windows.CreateJobObject(nil, nil); err == nil {
		var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(
			h,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		); err == nil {
			proc, openErr := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
			if openErr == nil {
				assignErr := windows.AssignProcessToJobObject(h, proc)
				_ = windows.CloseHandle(proc)
				if assignErr == nil {
					job = h
				}
			}
		}
		if job == 0 {
			_ = windows.CloseHandle(h)
		}
	}
	var closeOnce sync.Once
	closeJob := func() {
		closeOnce.Do(func() {
			if job != 0 {
				_ = windows.CloseHandle(job)
			}
		})
	}
	killTree = func() {
		closeJob()
		_ = cmd.Process.Kill()
	}
	return killTree, closeJob
}
