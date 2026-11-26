package cftunnel

import (
	"os"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const procThreadAttributeJobList = 0x0002000d

func launchProcess(cmd *exec.Cmd, writer *os.File) (processControl, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return processControl{}, err
	}
	process, err := createJobProcess(cmd, writer, job)
	if err != nil {
		_ = windows.CloseHandle(job)
		return processControl{}, err
	}
	return processControl{
		wait: func() {
			_, _ = windows.WaitForSingleObject(process, windows.INFINITE)
			_ = windows.CloseHandle(process)
		},
		stop: func(<-chan struct{}, time.Duration) { _ = windows.CloseHandle(job) },
	}, nil
}

func createJobProcess(cmd *exec.Cmd, writer *os.File, job windows.Handle) (windows.Handle, error) {
	var jobInfo windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	jobInfo.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&jobInfo)), uint32(unsafe.Sizeof(jobInfo))); err != nil {
		return 0, err
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		return 0, err
	}
	defer null.Close()
	input, err := inheritableHandle(null)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(input)
	output, err := inheritableHandle(writer)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(output)
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return 0, err
	}
	defer attrs.Delete()
	handles := [2]windows.Handle{input, output}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles), unsafe.Sizeof(handles)); err != nil {
		return 0, err
	}
	if err := attrs.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return 0, err
	}
	startup := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Flags: windows.STARTF_USESTDHANDLES, StdInput: input, StdOutput: output, StdErr: output,
		},
		ProcThreadAttributeList: attrs.List(),
	}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	binary, err := windows.UTF16PtrFromString(cmd.Path)
	if err != nil {
		return 0, err
	}
	args, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(cmd.Args))
	if err != nil {
		return 0, err
	}
	env := utf16.Encode([]rune(strings.Join(cmd.Environ(), "\x00") + "\x00\x00"))
	defer clear(env)
	var process windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if err := windows.CreateProcess(binary, args, nil, nil, true, flags, &env[0], nil, &startup.StartupInfo, &process); err != nil {
		return 0, err
	}
	_ = windows.CloseHandle(process.Thread)
	return process.Process, nil
}

func inheritableHandle(file *os.File) (windows.Handle, error) {
	current := windows.CurrentProcess()
	var handle windows.Handle
	err := windows.DuplicateHandle(current, windows.Handle(file.Fd()), current, &handle, 0, true, windows.DUPLICATE_SAME_ACCESS)
	return handle, err
}
