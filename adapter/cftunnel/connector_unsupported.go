//go:build !windows && (!unix || android || ios)

package cftunnel

import (
	"errors"
	"os"
	"os/exec"
)

func launchProcess(*exec.Cmd, *os.File) (processControl, error) {
	return processControl{}, errors.New("cftunnel: connector supervision unavailable on this platform")
}
