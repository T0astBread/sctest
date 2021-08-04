package util

import (
	"fmt"
	"os"
	"syscall"
)

// RedirectOutputs opens two files named "$path.stdout" and
// "$path.stderr" (where "$path" is the value given for path) and
// redirects the current processes stdio there.
//
// The current stdio files are duplicated to new file descriptors and
// those file descriptors returned.
func RedirectOutputs(path string) (prevOutFD, prevErrFD int, err error) {
	prevOutFD, newOut, err := openAndDupOutput(path, "out", 1)
	if err != nil {
		return 0, 0, err
	}
	prevErrFD, newErr, err := openAndDupOutput(path, "err", 2)
	if err != nil {
		return 0, 0, err
	}
	if err := switchOutput(os.Stdout, newOut); err != nil {
		return 0, 0, err
	}
	if err := switchOutput(os.Stderr, newErr); err != nil {
		return 0, 0, err
	}
	return prevOutFD, prevErrFD, nil
}

func openAndDupOutput(path string, channel string, channelFD int) (prevOutFD int, newOut *os.File, err error) {
	newOut, err = os.Create(fmt.Sprintf("%s.std%s", path, channel))
	if err != nil {
		return 0, nil, err
	}
	duppedPrevFD, err := syscall.Dup(channelFD)
	if err != nil {
		return 0, nil, err
	}
	return duppedPrevFD, newOut, nil
}

func switchOutput(channel, dst *os.File) error {
	return syscall.Dup2(int(dst.Fd()), int(channel.Fd()))
}
