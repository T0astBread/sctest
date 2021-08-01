package process

import (
	"net"
	"os"
	"syscall"

	sc "github.com/seccomp/libseccomp-golang"

	"t0ast.cc/sctest/util"
)

// RunExecer runs the "execer" process procedure and returns the exit
// status.
//
// Note that the execer uses `execve` so the process will be replaced
// and `RunExecer` will not return unless an error occurs.
func RunExecer() int {
	initializeExec()
	util.EP(syscall.Exec("/usr/bin/fish", []string{}, os.Environ()))
	return 0
}

func initializeExec() {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: "sock",
	})
	util.EP(err)
	defer conn.Close()

	wdBuffer := make([]byte, util.MaxMsgLen)
	n, _, _, _, err := conn.ReadMsgUnix(wdBuffer, []byte{})
	util.EP(err)
	wd := string(wdBuffer[:n])
	util.EP(os.Chdir(wd))

	filter, err := sc.NewFilter(sc.ActAllow)
	util.EP(err)

	mkdir, err := sc.GetSyscallFromName("mkdir")
	util.EP(err)
	util.EP(filter.AddRule(mkdir, sc.ActNotify))

	util.EP(filter.Load())
	println("Loaded filter")

	nfd, err := filter.GetNotifFd()
	util.EP(err)
	util.EP(util.SendFD(conn, int(nfd)))
	util.EP(syscall.Close(int(nfd)))
	println("Closed FD")
}
