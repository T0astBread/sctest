package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	sc "github.com/seccomp/libseccomp-golang"
)

func main() {
	if len(os.Args) > 0 && os.Args[0] == "monitor" {
		mainMonitor()
	} else {
		mainExec()
	}
}

func mainExec() {
	filter, err := sc.NewFilter(sc.ActAllow)
	ep(err)

	mkdir, err := sc.GetSyscallFromName("mkdir")
	ep(err)
	ep(filter.AddRule(mkdir, sc.ActNotify))

	ep(filter.Load())
	println("Loaded filter")

	nfd, err := filter.GetNotifFd()
	ep(err)

	continueGroup := sync.WaitGroup{}
	continueGroup.Add(1)

	go func() {
		listener, err := net.ListenUnix("unix", &net.UnixAddr{
			Name: "sock",
		})
		ep(err)
		defer listener.Close()

		conn, err := listener.AcceptUnix()
		ep(err)
		defer conn.Close()
		connFile, err := conn.File()
		ep(err)
		ep(sendFDOverUnixSocket(int(connFile.Fd()), int(nfd)))
		continueGroup.Done()
	}()

	selfExec, err := os.Executable()
	ep(err)
	monPID, err := syscall.ForkExec(selfExec, []string{"monitor"}, &syscall.ProcAttr{
		Files: []uintptr{
			os.Stdout.Fd(),
			os.Stdin.Fd(),
			os.Stderr.Fd(),
			uintptr(nfd),
		},
	})
	ep(err)
	println("Started monitor", monPID)

	continueGroup.Wait()

	ep(syscall.Close(int(nfd)))
	println("Closed FD")

	// fork exec
	pid, err := syscall.ForkExec("/usr/bin/fish", []string{}, &syscall.ProcAttr{
		Env: os.Environ(),
		Files: []uintptr{
			os.Stdout.Fd(),
			os.Stdin.Fd(),
			os.Stderr.Fd(),
		},
	})
	ep(err)
	println("Started process", pid)

	var ws syscall.WaitStatus
	syscall.Wait4(pid, &ws, 0, &syscall.Rusage{})
	println("Process exited")

	syscall.Kill(monPID, syscall.SIGINT)
	syscall.Wait4(monPID, &ws, 0, &syscall.Rusage{})
}

func mainMonitor() {
	rand.Seed(time.Now().UnixNano())

	notifyFD := recieveNotifyFD()

	println("Starting monitor")
	defer println("Monitor done")

	for {
		req, err := sc.NotifReceive(notifyFD)
		ep(err)
		println("RID", req.ID)

		var errno int32
		var flags uint32 = sc.NotifRespFlagContinue
		if randomChoice() {
			errno = 1
			flags = 0
			println("fail")
		} else {
			println("success")
		}
		// time.Sleep(5 * time.Second)
		sc.NotifRespond(notifyFD, &sc.ScmpNotifResp{
			ID:    req.ID,
			Error: errno,
			Val:   0,
			Flags: flags,
		})
	}
}

func randomChoice() bool {
	return rand.Intn(2) == 1
}

func sendFDOverUnixSocket(socketFD, fd int) error {
	oob := syscall.UnixRights(fd)
	return syscall.Sendmsg(socketFD, []byte{}, oob, nil, 0)
}

func recieveNotifyFD() sc.ScmpFd {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: "sock",
	})
	ep(err)
	defer conn.Close()
	connFile, err := conn.File()
	ep(err)
	nfd, err := recieveFDFromUnixSocket(int(connFile.Fd()))
	ep(err)

	return sc.ScmpFd(nfd)
}

func recieveFDFromUnixSocket(socketFD int) (int, error) {
	MaxNameLen := 4096
	oobSpace := syscall.CmsgSpace(4)
	stateBuf := make([]byte, 4096)
	oob := make([]byte, oobSpace)

	n, oobn, _, _, err := syscall.Recvmsg(socketFD, stateBuf, oob, 0)
	if err != nil {
		return 0, err
	}
	if n >= MaxNameLen || oobn != oobSpace {
		return 0, fmt.Errorf("recvfd: incorrect number of bytes read (n=%d oobn=%d)", n, oobn)
	}

	// Truncate.
	stateBuf = stateBuf[:n]
	oob = oob[:oobn]

	scms, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, err
	}
	if len(scms) != 1 {
		return 0, fmt.Errorf("recvfd: number of SCMs is not 1: %d", len(scms))
	}
	scm := scms[0]

	fds, err := syscall.ParseUnixRights(&scm)
	if err != nil {
		return 0, err
	}

	return fds[0], nil
}

func ep(err error) {
	if err != nil {
		panic(err)
	}
}
