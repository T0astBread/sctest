package main

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	sc "github.com/seccomp/libseccomp-golang"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "monitor" {
		waitForDebugger("monitor")
		mainMonitor()
	} else {
		waitForDebugger("execer")
		mainExec()
	}
}

var debuggerRE *regexp.Regexp = regexp.MustCompile("(?m)^TracerPid:\\s+[1-9]\\d*$")

func waitForDebugger(keyword string) {
	if strings.Contains(os.Getenv("SCT_DEBUG_WAIT"), keyword) {
		println("Waiting for debugger...")
		for !isBeingDebugged() {
			time.Sleep(250 * time.Millisecond)
		}
	}
}

func isBeingDebugged() bool {
	statusFile, err := os.Open("/proc/self/status")
	ep(err)
	statusBytes, err := io.ReadAll(statusFile)
	ep(err)
	return debuggerRE.Match(statusBytes)
}

func mainExec() {
	os.Exit(runExec())
}

func runExec() int {
	cwd, err := os.Getwd()
	ep(err)
	tmpDir, err := os.MkdirTemp("", "sctest-")
	ep(err)
	defer os.Remove(tmpDir)
	ep(os.Chdir(tmpDir))

	cleanUpFilter := initializeFilter()
	defer cleanUpFilter()

	cmd := exec.Command("/usr/bin/fish")
	cmd.Dir = cwd
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return err.ExitCode()
		}
	}
	return 0
}

func initializeFilter() func() {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: "sock",
	})
	ep(err)
	defer listener.Close()

	selfExec, err := os.Executable()
	ep(err)
	monArgv := []string{selfExec, "monitor"}
	monPID, err := syscall.ForkExec(monArgv[0], monArgv, &syscall.ProcAttr{
		Env: os.Environ(),
		Files: []uintptr{
			os.Stdout.Fd(),
			os.Stdin.Fd(),
			os.Stderr.Fd(),
		},
	})
	ep(err)
	println("Started monitor", monPID)

	filter, err := sc.NewFilter(sc.ActAllow)
	ep(err)

	mkdir, err := sc.GetSyscallFromName("mkdir")
	ep(err)
	ep(filter.AddRule(mkdir, sc.ActNotify))

	conn, err := listener.AcceptUnix()
	ep(err)
	defer conn.Close()
	connFile, err := conn.File()
	ep(err)
	defer connFile.Close()

	ep(filter.Load())
	println("Loaded filter")

	nfd, err := filter.GetNotifFd()
	ep(err)
	ep(sendFDOverUnixSocket(int(connFile.Fd()), int(nfd)))
	ep(syscall.Close(int(nfd)))
	println("Closed FD")

	cleanup := func() {
		ep(syscall.Kill(monPID, syscall.SIGINT))
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(monPID, &ws, 0, &syscall.Rusage{})
		ep(err)
	}
	return cleanup
}

func mainMonitor() {
	rand.Seed(time.Now().UnixNano())

	notifyFD := recieveNotifyFD()
	defer syscall.Close(int(notifyFD))

	reqChan := make(chan *sc.ScmpNotifReq)
	go func() {
		for {
			req, err := sc.NotifReceive(notifyFD)
			ep(err)
			reqChan <- req
		}
	}()

	signalChan := make(chan os.Signal)
	signal.Notify(signalChan, syscall.SIGINT)

	println("Starting monitor")
notify:
	for {
		select {
		case <-signalChan:
			break notify
		case req := <-reqChan:
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
	println("Monitor done")
}

var t int64 = time.Now().Unix()

func randomChoice() bool {
	return time.Now().Unix()-t > 5 && rand.Intn(2) == 1
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
	defer connFile.Close()
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
