package main

import (
	"context"
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

const wdBufferLen = 8192

func main() {
	if len(os.Args) > 1 && os.Args[1] == "execer" {
		waitForDebugger("execer")
		mainExec()
	} else {
		waitForDebugger("monitor")
		mainMonitor()
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

func mainMonitor() {
	e := runMonitor()
	os.Exit(e)
}

func runMonitor() int {
	rand.Seed(time.Now().UnixNano())

	wd, err := os.Getwd()
	ep(err)
	tmpDir, err := os.MkdirTemp("", "sctest-")
	ep(err)
	defer os.Remove(tmpDir)
	ep(os.Chdir(tmpDir))

	notifyFD, exitChan := initializeMonitor(wd)
	defer syscall.Close(int(notifyFD))

	reqChan := make(chan *sc.ScmpNotifReq)
	reqCtx, cancelReqs := context.WithCancel(context.Background())
	go func() {
		for {
			req, err := sc.NotifReceive(notifyFD)
			if err != nil {
				select {
				case <-reqCtx.Done():
					break
				case <-time.After(500 * time.Millisecond):
					panic(err)
				}
			}
			reqChan <- req
		}
	}()

	println("Starting monitor")
	defer println("Monitor done")
	for {
		select {
		case execState := <-exitChan:
			cancelReqs()
			if execState.Signaled() {
				println("sig'd:", execState.Signal().String())
				signal.Reset()
				ep(syscall.Kill(os.Getpid(), execState.Signal()))
			} else if !execState.Exited() {
				ep(fmt.Errorf("Unexpected execer process state: Not signaled and not exited: %#v", execState))
			}
			return execState.ExitStatus()
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
			sc.NotifRespond(notifyFD, &sc.ScmpNotifResp{
				ID:    req.ID,
				Error: errno,
				Val:   0,
				Flags: flags,
			})
		}
	}
}

func initializeMonitor(wd string) (sc.ScmpFd, chan syscall.WaitStatus) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: "sock",
	})
	ep(err)
	defer listener.Close()

	selfExec, err := os.Executable()
	ep(err)
	execerCmd := exec.Command(selfExec, "execer")
	execerCmd.Stdout = os.Stdout
	execerCmd.Stdin = os.Stdin
	execerCmd.Stderr = os.Stderr
	exitChan := make(chan syscall.WaitStatus)
	go func() {
		execerCmd.Run()
		exitChan <- execerCmd.ProcessState.Sys().(syscall.WaitStatus)
		println("Execer done")
	}()
	println("Started execer")

	conn, err := listener.AcceptUnix()
	ep(err)
	defer conn.Close()

	wdBytes := []byte(wd)
	if len(wdBytes) > wdBufferLen {
		panic(fmt.Errorf("Working directory path too long (length=%d max=%d)", len(wdBytes), wdBufferLen))
	}
	n, oobn, err := conn.WriteMsgUnix(wdBytes, []byte{}, nil)
	ep(err)
	if n != len(wdBytes) || oobn != 0 {
		panic(fmt.Errorf("recvfd: incorrect number of bytes written (n=%d oobn=%d; wanted: n=%d oobn=0)", n, oobn, len(wdBytes)))
	}

	nfd, err := recieveFDFromUnixSocket(conn)
	ep(err)

	signal.Ignore(syscall.SIGINT)

	return sc.ScmpFd(nfd), exitChan
}

func mainExec() {
	initializeExec()
	ep(syscall.Exec("/usr/bin/fish", []string{}, os.Environ()))
}

func initializeExec() {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: "sock",
	})
	ep(err)
	defer conn.Close()

	wdBuffer := make([]byte, wdBufferLen)
	n, _, _, _, err := conn.ReadMsgUnix(wdBuffer, []byte{})
	ep(err)
	wd := string(wdBuffer[:n])
	ep(os.Chdir(wd))

	filter, err := sc.NewFilter(sc.ActAllow)
	ep(err)

	mkdir, err := sc.GetSyscallFromName("mkdir")
	ep(err)
	ep(filter.AddRule(mkdir, sc.ActNotify))

	ep(filter.Load())
	println("Loaded filter")

	nfd, err := filter.GetNotifFd()
	ep(err)
	ep(sendFDOverUnixSocket(conn, int(nfd)))
	ep(syscall.Close(int(nfd)))
	println("Closed FD")
}

var t int64 = time.Now().Unix()

func randomChoice() bool {
	return time.Now().Unix()-t > 5 && rand.Intn(2) == 1
}

func sendFDOverUnixSocket(conn *net.UnixConn, fd int) error {
	oob := syscall.UnixRights(fd)
	n, oobn, err := conn.WriteMsgUnix([]byte{}, oob, nil)
	if err != nil {
		return err
	}
	if n != 0 || oobn != len(oob) {
		return fmt.Errorf("sendmsg: incorrect number of bytes written (n=%d oobn=%d)", n, oobn)
	}
	return nil
}

func recieveFDFromUnixSocket(conn *net.UnixConn) (int, error) {
	MaxNameLen := 4096
	oobSpace := syscall.CmsgSpace(4)
	stateBuf := make([]byte, 4096)
	oob := make([]byte, oobSpace)

	n, oobn, _, _, err := conn.ReadMsgUnix(stateBuf, oob)
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
