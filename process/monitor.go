package process

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	sc "github.com/seccomp/libseccomp-golang"

	"t0ast.cc/sctest/util"
)

// RunExecer runs the "monitor" process procedure and returns the
// exit status.
func RunMonitor() int {
	rand.Seed(time.Now().UnixNano())

	wd, err := os.Getwd()
	util.EP(err)
	tmpDir, err := os.MkdirTemp("", "sctest-")
	util.EP(err)
	defer os.Remove(tmpDir)
	util.EP(os.Chdir(tmpDir))

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
				util.EP(syscall.Kill(os.Getpid(), execState.Signal()))
			} else if !execState.Exited() {
				util.EP(fmt.Errorf("Unexpected execer process state: Not signaled and not exited: %#v", execState))
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
	util.EP(err)
	defer listener.Close()

	selfExec, err := os.Executable()
	util.EP(err)
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
	util.EP(err)
	defer conn.Close()

	wdBytes := []byte(wd)
	if len(wdBytes) > util.MaxMsgLen {
		panic(fmt.Errorf("Working directory path too long (length=%d max=%d)", len(wdBytes), util.MaxMsgLen))
	}
	n, oobn, err := conn.WriteMsgUnix(wdBytes, []byte{}, nil)
	util.EP(err)
	if n != len(wdBytes) || oobn != 0 {
		panic(fmt.Errorf("recvfd: incorrect number of bytes written (n=%d oobn=%d; wanted: n=%d oobn=0)", n, oobn, len(wdBytes)))
	}

	nfd, err := util.RecieveFD(conn)
	util.EP(err)

	signal.Ignore(syscall.SIGINT)

	return sc.ScmpFd(nfd), exitChan
}

var t int64 = time.Now().Unix()

func randomChoice() bool {
	return time.Now().Unix()-t > 5 && rand.Intn(2) == 1
}
