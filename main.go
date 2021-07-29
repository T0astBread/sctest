package main

import (
	"math/rand"
	"os"
	"path"
	"time"

	sc "github.com/seccomp/libseccomp-golang"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	filter, err := sc.NewFilter(sc.ActAllow)
	ep(err)

	mkdir, err := sc.GetSyscallFromName("mkdirat")
	ep(err)
	ep(filter.AddRule(mkdir, sc.ActNotify))

	// ep(filter.ExportPFC(os.Stdout))
	ep(filter.Load())

	go func() {
		time.Sleep(1 * time.Second)
		println("MKDIR")
		cwd, err := os.Getwd()
		ep(err)
		p := path.Join(cwd, "test")
		// ep(syscall.Mkdir(path, 0))
		ep(os.Mkdir(p, os.ModePerm))
		println("MKDIR DONE")
	}()

	nfd, err := filter.GetNotifFd()
	ep(err)
	println("NFD", nfd)

	req, err := sc.NotifReceive(nfd)
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
	sc.NotifRespond(nfd, &sc.ScmpNotifResp{
		ID:    req.ID,
		Error: errno,
		Val:   0,
		Flags: flags,
	})

	time.Sleep(1 * time.Second)
}

func randomChoice() bool {
	return rand.Intn(2) == 1
}

func ep(err error) {
	if err != nil {
		panic(err)
	}
}
