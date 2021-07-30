package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path"
	"syscall"
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

	fmt.Printf("ARGS %#v\n", req.Data.Args)
	mkdirPath, err := readArgString(int64(req.Data.Args[1]))
	ep(err)
	println("PATH ARG", mkdirPath)

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

func readArgString(offset int64) (string, error) {
	buffer := make([]byte, 4096) // PATH_MAX

	memfd, err := syscall.Open("/proc/self/mem", syscall.O_RDONLY, 0o777)
	if err != nil {
		return "", err
	}
	defer syscall.Close(memfd)

	_, err = syscall.Pread(memfd, buffer, offset)
	if err != nil {
		return "", err
	}

	buffer[len(buffer)-1] = 0
	s := buffer[:bytes.IndexByte(buffer, 0)]
	return string(s), nil
}
