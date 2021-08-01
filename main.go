package main

import (
	"os"

	"t0ast.cc/sctest/process"
	"t0ast.cc/sctest/util"
)

func main() {
	var role string
	var run func() int
	if len(os.Args) > 1 && os.Args[1] == "execer" {
		role = "execer"
		run = process.RunExecer
	} else {
		role = "monitor"
		run = process.RunMonitor
	}
	util.WaitForDebugger(role)
	os.Exit(run())
}
