package util

import (
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

var debuggerRE *regexp.Regexp = regexp.MustCompile("(?m)^TracerPid:\\s+[1-9]\\d*$")

// WaitForDebugger waits for a debugger to attach to the current
// process if enabled via the given keyword in the `SCT_DEBUG_WAIT`
// environment variable.
func WaitForDebugger(keyword string) {
	if strings.Contains(os.Getenv("SCT_DEBUG_WAIT"), keyword) {
		println("Waiting for debugger...")
		for !isBeingDebugged() {
			time.Sleep(250 * time.Millisecond)
		}
	}
}

func isBeingDebugged() bool {
	statusFile, err := os.Open("/proc/self/status")
	EP(err)
	statusBytes, err := io.ReadAll(statusFile)
	EP(err)
	return debuggerRE.Match(statusBytes)
}
