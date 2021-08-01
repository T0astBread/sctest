package util

import (
	"fmt"
	"net"
	"syscall"
)

// MaxMsgLen is the maximum length for messages sent over Unix
// sockets.
const MaxMsgLen = 8192

// SendFD sends the given file descriptor over the given UnixConn.
func SendFD(conn *net.UnixConn, fd int) error {
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

// RecieveFD recieves a file descriptor over the given UnixConn.
func RecieveFD(conn *net.UnixConn) (int, error) {
	oobSpace := syscall.CmsgSpace(4)
	stateBuf := make([]byte, MaxMsgLen)
	oob := make([]byte, oobSpace)

	n, oobn, _, _, err := conn.ReadMsgUnix(stateBuf, oob)
	if err != nil {
		return 0, err
	}
	if n >= MaxMsgLen || oobn != oobSpace {
		return 0, fmt.Errorf("recvfd: incorrect number of bytes read (n=%d oobn=%d)", n, oobn)
	}

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
