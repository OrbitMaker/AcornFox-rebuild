package main

import (
	"io"
	"net"
	"os"
)

// net.FileConn duplicates the inherited socket into a close-on-exec descriptor.
// Closing the inherited original prevents detached workers from retaining the
// bootstrap lifecycle channel after the managed controller exits.
func adoptLifecycleFile(file *os.File) (io.ReadWriteCloser, error) {
	conn, err := net.FileConn(file)
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		conn.Close()
		return nil, closeErr
	}
	return conn, nil
}
