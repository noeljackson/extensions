package main

import (
	"fmt"
	"os"
	"syscall"
)

const (
	qemuPath = "/usr/local/libexec/qemu-system-x86_64-snp-experimental"
	dataPath = "/usr/local/share/kata-qemu-snp-experimental/qemu"
)

func main() {
	argv := make([]string, 0, len(os.Args)+3)
	argv = append(argv, qemuPath, "-L", dataPath)
	argv = append(argv, os.Args[1:]...)

	if err := syscall.Exec(qemuPath, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "exec %s: %v\n", qemuPath, err)
		os.Exit(127)
	}
}
