package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const defaultNydusOverlayfsPath = "/usr/local/bin/nydus-overlayfs"

func main() {
	nydusOverlayfsPath := defaultNydusOverlayfsPath
	args := make([]string, 0, 4)
	options := make([]string, 0, len(os.Args))

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		if arg == "-t" && i+1 < len(os.Args) {
			if isNydusOverlayfs(os.Args[i+1]) {
				nydusOverlayfsPath = os.Args[i+1]
			}
			i++
			continue
		}

		if arg == "-o" && i+1 < len(os.Args) {
			appendOptions(&options, os.Args[i+1])
			i++
			continue
		}

		if strings.HasPrefix(arg, "-o=") {
			appendOptions(&options, strings.TrimPrefix(arg, "-o="))
			continue
		}

		args = append(args, arg)
	}

	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: mount.fuse <source> <target> -o <options> -t <nydus-overlayfs>\n")
		os.Exit(2)
	}

	argv := []string{
		nydusOverlayfsPath,
		args[0],
		args[1],
		"-o",
		strings.Join(options, ","),
	}

	if err := syscall.Exec(nydusOverlayfsPath, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "exec %s: %v\n", nydusOverlayfsPath, err)
		os.Exit(127)
	}
}

func appendOptions(options *[]string, optionString string) {
	for _, option := range strings.Split(optionString, ",") {
		option = strings.TrimSpace(option)
		if option != "" {
			*options = append(*options, option)
		}
	}
}

func isNydusOverlayfs(path string) bool {
	return filepath.Base(path) == "nydus-overlayfs"
}
