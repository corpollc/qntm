package main

import (
	"fmt"
	"os"

	"github.com/corpo/qntm/cli"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z"
var version = "dev"

func main() {
	cli.SetVersion(version)
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}