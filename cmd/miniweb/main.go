package main

import (
	"os"

	cmd "github.com/jueckstock/miniweb/pkg/cmd/miniweb"
)

func main() {
	cmd.Main(os.Args[1:])
}
