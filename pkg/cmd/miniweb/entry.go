package miniweb

import (
	"flag"
	"fmt"

	lib "github.com/jueckstock/miniweb/pkg/miniweb"
)

// Main is the normal entry point for parsing command line arguments and running a miniweb server
func Main(args []string) {
	fs := flag.NewFlagSet("", flag.ExitOnError)

	var socksPort = fs.Int("p", 1080, "TCP port for SOCKS5 server")
	var caRoot = fs.String("c", "~/.miniweb", "directory for miniCA certs/keys")
	var wwwRoot = "."

	fs.Parse(args)
	if fs.NArg() == 1 {
		wwwRoot = fs.Arg(0)
	} else if fs.NArg() > 1 {
		fs.Usage()
	}

	err := lib.ListenAndServe(lib.ServerConfig{
		SOCKS5Addr: fmt.Sprintf("localhost:%d", *socksPort),
		CARoot:     *caRoot,
		MicroRoot:  wwwRoot,
	})
	if err != nil {
		panic(err)
	}
}
