package miniweb

import (
	"flag"
	"fmt"

	lib "github.com/jueckstock/miniweb/pkg/miniweb"
)

// Main is the normal entry point for parsing command line arguments and running a miniweb server
func Main(args []string) {
	fs := flag.NewFlagSet("", flag.ExitOnError)

	var socksPort = fs.Int("socksPort", 1080, "TCP port for SOCKS5 server")
	var httpPort = fs.Int("httpPort", 8080, "TCP port for HTTP server")
	var httpsPort = fs.Int("httpsPort", -1, "TCP port for HTTPS server [no HTTPS if not specified]")
	var wwwRoot = fs.String("wwwRoot", ".", "root directory for serving domains/HTTP content")

	fs.Parse(args)

	err := lib.ListenAndServe(lib.ServerConfig{
		HTTPPort:   *httpPort,
		HTTPSPort:  *httpsPort,
		SOCKS5Addr: fmt.Sprintf("localhost:%d", *socksPort),
		DataRoot:   *wwwRoot,
	})
	if err != nil {
		panic(err)
	}
}
