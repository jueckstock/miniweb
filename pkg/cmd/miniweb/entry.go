package miniweb

import (
	"flag"
	"fmt"
	"time"

	lib "github.com/jueckstock/miniweb/pkg/miniweb"
)

// Main is the normal entry point for parsing command line arguments and running a miniweb server
func Main(args []string) {
	fs := flag.NewFlagSet("", flag.ExitOnError)

	var socksPort = fs.Int("socksPort", 1080, "TCP port for SOCKS5 server")
	var httpPort = fs.Int("httpPort", 8080, "TCP port for HTTP server")
	var httpsPort = fs.Int("httpsPort", -1, "TCP port for HTTPS server [no HTTPS if not specified]")
	var wwwRoot = fs.String("wwwRoot", ".", "root directory for serving domains/HTTP content")

	var browserStyle = fs.String("browser", "chromium", "what kind of browser is being launch (supported: 'chromium')")
	var browserExe = fs.String("exe", "", "run browser executable found at this path with SOCKS5 proxy settings")
	var browseURL = fs.String("url", "", "point launched browser at this URL")

	fs.Parse(args)

	if *browseURL != "" {
		go func() {
			time.Sleep(time.Second) // eeeek
			browser := lib.NewBrowser(*browserStyle, *browserExe, *socksPort)
			err := browser.Launch(*browseURL)
			if err != nil {
				panic(err)
			}
		}()
	}

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
