package miniweb

import (
	"fmt"
	"log"
	"os/exec"
)

// ErrUnknownBrowserKind indicates use of an unknown/unsupported browser family name
var ErrUnknownBrowserKind = fmt.Errorf("supported browser kinds are: 'chromium'")

// Browser is a launch structure for viewing proxied miniweb resource in a Web browser
type Browser struct {
	kind      string // e.g., "chromium", "firefox"
	exe       string // path to actual executable
	socksPort int    // SOCKS5 port on localhost to use for traffic proxying
}

// NewBrowser constructs a Browser for a given kind/exe path and with a given SOCKS5 port on localhost
func NewBrowser(kind, exe string, socksPort int) Browser {
	// TODO: auto-discover exe from kind if it's empty using platform defaults?
	return Browser{
		kind:      kind,
		exe:       exe,
		socksPort: socksPort,
	}
}

// Launch launches the given browser with the given SOCKS5 proxy, opening the given URL as the initial document
func (b *Browser) Launch(url string) error {
	switch b.kind {
	case "chromium":
		return b.launchChromium(url)
	default:
		return ErrUnknownBrowserKind
	}
}

func (b Browser) launchChromium(url string) error {
	args := make([]string, 0, 8)

	if b.socksPort > 0 {
		args = append(args,
			fmt.Sprintf(`--proxy-server=socks5://localhost:%d`, b.socksPort),
			`--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE localhost`,
		)
	}

	args = append(args, url)

	cmd := exec.Command(b.exe, args...)
	log.Println(cmd)

	return cmd.Start()
}
