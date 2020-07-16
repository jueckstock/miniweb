package miniweb

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"path"

	socks "github.com/armon/go-socks5"
)

// MiniwebHostname is the "magic" hostname which gives access to e.g., miniCA-root-cert download
const MiniwebHostname = "mini.web"

// Server encapsulates the inner state of a running miniweb server (ports, filesystem root, configurations, caches, etc.)
type Server struct {
	// Public information
	Config ServerConfig // Config is the initial configuration (ports, paths) used to initialize the server

	// Internal state
	host      net.IP                      // host is the IP address on which we are listening for HTTP[S] requests (used to resolve DNS requests via SOCKS)
	root      http.FileSystem             // root is the HTTP server FileSystem anchored at the miniweb file root
	certCache map[string]*tls.Certificate // certCache is the in-memory map of TLS certs to use for DNS names
}

// Resolve a DNS name against the miniweb file tree
func (ws *Server) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	log.Printf("resolving '%s' -> local proxy\n", name)
	if name != MiniwebHostname {
		dir, err := ws.root.Open(name)
		if err != nil {
			return ctx, nil, fmt.Errorf("NXDOMAIN")
		}
		defer dir.Close()
		stat, err := dir.Stat()
		if err != nil {
			return ctx, nil, err
		}
		if !stat.IsDir() {
			return ctx, nil, fmt.Errorf("invalid domain file type")
		}
	}
	return ctx, ws.host, nil
}

// Rewrite an HTTP[S] request coming through SOCKS to target our local HTTP[S] server
func (ws *Server) Rewrite(ctx context.Context, request *socks.Request) (context.Context, *socks.AddrSpec) {
	newDest := &socks.AddrSpec{
		FQDN: request.DestAddr.FQDN,
		IP:   request.DestAddr.IP,
	}
	if request.DestAddr.Port == 443 {
		newDest.Port = ws.Config.HTTPSPort
	} else {
		newDest.Port = ws.Config.HTTPPort
	}
	log.Printf("rewriting address '%s' -> '%s'\n", request.DestAddr, newDest)
	return ctx, newDest
}

// ServeHTTP responses from the miniweb file tree and/or configuration settings
func (ws *Server) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	log.Printf("request (Host: %s, Path: %s)", req.Host, req.URL.Path)

	if req.Host == MiniwebHostname {
		response := "hello, world!"
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("Content-Length", fmt.Sprintf("%d", len(response)))
		_, err := writer.Write([]byte(response))
		if err != nil {
			log.Printf("error streaming %s/%s: %v", MiniwebHostname, req.URL.Path, err)
		}
		return
	}

	reqPath := fmt.Sprintf("%s/%s", req.Host, req.URL.Path)
	file, err := ws.root.Open(reqPath)
	if err != nil {
		if os.IsNotExist(err) {
			writer.WriteHeader(404)
		} else {
			writer.WriteHeader(500)
			writer.Write([]byte(err.Error()))
		}
	} else {
		defer file.Close()
		mimeType := mime.TypeByExtension(path.Ext(req.URL.EscapedPath()))
		log.Printf("got MIME type '%s' for path '%s'", mimeType, req.URL.EscapedPath())
		writer.Header().Set("Content-Type", mimeType)

		if info, err := file.Stat(); err != nil {
			writer.WriteHeader(500)
			writer.Write([]byte(err.Error()))
		} else {
			writer.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
			_, err := io.Copy(writer, file)
			if err != nil {
				log.Printf("error streaming '%s': %v", reqPath, err)
			}
		}
	}
}

// GetCert retrieves the TLS cert to use for a particular DNS name from the miniweb file tree/configuration
func (ws *Server) GetCert(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, ok := ws.certCache[info.ServerName]
	if !ok {
		log.Printf("get-certificate for server name '%s'", info.ServerName)
		certFileName := fmt.Sprintf("%s/cert.pem", info.ServerName)
		file, err := ws.root.Open(certFileName)
		if err != nil {
			log.Printf("unable to open cert file '%s': %v", certFileName, err)
			return nil, err
		}
		certBlob, err := ioutil.ReadAll(file)
		if err != nil {
			log.Printf("unable to fully read cert file '%s': %v", certFileName, err)
			return nil, err
		}
		keyFileName := fmt.Sprintf("%s/key.pem", info.ServerName)
		file, err = ws.root.Open(keyFileName)
		if err != nil {
			log.Printf("unable to open key file '%s': %v", keyFileName, err)
			return nil, err
		}
		keyBlob, err := ioutil.ReadAll(file)
		if err != nil {
			log.Printf("unable to fully read key file '%s': %v", keyFileName, err)
			return nil, err
		}

		newCert, err := tls.X509KeyPair(certBlob, keyBlob)
		if err != nil {
			log.Printf("failed to parse/load certificate and/or key data: %v", err)
			return nil, err
		}

		cert = &newCert
		ws.certCache[info.ServerName] = cert

	}
	return cert, nil
}

// ServerConfig defines the operating parameters of a miniweb server: TCP ports to bind and filesystem root
type ServerConfig struct {
	HTTPPort   int    // HTTPPort is the TCP port (on localhost, exclusively) from which we will serve redirected HTTP requests
	HTTPSPort  int    // HTTPSPort is like HTTPPort but for redirected TLS connections
	SOCKS5Addr string // SOCKS5Port is the TCP endpoint at which we will accept SOCKS5 requests to resolve/redirect DNS names and HTTP[S] requests
	DataRoot   string // Full path to miniweb data store (top level directory names == DNS names, contents == HTTP[S] document root tree)
}

// ListenAndServe creates/runs a miniweb server until an error interrupts it
func ListenAndServe(config ServerConfig) error {
	ws := &Server{
		Config:    config,
		host:      net.IPv4(127, 0, 0, 1),
		root:      http.Dir(config.DataRoot),
		certCache: make(map[string]*tls.Certificate),
	}

	socksServer, err := socks.New(&socks.Config{
		Resolver: ws,
		Rewriter: ws,
	})
	if err != nil {
		return fmt.Errorf("socks.New(...) error: %w", err)
	}

	go func() {
		log.Printf("HTTP: listening on %s:%d, serving from %s\n", ws.host, config.HTTPPort, config.DataRoot)
		err = http.ListenAndServe(fmt.Sprintf("%s:%d", ws.host, config.HTTPPort), ws)
		if err != nil {
			log.Panicf("error listening/serving HTTP traffic: %v", err)
		}
	}()
	if config.HTTPSPort > 0 {
		go func() {
			log.Printf("HTTPS: listening on %s:%d, serving from %s\n", ws.host, config.HTTPSPort, config.DataRoot)
			srv := &http.Server{
				Addr:    fmt.Sprintf("%s:%d", ws.host, config.HTTPSPort),
				Handler: ws,
				TLSConfig: &tls.Config{
					GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
						return ws.GetCert(info)
					},
				},
			}
			err = srv.ListenAndServeTLS("", "")
			if err != nil {
				log.Panicf("error serving HTTPS traffic: %v", err)
			}
		}()
	}

	log.Printf("SOCKS: listening on %s\n", config.SOCKS5Addr)
	err = socksServer.ListenAndServe("tcp", config.SOCKS5Addr)
	if err != nil {
		return fmt.Errorf("socks.ListenAndServe(...) error: %w", err)
	}

	return nil
}
