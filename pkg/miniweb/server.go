package miniweb

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"

	socks "github.com/armon/go-socks5"
	"github.com/jueckstock/miniweb/pkg/minica"
)

// Server encapsulates the inner state of a running miniweb server (ports, filesystem root, configurations, caches, etc.)
type Server struct {
	// Public information
	Config ServerConfig // Config is the initial configuration (ports, paths) used to initialize the server

	// Core internal state
	host net.IP      // host is the IP address on which we are listening for HTTP[S] requests (used to resolve DNS requests via SOCKS)
	tree contentTree // tree is the master tree of domains/doc-roots that we are serving

	// HTTPS/TLS supporting state
	issuer    *minica.Issuer              // issuer is our internal toy CA for signing TLS certs (using a self-generated toy CA cert/key)
	certCache map[string]*tls.Certificate // certCache is the in-memory map of TLS certs to use for DNS names
}

// Resolve a DNS name against the miniweb file tree
func (ws *Server) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	domain := ws.tree.domain(name)
	if domain == nil {
		return ctx, nil, fmt.Errorf("NXDOMAIN")
	}
	return ctx, ws.host, nil
}

// Rewrite an HTTP[S] request coming through SOCKS to target our local HTTP[S] server (or to a custom server, if a socks-rewriter is configured)
func (ws *Server) Rewrite(ctx context.Context, request *socks.Request) (context.Context, *socks.AddrSpec) {
	tree := ws.tree.domain(request.DestAddr.FQDN)
	if (tree != nil) && (tree.config.DefaultHandler.socksRewriter != nil) {
		// custom rewrite rule from the domain config
		return tree.config.DefaultHandler.socksRewriter.Rewrite(ctx, request)
	} else {
		// standard rewrite (handle with our special internal HTTP server and configured HTTP handler rules)
		newDest := &socks.AddrSpec{
			FQDN: request.DestAddr.FQDN,
			IP:   request.DestAddr.IP,
		}
		if request.DestAddr.Port == 443 {
			newDest.Port = ws.Config.HTTPSPort
		} else {
			newDest.Port = ws.Config.HTTPPort
		}
		return ctx, newDest
	}
}

// ServeHTTP responses from the miniweb file tree and/or configuration settings
func (ws *Server) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	domain := ws.tree.domain(req.Host)
	if domain == nil {
		log.Panicf("how did we accept a request for NXDOMAIN '%s'??", req.Host)
	}

	handler := domain.httpHandler(req)
	if handler == nil {
		log.Panicf("how are we missing a handler for '%s'??", req.URL.Path)
	}

	handler.ServeHTTP(writer, req)
}

// GetCert retrieves the TLS cert to use for a particular DNS name from the miniweb file tree/configuration
func (ws *Server) GetCert(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert, ok := ws.certCache[info.ServerName]
	if !ok {
		newCert, err := ws.issuer.Sign([]string{info.ServerName}, []string{ws.host.String()})
		if err != nil {
			log.Printf("unable to sign TLS cert for hostname '%s': %v", info.ServerName, err)
			return nil, err
		}
		cert = newCert
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
	tree, err := newContentTree(config.DataRoot)
	if err != nil {
		return fmt.Errorf("ListenAndServe(...): %w", err)
	}

	ws := &Server{
		Config:    config,
		host:      net.IPv4(127, 0, 0, 1),
		certCache: make(map[string]*tls.Certificate),
		tree:      tree,
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
		keyFileName := filepath.Join(config.DataRoot, "minica-key.pem")
		certFileName := filepath.Join(config.DataRoot, "minica.pem")
		ws.issuer, err = minica.GetIssuer(keyFileName, certFileName)
		if err != nil {
			log.Panicf("error initializing miniCA (required for HTTPS server support): %v", err)
		}
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
