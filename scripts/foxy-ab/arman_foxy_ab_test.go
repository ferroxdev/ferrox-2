package proxy

import (
	"net"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"
)

// abOpener is the SOCKS front's view of one arman MASQUE session: the same
// tunnelOpener the app's controller hands it, without the account plane.
type abOpener struct {
	open func(string) (net.Conn, error)
}

func (o abOpener) OpenTunnel(authority string) (net.Conn, error) { return o.open(authority) }

// TestFoxyAB runs arman's own h2/h3 CONNECT session behind its own SOCKS
// server for a same-server A/B against ferrox-app. It is a driver, not a
// test: it blocks until the process is killed.
func TestFoxyAB(t *testing.T) {
	token := os.Getenv("FOXY_AB_TOKEN")
	edge := os.Getenv("FOXY_AB_EDGE")
	if token == "" || edge == "" {
		t.Skip("FOXY_AB_TOKEN and FOXY_AB_EDGE are not set")
	}
	transport := os.Getenv("FOXY_AB_TRANSPORT")
	listen := os.Getenv("FOXY_AB_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	timeout := 10 * time.Second
	if v := os.Getenv("FOXY_AB_TIMEOUT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("FOXY_AB_IP_VERSION"); v != "" {
		SetUpstreamIPVersion(v)
	}
	u := &url.URL{Scheme: "https", Host: edge}
	if addr := os.Getenv("FOXY_AB_EDGE_ADDR"); addr != "" {
		noteRecommended(u, true)
		if err := SetEdge(addr); err != nil {
			t.Fatalf("pin edge %s: %v", addr, err)
		}
	}
	var opener abOpener
	switch transport {
	case "h3":
		s, err := newH3ProxySession(u, token, timeout)
		if err != nil {
			t.Fatalf("h3 session: %v", err)
		}
		defer s.Close()
		opener = abOpener{open: s.OpenTunnel}
	default:
		s, err := newH2ProxySession(u, token, timeout)
		if err != nil {
			t.Fatalf("h2 session: %v", err)
		}
		defer s.Close()
		opener = abOpener{open: s.OpenTunnel}
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatalf("listen %s: %v", listen, err)
	}
	if ready := os.Getenv("FOXY_AB_READY"); ready != "" {
		if err := os.WriteFile(ready, []byte(ln.Addr().String()), 0o600); err != nil {
			t.Fatalf("write ready: %v", err)
		}
	}
	ServeSOCKS(ln, NewSOCKSServer(opener, 10*time.Second, 2*time.Minute, 0))
}
