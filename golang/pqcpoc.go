/*
 This is a trivial HTTPS server, whose only purpose is
 to serve PQC enabled TLS1.3 and report whether the
 client connected using X25519MLKEM768.

 Hastily slapped together by Jan Schaumann
 <jschauma@netmeister.org> in May 2025.

 This code is in the public domain.

 See this link for more information:
 https://www.netmeister.org/blog/pqc-pocs.html
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/sync/errgroup"
)

const LOGFILE = "/var/log/pqcpoc"
const HTTPS_PORT = 443
const HTTP_PORT = 80

/*
 * Global Variables
 */

var CERT = "/usr/local/pqc/certs/cert.pem"
var KEY = "/usr/local/pqc/certs/key.pem"

var curves = map[string]string{
	"23":   "CurveP256",
	"24":   "CurveP384",
	"25":   "CurveP521",
	"29":   "X25519",
	"4588": "X25519MLKEM768",
}

var (
	conns = make(map[string]struct {
		conn net.Conn
		cs   tls.ConnectionState
	})
	qconns = make(map[string]struct {
		conn quic.Connection
		cs   quic.ConnectionState
	})
	connsMu sync.Mutex
)

/*
 * Functions
 */

func GetConnInfo(r *http.Request) (tls.ConnectionState, bool) {
	qinfo, qok := qconns[r.RemoteAddr]
	if qok {
		return qinfo.cs.TLS, qok
	}

	info, ok := conns[r.RemoteAddr]
	if ok {
		return info.cs, ok
	}

	return tls.ConnectionState{}, false
}

/* This is fugly.  https://golang.google.cn/src/crypto/tls/common.go has
 * CurveID unexported as 'testingOnlyCurveID', so we extract it the stupid
 * way.  This will break as soon as Go changes the private members.
 *
 * Go 1.25 will expose the CurveId in the ConnectionState:
 * https://github.com/golang/go/commit/6bd5741a4c600ee9a48dfa5244f0c4116b718404
 */
func getNamedGroup(tlsInfo tls.ConnectionState) (curve string) {
	s := fmt.Sprintf("%v", tlsInfo)
	fields := strings.Split(s, " ")
	last := strings.TrimRight(fields[len(fields)-1], "}")

	curve = curves[last]

	return
}

/* As above... */
func wasHRR(tlsInfo tls.ConnectionState) (hrr bool) {
	s := fmt.Sprintf("%v", tlsInfo)
	fields := strings.Split(s, " ")
	wasHRR := strings.TrimRight(fields[len(fields)-2], "}")

	hrr, _ = strconv.ParseBool(wasHRR)

	return
}

func handler(w http.ResponseWriter, r *http.Request) {
	for name, values := range r.Header {
		if strings.EqualFold(name, "origin") {
			for _, value := range values {
				if strings.HasSuffix(value, ".pqc.dotwtf.wtf") {
					w.Header().Set("Access-Control-Allow-Origin", value)
					break
				}
			}
			break
		}
	}
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        w.Header().Set("Alt-Svc", fmt.Sprintf("h3=\":%d\",h2=\":%d\"", HTTPS_PORT, HTTPS_PORT))

	tlsInfo, ok := GetConnInfo(r)
	if !ok {
		http.Error(w, "Connection info not found", http.StatusInternalServerError)
		return
	}

	tlsVersion := tls.VersionName(tlsInfo.Version)
	tlsCipher := tls.CipherSuiteName(tlsInfo.CipherSuite)
	tlsNamedGroup := getNamedGroup(tlsInfo)
	tlsHRR := wasHRR(tlsInfo)

	log.Printf("%s \"%s %s %s\" - %s %s %s",
		r.RemoteAddr,
		r.Method, r.URL.Path, r.Proto,
		tlsVersion, tlsCipher, tlsNamedGroup)

	html := `<!DOCTYPE html>

<html lang="en">
  <head>
    <title>PQC PoC</title>
    <meta http-equiv="content-type" content= "text/html; charset=utf-8">
    <link rel="icon" href="data:,">
  </head>

  <body>
    <h1>PQC PoC</h1>
    <hr class="noshade" style="width:100%%;">
    <p>
      This site uses: go version go1.24.2 linux/amd64
    </p>
    <p>
      (See also: <code>host -t txt golang.pqc.dotwtf.wtf</code>)
    </p>
    <hr class="noshade" style="width:100%%;">
    <p>
      You appear to be using:
    </p>
    <p>
`
	fmt.Fprintf(w, html)
	fmt.Fprintf(w, "      HTTP Version: %s<br>\n", r.Proto)
	fmt.Fprintf(w, "      Protocol: %s<br>\n", tlsVersion)
	fmt.Fprintf(w, "      TLS HRR: %v<br>\n", tlsHRR)
	fmt.Fprintf(w, "      Cipher: %s<br>\n", tlsCipher)
	fmt.Fprintf(w, "      Named Group: %s<br>\n", tlsNamedGroup)

	html = `
    </p>
    <hr class="noshade" style="width:100%%;">
    <p>
      Also available:
      <ul>
        <li><a href="https://boringssl-nginx.pqc.dotwtf.wtf">https://boringssl-nginx.pqc.dotwtf.wtf</a></li>
        <li><a href="https://java-bc.pqc.dotwtf.wtf">https://java-bc.pqc.dotwtf.wtf</a></li>
        <li><a href="https://openssl-nginx.pqc.dotwtf.wtf">https://openssl-nginx.pqc.dotwtf.wtf</a></li>
        <li><a href="https://openssl-oqs-apache.pqc.dotwtf.wtf">https://openssl-oqs-apache.pqc.dotwtf.wtf</a></li>
        <li><a href="https://wolfssl-nginx.pqc.dotwtf.wtf">https://wolfssl-nginx.pqc.dotwtf.wtf</a></li>
      </ul>
    </p>
    <hr class="noshade" style="width:100%%;">
    <small>
    [<a href="https://www.netmeister.org/">homepage</a>]&nbsp;
    [<a href="mailto:jschauma@netmeister.org">jschauma@netmeister.org</a>]&nbsp;
    [<a href="https://mstdn.social/@jschauma/">@jschauma</a>]&nbsp;
    </small>
    <hr class="noshade" style="width:100%%;">
  </body>
</html>
`

	fmt.Fprintf(w, html)
}

func connContextHook(ctx context.Context, conn quic.Connection) context.Context {
	raddr := conn.RemoteAddr().String()
	connsMu.Lock()
	qconns[raddr] = struct {
		conn quic.Connection
		cs   quic.ConnectionState
	}{conn, conn.ConnectionState()}
	connsMu.Unlock()

	go func() {
		<-ctx.Done()
		connsMu.Lock()
		delete(qconns, raddr)
		connsMu.Unlock()
	}()

	return ctx
}

func connStateHook(conn net.Conn, state http.ConnState) {
	raddr := conn.RemoteAddr().String()
	switch state {
	case http.StateActive:
		if tlsConn, ok := conn.(*tls.Conn); ok {
			conns[raddr] = struct {
				conn net.Conn
				cs   tls.ConnectionState
			}{conn, tlsConn.ConnectionState()}
		}
	case http.StateClosed:
		delete(conns, raddr)
	}
}

func redirectHTTP(w http.ResponseWriter, r *http.Request) {
	s := ""
	if HTTPS_PORT != 443 {
		s = fmt.Sprintf(":%d", HTTPS_PORT)
	}
	dest := fmt.Sprintf("https://%s%s%s", r.Host, s, r.RequestURI)
	http.Redirect(w, r, dest, http.StatusMovedPermanently)
}

func main() {

	logFile, err := os.OpenFile(LOGFILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	tlsConfig := &tls.Config{
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.X25519,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1"},
	}

	listenAddress := fmt.Sprintf(":%d", HTTPS_PORT)

	tcpServer := &http.Server{
		Addr:      listenAddress,
		Handler:   http.HandlerFunc(handler),
		ConnState: connStateHook,
		TLSConfig: tlsConfig,
	}

	tlsConfig.NextProtos = []string{"h3"}

	h3server := &http3.Server{
		Addr:        listenAddress,
		Handler:     http.HandlerFunc(handler),
		ConnContext: connContextHook,
		TLSConfig:   http3.ConfigureTLSConfig(tlsConfig),
	}

	var eg errgroup.Group
	eg.Go(func() error {
		return tcpServer.ListenAndServeTLS(CERT, KEY)
	})
	eg.Go(func() error {
		return h3server.ListenAndServeTLS(CERT, KEY)
	})
	eg.Go(func() error {
		http.HandleFunc("/", redirectHTTP)
		return http.ListenAndServe(fmt.Sprintf(":%d", HTTP_PORT), nil)
	})

	if err := eg.Wait(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
