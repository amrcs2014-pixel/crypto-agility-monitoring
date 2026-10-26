// tlslab: server and Go-stack client for the Paper B testbed.
//
//	tlslab echgen  -out DIR                         ECH key + ECHConfigList (base64) for public name public.example.test
//	tlslab server  -cert C -key K [-ech DIR] [-quic] -addr :443
//	tlslab client  -profile P -target IP -kx classical|hybrid [-ech DIR] [-quic] -ca CA -dur S -seed N
//
// Every behaviour runs only against this lab's own server inside the emulated network.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const sni = "www.example.test"
const publicName = "public.example.test"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: tlslab echgen|server|client ...")
	}
	switch os.Args[1] {
	case "echgen":
		echgen(os.Args[2:])
	case "echimport":
		echimport(os.Args[2:])
	case "server":
		server(os.Args[2:])
	case "client":
		client(os.Args[2:])
	default:
		log.Fatal("unknown command")
	}
}

// ---------------------------------------------------------------- ECH keys
func echgen(args []string) {
	fs := flag.NewFlagSet("echgen", flag.ExitOnError)
	out := fs.String("out", ".", "output dir")
	fs.Parse(args)
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cfg := echConfig(7, k.PublicKey().Bytes())
	list := make([]byte, 2+len(cfg))
	binary.BigEndian.PutUint16(list, uint16(len(cfg)))
	copy(list[2:], cfg)
	os.MkdirAll(*out, 0o755)
	os.WriteFile(filepath.Join(*out, "ech_config.bin"), cfg, 0o644)
	os.WriteFile(filepath.Join(*out, "ech_key.bin"), k.Bytes(), 0o600)
	os.WriteFile(filepath.Join(*out, "ech_configlist.b64"), []byte(base64.StdEncoding.EncodeToString(list)), 0o644)
	fmt.Println("ECHConfigList bytes:", len(list))
}

// echimport converts an OpenSSL "openssl ech" PEM (X25519 PKCS#8 key + ECHConfigList) into the
// files the Go server and both clients use, so every stack shares one ECH configuration.
func echimport(args []string) {
	fs := flag.NewFlagSet("echimport", flag.ExitOnError)
	in := fs.String("in", "ech.pem", "")
	out := fs.String("out", ".", "")
	fs.Parse(args)
	raw, err := os.ReadFile(*in)
	if err != nil {
		log.Fatal(err)
	}
	var key, list []byte
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			break
		}
		switch b.Type {
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			key = k.(*ecdh.PrivateKey).Bytes()
		case "ECHCONFIG":
			list = b.Bytes
		}
	}
	if key == nil || len(list) < 4 {
		log.Fatal("ech pem incomplete")
	}
	n := int(binary.BigEndian.Uint16(list))
	os.MkdirAll(*out, 0o755)
	os.WriteFile(filepath.Join(*out, "ech_config.bin"), list[2:2+n], 0o644)
	os.WriteFile(filepath.Join(*out, "ech_key.bin"), key, 0o600)
	os.WriteFile(filepath.Join(*out, "ech_configlist.b64"), []byte(base64.StdEncoding.EncodeToString(list)), 0o644)
	fmt.Println("imported ECHConfigList bytes:", len(list))
}

// draft-ietf-tls-esni ECHConfig, version 0xfe0d, KEM X25519 (0x0020), HKDF-SHA256 / AES-128-GCM
func echConfig(id uint8, pub []byte) []byte {
	var c bytes.Buffer
	c.WriteByte(id)
	binary.Write(&c, binary.BigEndian, uint16(0x0020))
	binary.Write(&c, binary.BigEndian, uint16(len(pub)))
	c.Write(pub)
	binary.Write(&c, binary.BigEndian, uint16(4))
	binary.Write(&c, binary.BigEndian, uint16(0x0001))
	binary.Write(&c, binary.BigEndian, uint16(0x0001))
	c.WriteByte(0) // maximum_name_length
	c.WriteByte(uint8(len(publicName)))
	c.WriteString(publicName)
	binary.Write(&c, binary.BigEndian, uint16(0)) // extensions
	var o bytes.Buffer
	binary.Write(&o, binary.BigEndian, uint16(0xfe0d))
	binary.Write(&o, binary.BigEndian, uint16(c.Len()))
	o.Write(c.Bytes())
	return o.Bytes()
}

// ---------------------------------------------------------------- server
func handler() http.Handler {
	mux := http.NewServeMux()
	blob := make([]byte, 16<<20)
	rand.Read(blob)
	mux.HandleFunc("/obj", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n <= 0 || n > len(blob) {
			n = 1024
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(blob[:n])
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "{\"received\":%d}", n)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("{\"ok\":false}"))
	})
	mux.HandleFunc("/beacon", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "{\"t\":%d,\"task\":\"none\"}", time.Now().Unix())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(blob[:12000])
	})
	return mux
}

func server(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cert := fs.String("cert", "", "")
	key := fs.String("key", "", "")
	ech := fs.String("ech", "", "ECH key dir (enables ECH)")
	addr := fs.String("addr", ":443", "")
	useQuic := fs.Bool("quic", false, "also serve HTTP/3 on the same UDP port")
	fs.Parse(args)
	c, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		log.Fatal(err)
	}
	// server keeps Go's default group preferences (X25519MLKEM768 first, then X25519, P-256, ...)
	cfg := &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13}
	if *ech != "" {
		ec, _ := os.ReadFile(filepath.Join(*ech, "ech_config.bin"))
		ek, _ := os.ReadFile(filepath.Join(*ech, "ech_key.bin"))
		cfg.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: ec, PrivateKey: ek, SendAsRetry: true}}
	}
	h := handler()
	if *useQuic {
		qs := &http3.Server{Addr: *addr, Handler: h, TLSConfig: http3.ConfigureTLSConfig(cfg.Clone())}
		go func() { log.Fatal(qs.ListenAndServe()) }()
	}
	cfg.NextProtos = []string{"http/1.1"}
	srv := &http.Server{Addr: *addr, Handler: h, TLSConfig: cfg, IdleTimeout: 60 * time.Second}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// ---------------------------------------------------------------- client
type cl struct {
	target, kx, ech, ca string
	quic                bool
	rng                 *mrand.Rand
	tcfg                *tls.Config
	n, errs             int
	oneShot             bool // a new connection per request (many_short, beacon, brute)
}

func (c *cl) tlsConfig() *tls.Config {
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(c.ca)
	if err != nil {
		log.Fatal(err)
	}
	pool.AppendCertsFromPEM(pem)
	cfg := &tls.Config{ServerName: sni, RootCAs: pool, MinVersion: tls.VersionTLS13}
	if c.kx == "classical" { // pre-migration default (Go <= 1.22): no hybrid group
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	} // hybrid: Go 1.27 default list, X25519MLKEM768 first (key shares for X25519MLKEM768 and X25519)
	if c.ech != "" {
		b, _ := os.ReadFile(filepath.Join(c.ech, "ech_configlist.b64"))
		l, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			log.Fatal(err)
		}
		cfg.EncryptedClientHelloConfigList = l
	}
	return cfg
}

func (c *cl) httpClient(keepAlive bool) *http.Client {
	if c.quic {
		t := &http3.Transport{TLSClientConfig: c.tcfg.Clone(), QUICConfig: &quic.Config{},
			Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
				return quic.DialAddrEarly(ctx, net.JoinHostPort(c.target, "443"), tc, qc) // no DNS in the lab
			}}
		return &http.Client{Transport: t, Timeout: 60 * time.Second}
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	t := &http.Transport{
		DialContext: func(ctx context.Context, n, a string) (net.Conn, error) {
			return d.DialContext(ctx, n, net.JoinHostPort(c.target, "443"))
		},
		TLSClientConfig: c.tcfg.Clone(), DisableKeepAlives: !keepAlive, MaxConnsPerHost: 4,
		ForceAttemptHTTP2: false, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	t.TLSClientConfig.NextProtos = []string{"http/1.1"}
	return &http.Client{Transport: t, Timeout: 60 * time.Second}
}

// fresh returns a one-shot HTTP/3 client for profiles that open a new connection per request
// (http3 reuses connections even without keep-alive); for TCP the passed client already disables keep-alive.
func (c *cl) fresh(h *http.Client, keepAlive bool) (*http.Client, func()) {
	if c.quic && !keepAlive {
		n := c.httpClient(true)
		return n, func() { n.Transport.(*http3.Transport).Close() }
	}
	return h, func() {}
}

func (c *cl) get(h *http.Client, path string) {
	if c.oneShot {
		var done func()
		h, done = c.fresh(h, false)
		defer done()
	}
	r, err := h.Get("https://" + sni + path) // www.example.test resolves to the server via /etc/hosts
	c.n++
	if err != nil {
		c.errs++
		log.Println("get:", err)
		return
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
}

func (c *cl) post(h *http.Client, path string, body []byte, ctype string) {
	if c.oneShot {
		var done func()
		h, done = c.fresh(h, false)
		defer done()
	}
	r, err := h.Post("https://"+sni+path, ctype, bytes.NewReader(body))
	c.n++
	if err != nil {
		c.errs++
		log.Println("post:", err)
		return
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
}

func (c *cl) sleep(lo, hi float64) {
	time.Sleep(time.Duration((lo + c.rng.Float64()*(hi-lo)) * float64(time.Second)))
}

func (c *cl) size(median float64) int {
	return int(median * (0.25 + 1.5*c.rng.Float64()))
}

func client(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	c := &cl{}
	prof := fs.String("profile", "web_page", "")
	fs.StringVar(&c.target, "target", "10.0.0.1", "")
	fs.StringVar(&c.kx, "kx", "hybrid", "")
	fs.StringVar(&c.ech, "ech", "", "")
	fs.StringVar(&c.ca, "ca", "", "")
	fs.BoolVar(&c.quic, "quic", false, "")
	dur := fs.Float64("dur", 20, "seconds")
	seed := fs.Int64("seed", 1, "")
	fs.Parse(args)
	c.rng = mrand.New(mrand.NewSource(*seed))
	c.tcfg = c.tlsConfig()
	end := time.Now().Add(time.Duration(*dur * float64(time.Second)))
	switch *prof {
	case "web_page": // page + 6-14 objects over up to 4 keep-alive connections, think time between pages
		h := c.httpClient(true)
		for time.Now().Before(end) {
			c.get(h, "/")
			k := 6 + c.rng.Intn(9)
			done := make(chan bool, k)
			for i := 0; i < k; i++ {
				n := c.size(9000)
				go func() { c.get(h, "/obj?n="+strconv.Itoa(n)); done <- true }()
			}
			for i := 0; i < k; i++ {
				<-done
			}
			c.sleep(2, 5)
		}
	case "api_poll": // one persistent connection, small JSON-sized responses every 1-3 s
		h := c.httpClient(true)
		for time.Now().Before(end) {
			c.get(h, "/obj?n="+strconv.Itoa(c.size(900)))
			c.sleep(1, 3)
		}
	case "download":
		h := c.httpClient(true)
		c.get(h, "/obj?n="+strconv.Itoa(c.size(5<<20)))
	case "upload":
		h := c.httpClient(true)
		b := make([]byte, c.size(2<<20))
		c.rng.Read(b)
		c.post(h, "/upload", b, "application/octet-stream")
	case "video": // segment every 2 s on a persistent connection
		h := c.httpClient(true)
		for time.Now().Before(end) {
			c.get(h, "/obj?n="+strconv.Itoa(c.size(400000)))
			c.sleep(1.8, 2.2)
		}
	case "many_short": // a new connection for each small object
		c.oneShot = true
		h := c.httpClient(false)
		for time.Now().Before(end) {
			c.get(h, "/obj?n="+strconv.Itoa(c.size(3000)))
			c.sleep(0.3, 1.2)
		}
	case "beacon": // periodic check-in on a fresh connection, 5 s +-20 %
		c.oneShot = true
		h := c.httpClient(false)
		for time.Now().Before(end) {
			c.get(h, "/beacon?id="+strconv.Itoa(c.rng.Intn(1<<20)))
			c.sleep(4, 6)
		}
	case "brute": // credential guessing against the lab's own /login, fresh connection per attempt
		c.oneShot = true
		h := c.httpClient(false)
		for time.Now().Before(end) {
			f := url.Values{"user": {"admin"}, "password": {fmt.Sprintf("pw%06d", c.rng.Intn(1000000))}}
			c.post(h, "/login", []byte(f.Encode()), "application/x-www-form-urlencoded")
			c.sleep(0.05, 0.25)
		}
	case "scan": // TLS handshake sweep: complete or fail the handshake, then close
		ports := []int{443, 8443, 9443, 10443, 4433, 443}
		for time.Now().Before(end) {
			p := ports[c.rng.Intn(len(ports))]
			a := net.JoinHostPort(c.target, strconv.Itoa(p))
			if c.quic {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				t := c.tcfg.Clone()
				t.NextProtos = []string{"h3"}
				conn, err := quic.DialAddr(ctx, a, t, &quic.Config{})
				if err == nil {
					conn.CloseWithError(0, "")
				}
				cancel()
			} else {
				conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", a, c.tcfg.Clone())
				if err == nil {
					conn.Close()
				}
			}
			c.n++
			c.sleep(0.05, 0.2)
		}
	case "probe": // one request, print the negotiated parameters
		h := c.httpClient(true)
		var st *tls.ConnectionState
		r, err := h.Get("https://" + sni + "/obj?n=100")
		if err != nil {
			fmt.Println("probe error:", err)
			os.Exit(1)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		st = r.TLS
		if st != nil {
			fmt.Printf("version=%x curve=%v ech=%v alpn=%s sigalg_cert=%v\n", st.Version, st.CurveID, st.ECHAccepted,
				st.NegotiatedProtocol, st.PeerCertificates[0].SignatureAlgorithm)
		}
		return
	default:
		log.Fatal("unknown profile ", *prof)
	}
	fmt.Println("requests", c.n, "errors", c.errs)
}
