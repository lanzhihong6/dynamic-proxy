package main

import (
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ProxyListURLs              []string `yaml:"proxy_list_urls"`
	SpecialProxyListUrls       []string `yaml:"special_proxy_list_urls"`
	HealthCheckConcurrency     int      `yaml:"health_check_concurrency"`
	UpdateIntervalMinutes      int      `yaml:"update_interval_minutes"`
	HealthCheck                struct {
		TotalTimeoutSeconds          int `yaml:"total_timeout_seconds"`
		TLSHandshakeThresholdSeconds int `yaml:"tls_handshake_threshold_seconds"`
	} `yaml:"health_check"`
	Ports struct {
		HTTPStrict  string `yaml:"http_strict"`
		HTTPRelaxed string `yaml:"http_relaxed"`
	} `yaml:"ports"`
}

type ProxyInfo struct {
	Addr    string
	Country string
}

var (
	config           Config
	simpleProxyRegex = regexp.MustCompile(`([0-9a-fA-F:]{3,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})`)

	// Store IP2Region databases as byte buffers in memory
	// These are read-only after initialization - safe for concurrent reads
	ip2regionV4Buffer []byte
	ip2regionV6Buffer []byte

	// Searcher pools for thread-safe concurrent access
	// Each goroutine gets its own Searcher instance from the pool
	searcherV4Pool *sync.Pool
	searcherV6Pool *sync.Pool
)

type ProxyPool struct {
	proxies  []ProxyInfo
	mu       sync.RWMutex
	index    uint64
	updating int32
}

func (p *ProxyPool) Update(proxies []ProxyInfo) {
	p.mu.Lock()
	p.proxies = proxies
	p.mu.Unlock()
}

func (p *ProxyPool) GetNext(session, country string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.proxies) == 0 {
		return "", fmt.Errorf("proxy pool empty")
	}
	var cands []ProxyInfo
	if country != "" {
		for _, pr := range p.proxies {
			if strings.EqualFold(pr.Country, country) {
				cands = append(cands, pr)
			}
		}
		if len(cands) == 0 {
			return "", fmt.Errorf("no proxies in %s", country)
		}
	} else {
		cands = p.proxies
	}
	var idx uint64
	if session != "" {
		h := fnv.New32a()
		h.Write([]byte(session))
		idx = uint64(h.Sum32()) % uint64(len(cands))
	} else {
		idx = atomic.AddUint64(&p.index, 1) % uint64(len(cands))
	}
	return cands[idx].Addr, nil
}

func fetchProxyList() []string {
	client := &http.Client{Timeout: 15 * time.Second}
	var list []string
	set := make(map[string]bool)
	urls := append(config.ProxyListURLs, config.SpecialProxyListUrls...)
	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		matches := simpleProxyRegex.FindAllString(string(b), -1)
		for _, m := range matches {
			if !set[m] {
				set[m] = true
				list = append(list, m)
			}
		}
	}
	return list
}

// initSearcherPools initializes the sync.Pool for Searcher instances
// This MUST be called after loading the xdb buffers
func initSearcherPools() {
	if ip2regionV4Buffer != nil {
		searcherV4Pool = &sync.Pool{
			New: func() interface{} {
				// CRITICAL: Must pass xdb.IPv4, NOT nil!
				// Passing nil causes s.version to be nil, which leads to
				// nil pointer dereference when accessing s.version.Bytes in Search()
				searcher, err := xdb.NewWithBuffer(xdb.IPv4, ip2regionV4Buffer)
				if err != nil {
					log.Printf("[WARN] Failed to create V4 searcher in pool: %v", err)
					return nil
				}
				return searcher
			},
		}
	}

	if ip2regionV6Buffer != nil {
		searcherV6Pool = &sync.Pool{
			New: func() interface{} {
				// CRITICAL: Must pass xdb.IPv6, NOT nil!
				searcher, err := xdb.NewWithBuffer(xdb.IPv6, ip2regionV6Buffer)
				if err != nil {
					log.Printf("[WARN] Failed to create V6 searcher in pool: %v", err)
					return nil
				}
				return searcher
			},
		}
	}
}

// getCountryCode looks up the country code for an IP address
// Uses sync.Pool for thread-safe Searcher access
func getCountryCode(ipAddr string) string {
	var pool *sync.Pool
	isV6 := strings.Contains(ipAddr, ":")

	if isV6 {
		pool = searcherV6Pool
	} else {
		pool = searcherV4Pool
	}

	if pool == nil {
		return "XX"
	}

	// Get a searcher from the pool
	searcherIface := pool.Get()
	if searcherIface == nil {
		return "XX"
	}

	searcher, ok := searcherIface.(*xdb.Searcher)
	if !ok || searcher == nil {
		return "XX"
	}

	// Put the searcher back when done
	// Note: xdb.Searcher created with NewWithBuffer has no file handle,
	// so Close() is a no-op and we can safely reuse it
	defer pool.Put(searcher)

	// Perform the search with panic recovery as last resort
	var region string
	var err error

	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[WARN] Panic in ip2region search for %s: %v", ipAddr, r)
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		region, err = searcher.SearchByStr(ipAddr)
	}()

	if err != nil {
		return "XX"
	}

	parts := strings.Split(region, "|")
	if len(parts) < 1 || parts[0] == "" {
		return "XX"
	}

	countryName := parts[0]
	switch countryName {
	case "韩国":
		return "KR"
	case "美国":
		return "US"
	case "日本":
		return "JP"
	case "中国":
		return "CN"
	case "英国":
		return "GB"
	case "德国":
		return "DE"
	case "新加坡":
		return "SG"
	case "香港":
		return "HK"
	case "台湾":
		return "TW"
	case "加拿大":
		return "CA"
	case "澳大利亚":
		return "AU"
	case "法国":
		return "FR"
	case "荷兰":
		return "NL"
	case "俄罗斯":
		return "RU"
	case "巴西":
		return "BR"
	case "印度":
		return "IN"
	case "意大利":
		return "IT"
	case "西班牙":
		return "ES"
	case "瑞士":
		return "CH"
	case "瑞典":
		return "SE"
	default:
		// If it's already a 2-letter code, return as-is
		if len(countryName) == 2 {
			return strings.ToUpper(countryName)
		}
		return countryName
	}
}

func check(addr string, strict bool) (bool, string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false, ""
	}
	country := getCountryCode(host)
	timeout := time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second
	dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return false, ""
	}
	conn, err := dialer.Dial("tcp", "www.google.com:443")
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	if strict {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: false, ServerName: "www.google.com"})
		if err := tlsConn.Handshake(); err != nil {
			return false, ""
		}
		tlsConn.Close()
	}
	return true, country
}

func updatePools(sp, rp *ProxyPool) {
	if !atomic.CompareAndSwapInt32(&sp.updating, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&sp.updating, 0)

	log.Println("[UPDATE] Refreshing proxy list...")
	list := fetchProxyList()
	total := len(list)
	var s, r []ProxyInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	var checked int64
	sem := make(chan struct{}, config.HealthCheckConcurrency)

	for _, a := range list {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ok, c := check(addr, true); ok {
				mu.Lock()
				info := ProxyInfo{addr, c}
				s = append(s, info)
				r = append(r, info)
				mu.Unlock()
			} else if ok, c := check(addr, false); ok {
				mu.Lock()
				r = append(r, ProxyInfo{addr, c})
				mu.Unlock()
			}
			val := atomic.AddInt64(&checked, 1)
			if val%100 == 0 || val == int64(total) {
				log.Printf("[UPDATE] Progress: %d/%d", val, total)
			}
		}(a)
	}
	wg.Wait()
	sp.Update(s)
	rp.Update(r)
	log.Printf("[UPDATE] Complete. Strict: %d, Relaxed: %d", len(s), len(r))
}

func handleHTTP(w http.ResponseWriter, r *http.Request, pool *ProxyPool, mode string) {
	session := r.Header.Get("X-Proxy-Session")
	country := r.Header.Get("X-Proxy-Country")
	proxyAddr, err := pool.GetNext(session, country)
	if err != nil {
		http.Error(w, err.Error(), 503)
		return
	}

	dialer, _ := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if r.Method == http.MethodConnect || r.URL.Scheme == "https" {
		target := r.Host
		if target == "" {
			target = r.URL.Host
		}
		dest, err := dialer.Dial("tcp", target)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer dest.Close()
		hj, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, _, _ := hj.Hijack()
		defer conn.Close()
		if r.Method == http.MethodConnect {
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}
		go io.Copy(dest, conn)
		io.Copy(conn, dest)
		return
	}

	transport := &http.Transport{Dial: dialer.Dial, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	cfgFile, err := os.ReadFile("config.yaml")
	if err == nil {
		yaml.Unmarshal(cfgFile, &config)
	}
	if config.HealthCheckConcurrency <= 0 {
		config.HealthCheckConcurrency = 200
	}
	if config.UpdateIntervalMinutes <= 0 {
		config.UpdateIntervalMinutes = 5
	}
	if config.HealthCheck.TotalTimeoutSeconds <= 0 {
		config.HealthCheck.TotalTimeoutSeconds = 8
	}

	// Load IPv4 database into memory - REQUIRED
	log.Println("[BOOT] Loading ip2region_v4.xdb...")
	v4b, err := os.ReadFile("ip2region_v4.xdb")
	if err != nil {
		log.Fatalf("[FATAL] Could not read ip2region_v4.xdb: %v", err)
	}
	ip2regionV4Buffer = v4b

	// Validate V4 database by creating a test searcher with proper version
	testSearcher, err := xdb.NewWithBuffer(xdb.IPv4, ip2regionV4Buffer)
	if err != nil {
		log.Fatalf("[FATAL] Could not initialize v4 searcher: %v", err)
	}
	testSearcher.Close()
	log.Println("[BOOT] IPv4 database loaded and validated successfully")

	// Load IPv6 database into memory - OPTIONAL
	v6b, err := os.ReadFile("ip2region_v6.xdb")
	if err == nil {
		ip2regionV6Buffer = v6b
		testSearcherV6, err := xdb.NewWithBuffer(xdb.IPv6, ip2regionV6Buffer)
		if err == nil {
			testSearcherV6.Close()
			log.Println("[BOOT] IPv6 database loaded and validated successfully")
		} else {
			log.Printf("[WARN] IPv6 database file found but invalid: %v", err)
			ip2regionV6Buffer = nil
		}
	} else {
		log.Printf("[WARN] IPv6 database not found (optional): %v", err)
	}

	// Initialize searcher pools AFTER loading buffers
	initSearcherPools()
	log.Println("[BOOT] Searcher pools initialized")

	sp, rp := &ProxyPool{}, &ProxyPool{}
	log.Println("[BOOT] Initial health check starting...")
	updatePools(sp, rp)

	go func() {
		for {
			time.Sleep(time.Duration(config.UpdateIntervalMinutes) * time.Minute)
			updatePools(sp, rp)
		}
	}()

	hS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleHTTP(w, r, sp, "STRICT") })
	hR := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleHTTP(w, r, rp, "RELAXED") })

	log.Printf("[BOOT] Servers on %s and %s", config.Ports.HTTPStrict, config.Ports.HTTPRelaxed)
	go http.ListenAndServe(config.Ports.HTTPStrict, hS)
	http.ListenAndServe(config.Ports.HTTPRelaxed, hR)
}
