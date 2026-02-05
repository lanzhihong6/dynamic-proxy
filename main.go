package main

import (
	"context"
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
		TotalTimeoutSeconds           int `yaml:"total_timeout_seconds"`
		TLSHandshakeThresholdSeconds  int `yaml:"tls_handshake_threshold_seconds"`
	} `yaml:"health_check"`
	Ports struct {
		HTTPStrict     string `yaml:"http_strict"`
		HTTPRelaxed    string `yaml:"http_relaxed"`
	} `yaml:"ports"`
}

type ProxyInfo struct {
	Addr    string
	Country string
}

var (
	config           Config
	simpleProxyRegex = regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})`)
	searcher         *xdb.Searcher
)

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil { return nil, err }
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil { return nil, err }
	if cfg.HealthCheckConcurrency <= 0 { cfg.HealthCheckConcurrency = 200 }
	if cfg.UpdateIntervalMinutes <= 0 { cfg.UpdateIntervalMinutes = 5 }
	if cfg.HealthCheck.TotalTimeoutSeconds <= 0 { cfg.HealthCheck.TotalTimeoutSeconds = 8 }
	if cfg.Ports.HTTPStrict == "" { cfg.Ports.HTTPStrict = ":17285" }
	if cfg.Ports.HTTPRelaxed == "" { cfg.Ports.HTTPRelaxed = ":17286" }
	return &cfg, nil
}

func getCountryCode(ipAddr string) string {
	if searcher == nil { return "XX" }
	region, err := searcher.SearchByStr(ipAddr)
	if err != nil { return "XX" }
	
	// region format: 国家|区域|省份|城市|ISP
	parts := strings.Split(region, "|")
	if len(parts) < 1 { return "XX" }
	
	countryName := parts[0]
	switch countryName {
	case "韩国": return "KR"
	case "美国": return "US"
	case "日本": return "JP"
	case "中国": return "CN"
	case "英国": return "GB"
	case "德国": return "DE"
	case "新加坡": return "SG"
	default: 
		// 简单映射，如果不在常用列表中，返回前两个字作为标识或保持原样
		log.Printf("[GEO] Unknown mapping for: %s", countryName)
		return countryName 
	}
}

type ProxyPool struct {
	proxies   []ProxyInfo
	mu        sync.RWMutex
	index     uint64
}

func (p *ProxyPool) Update(proxies []ProxyInfo) {
	p.mu.Lock()
	p.proxies = proxies
	p.mu.Unlock()
}

func (p *ProxyPool) GetNext(session, country string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.proxies) == 0 { return "", fmt.Errorf("proxy pool is empty") }
	
	var cands []ProxyInfo
	if country != "" {
		for _, pr := range p.proxies {
			if strings.EqualFold(pr.Country, country) { cands = append(cands, pr) }
		}
		if len(cands) == 0 { return "", fmt.Errorf("no proxies in %s", country) }
	} else {
		cands = p.proxies
	}
	
	var idx uint64
	if session != "" {
		h := fnv.New32a(); h.Write([]byte(session))
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
	for _, url := range append(config.ProxyListURLs, config.SpecialProxyListUrls...) {
		resp, err := client.Get(url)
		if err != nil { continue }
		b, _ := io.ReadAll(resp.Body); resp.Body.Close()
		matches := simpleProxyRegex.FindAllString(string(b), -1)
		for _, m := range matches {
			if !set[m] { set[m] = true; list = append(list, m) }
		}
	}
	return list
}

func check(addr string, strict bool) (bool, string) {
	host, _, _ := net.SplitHostPort(addr)
	country := getCountryCode(host)
	
	timeout := time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second
	dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: timeout})
	if err != nil { return false, "" }

	conn, err := dialer.Dial("tcp", "www.google.com:443")
	if err != nil { return false, "" }
	defer conn.Close()

	if strict {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: false, ServerName: "www.google.com"})
		if err := tlsConn.Handshake(); err != nil { return false, "" }
		tlsConn.Close()
	}
	return true, country
}

func performUpdate(sp, rp *ProxyPool) {
	log.Println("[UPDATE] Refreshing proxy list...")
	raw := fetchProxyList()
	total := len(raw)
	log.Printf("[UPDATE] Testing %d candidates with concurrency %d...", total, config.HealthCheckConcurrency)

	var s, r []ProxyInfo
	var mu sync.Mutex
	var wg sync.WaitGroup
	var checked int64
	sem := make(chan struct{}, config.HealthCheckConcurrency)
	
	for _, a := range raw {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			sem <- struct{}{}; defer func(){ <-sem }()
			
			if okS, cS := check(addr, true); okS {
				mu.Lock(); info := ProxyInfo{addr, cS}; s = append(s, info); r = append(r, info); mu.Unlock()
			} else if okR, cR := check(addr, false); okR {
				mu.Lock(); r = append(r, ProxyInfo{addr, cR}); mu.Unlock()
			}
			val := atomic.AddInt64(&checked, 1)
			if val%50 == 0 || val == int64(total) {
				log.Printf("[UPDATE] Progress: %d/%d", val, total)
			}
		}(a)
	}
	wg.Wait()
	sp.Update(s); rp.Update(r)
	log.Printf("[UPDATE] Complete. Strict: %d, Relaxed: %d", len(s), len(r))
}

func handleHTTP(w http.ResponseWriter, r *http.Request, pool *ProxyPool, mode string) {
	session := r.Header.Get("X-Proxy-Session")
	country := r.Header.Get("X-Proxy-Country")
	proxyAddr, err := pool.GetNext(session, country)
	if err != nil {
		http.Error(w, err.Error(), 503); return
	}

	dialer, _ := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)

	if r.Method == http.MethodConnect || r.URL.Scheme == "https" {
		target := r.Host
		if target == "" { target = r.URL.Host }
		dest, err := dialer.Dial("tcp", target)
		if err != nil { http.Error(w, err.Error(), 502); return }
		defer dest.Close()
		
		hj, _ := w.(http.Hijacker)
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
	if err != nil { http.Error(w, err.Error(), 502); return }
	defer resp.Body.Close()
	for k, vv := range resp.Header { for _, v := range vv { w.Header().Add(k, v) } }
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	cfg, err := loadConfig("config.yaml")
	if err != nil { log.Fatal(err) }
	config = *cfg

	// Load ip2region
	cPath := "ip2region.xdb"
	v, err := xdb.LoadContentFromFile(cPath)
	if err != nil {
		log.Printf("[BOOT] Failed to load xdb: %v", err)
	} else {
		searcher, err = xdb.NewWithBuffer(v)
		if err != nil { log.Printf("[BOOT] Failed to create searcher: %v", err) }
	}

	sp, rp := &ProxyPool{}, &ProxyPool{}
	log.Println("[BOOT] Initial health check starting...")
	performUpdate(sp, rp)

	go func() {
		for {
			time.Sleep(time.Duration(config.UpdateIntervalMinutes) * time.Minute)
			performUpdate(sp, rp)
		}
	}()

	hS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleHTTP(w, r, sp, "STRICT") })
	hR := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleHTTP(w, r, rp, "RELAXED") })
	
	log.Printf("[BOOT] Servers on %s and %s", config.Ports.HTTPStrict, config.Ports.HTTPRelaxed)
	go http.ListenAndServe(config.Ports.HTTPStrict, hS)
	http.ListenAndServe(config.Ports.HTTPRelaxed, hR)
}
