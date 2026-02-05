package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
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

	"github.com/armon/go-socks5"
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
		SOCKS5Strict   string `yaml:"socks5_strict"`
		SOCKS5Relaxed  string `yaml:"socks5_relaxed"`
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

type ProxyPool struct {
	proxies   []ProxyInfo
	mu        sync.RWMutex
	index     uint64
	updating  int32
}

func (p *ProxyPool) Update(proxies []ProxyInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = proxies
	atomic.StoreUint64(&p.index, 0)
	log.Printf("[POOL] Updated with %d healthy proxies", len(proxies))
}

func (p *ProxyPool) GetNext(session, country string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.proxies) == 0 { return "", fmt.Errorf("no proxies available") }
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
	for _, url := range append(config.ProxyListURLs, config.SpecialProxyListUrls...) {
		resp, err := client.Get(url)
		if err != nil { continue }
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		matches := simpleProxyRegex.FindAllString(string(b), -1)
		for _, m := range matches {
			if !set[m] { set[m] = true; list = append(list, m) }
		}
	}
	return list
}

func check(addr string, strict bool) (bool, string) {
	timeout := time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second
	dialer, err := proxy.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: timeout})
	if err != nil { return false, "" }
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return dialer.Dial(n, a) },
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !strict},
		},
		Timeout: timeout,
	}
	resp, err := client.Get("http://ip-api.com/json")
	if err != nil { return false, "" }
	defer resp.Body.Close()
	var g struct { Status, CountryCode string }
	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil { return true, "XX" }
	if g.Status == "success" { return true, g.CountryCode }
	return true, "XX"
}

func update(sp, rp *ProxyPool) {
	if !atomic.CompareAndSwapInt32(&sp.updating, 0, 1) { return }
	defer atomic.StoreInt32(&sp.updating, 0)
	list := fetchProxyList()
	var s, r []ProxyInfo
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, config.HealthCheckConcurrency)
	for _, a := range list {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done(); sem <- struct{}{}; defer func(){ <-sem }()
			if ok, c := check(addr, true); ok {
				mu.Lock(); info := ProxyInfo{addr, c}; s = append(s, info); r = append(r, info); mu.Unlock()
			} else if ok, c := check(addr, false); ok {
				mu.Lock(); r = append(r, ProxyInfo{addr, c}); mu.Unlock()
			}
		}(a)
	}
	wg.Wait()
	sp.Update(s); rp.Update(r)
}

func handleHTTP(w http.ResponseWriter, r *http.Request, pool *ProxyPool, mode string) {
	session := r.Header.Get("X-Proxy-Session")
	country := r.Header.Get("X-Proxy-Country")
	proxyAddr, err := pool.GetNext(session, country)
	if err != nil { http.Error(w, err.Error(), 503); return }

	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil { http.Error(w, "Dialer error", 500); return }

	if r.Method == http.MethodConnect || r.URL.Scheme == "https" {
		target := r.Host
		if target == "" { target = r.URL.Host }
		dest, err := dialer.Dial("tcp", target)
		if err != nil { http.Error(w, err.Error(), 502); return }
		defer dest.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok { http.Error(w, "Hijack error", 500); return }
		conn, _, _ := hijacker.Hijack()
		defer conn.Close()
		if r.Method == http.MethodConnect {
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}
		go io.Copy(dest, conn)
		io.Copy(conn, dest)
		return
	}

	transport := &http.Transport{Dial: dialer.Dial}
	resp, err := transport.RoundTrip(r)
	if err != nil { http.Error(w, err.Error(), 502); return }
	defer resp.Body.Close()
	for k, vv := range resp.Header { for _, v := range vv { w.Header().Add(k, v) } }
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	cfg, err := loadConfig("config.yaml")
	if err != nil { log.Fatalf("Config failed: %v", err) }
	config = *cfg
	sp, rp := &ProxyPool{}, &ProxyPool{}
	go func() {
		for {
			update(sp, rp)
			time.Sleep(time.Duration(config.UpdateIntervalMinutes) * time.Minute)
		}
	}()
	hS := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleHTTP(w, r, sp, "STRICT") })
	hR := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handleHTTP(w, r, rp, "RELAXED") })
	log.Printf("Starting servers on %s and %s", config.Ports.HTTPStrict, config.Ports.HTTPRelaxed)
	go http.ListenAndServe(config.Ports.HTTPStrict, hS)
	http.ListenAndServe(config.Ports.HTTPRelaxed, hR)
}
