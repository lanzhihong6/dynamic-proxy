package main

import (
	"bufio"
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

// Config represents the application configuration
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
	Country string // ISO Country Code
}

var config Config
var simpleProxyRegex = regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})`)

// loadConfig loads configuration from config.yaml
func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	if cfg.HealthCheckConcurrency <= 0 { cfg.HealthCheckConcurrency = 200 }
	if cfg.UpdateIntervalMinutes <= 0 { cfg.UpdateIntervalMinutes = 5 }
	if cfg.HealthCheck.TotalTimeoutSeconds <= 0 { cfg.HealthCheck.TotalTimeoutSeconds = 8 }
	if cfg.HealthCheck.TLSHandshakeThresholdSeconds <= 0 { cfg.HealthCheck.TLSHandshakeThresholdSeconds = 5 }
	if cfg.Ports.SOCKS5Strict == "" { cfg.Ports.SOCKS5Strict = ":17283" }
	if cfg.Ports.SOCKS5Relaxed == "" { cfg.Ports.SOCKS5Relaxed = ":17284" }
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

func NewProxyPool() *ProxyPool {
	return &ProxyPool{proxies: make([]ProxyInfo, 0)}
}

func (p *ProxyPool) Update(proxies []ProxyInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proxies = proxies
	atomic.StoreUint64(&p.index, 0)
	log.Printf("[POOL] Updated: %d active proxies", len(proxies))
}

func (p *ProxyPool) GetNext(session, country string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.proxies) == 0 {
		return "", fmt.Errorf("no available proxies")
	}

	var candidates []ProxyInfo
	if country != "" {
		for _, pr := range p.proxies {
			if strings.EqualFold(pr.Country, country) {
				candidates = append(candidates, pr)
			}
		}
		if len(candidates) == 0 {
			return "", fmt.Errorf("no proxies in %s", country)
		}
	} else {
		candidates = p.proxies
	}

	targetIdx := uint64(0)
	if session != "" {
		h := fnv.New32a()
		h.Write([]byte(session))
		targetIdx = uint64(h.Sum32()) % uint64(len(candidates))
	} else {
		targetIdx = atomic.AddUint64(&p.index, 1) % uint64(len(candidates))
	}
	return candidates[targetIdx].Addr, nil
}

func fetchProxyList() ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	allProxies := make([]string, 0)
	proxySet := make(map[string]bool)

	urls := append(config.ProxyListURLs, config.SpecialProxyListUrls...)
	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil { log.Printf("[FETCH] Failed %s: %v", url, err); continue }
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Regex based extraction for all sources to be safe
		matches := simpleProxyRegex.FindAllString(string(body), -1)
		for _, m := range matches {
			if !proxySet[m] {
				proxySet[m] = true
				allProxies = append(allProxies, m)
			}
		}
	}
	return allProxies, nil
}

func checkProxyHealth(proxyAddr string, strictMode bool) (bool, string) {
	totalTimeout := time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{Timeout: totalTimeout})
	if err != nil { return false, "" }

	// Phase 1: Rapid TCP/TLS Handshake
	conn, err := dialer.Dial("tcp", "www.google.com:443")
	if err != nil { return false, "" }
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: !strictMode, ServerName: "www.google.com"})
	if err := tlsConn.Handshake(); err != nil { return false, "" }
	tlsConn.Close()

	// Phase 2: Geo Lookup (Only for healthy proxies)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return dialer.Dial(n, a) },
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("http://ip-api.com/json")
	if err == nil {
		defer resp.Body.Close()
		var geo struct { Status string `json:"status"`; Country string `json:"countryCode"` }
		if json.NewDecoder(resp.Body).Decode(&geo) == nil && geo.Status == "success" {
			return true, geo.Country
		}
	}
	return true, "XX"
}

func healthCheckProxies(proxies []string) HealthCheckResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	strict := make([]ProxyInfo, 0)
	relaxed := make([]ProxyInfo, 0)
	sem := make(chan struct{}, config.HealthCheckConcurrency)

	for _, addr := range proxies {
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			sem <- struct{}{}; defer func(){ <-sem }()
			if ok, country := checkProxyHealth(a, true); ok {
				mu.Lock(); info := ProxyInfo{Addr: a, Country: country}
				strict = append(strict, info); relaxed = append(relaxed, info)
				mu.Unlock()
			} else if ok, country := checkProxyHealth(a, false); ok {
				mu.Lock(); relaxed = append(relaxed, ProxyInfo{Addr: a, Country: country}); mu.Unlock()
			}
		}(addr)
	}
	wg.Wait()
	return HealthCheckResult{strict, relaxed}
}

type HealthCheckResult struct { Strict, Relaxed []ProxyInfo }

func updateProxyPool(strictPool, relaxedPool *ProxyPool) {
	if !atomic.CompareAndSwapInt32(&strictPool.updating, 0, 1) { return }
	defer atomic.StoreInt32(&strictPool.updating, 0)

	log.Println("[UPDATE] Refreshing proxy list...")
	list, _ := fetchProxyList()
	res := healthCheckProxies(list)
	strictPool.Update(res.Strict)
	relaxedPool.Update(res.Relaxed)
}

func handleHTTPProxy(w http.ResponseWriter, r *http.Request, pool *ProxyPool, mode string) {
	session := r.Header.Get("X-Proxy-Session")
	country := r.Header.Get("X-Proxy-Country")
	proxyAddr, err := pool.GetNext(session, country)
	if err != nil {
		log.Printf("[HTTP-%s] No proxy: %v", mode, err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable); return
	}

	dialer, _ := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if r.Method == http.MethodConnect {
		log.Printf("[HTTPS-%s] Tunnel: %s via %s", mode, r.Host, proxyAddr)
		targetConn, err := dialer.Dial("tcp", r.Host)
		if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
		defer targetConn.Close()
		
		hijacker, _ := w.(http.Hijacker)
		clientConn, _, _ := hijacker.Hijack()
		defer clientConn.Close()
		clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		
		go io.Copy(targetConn, clientConn)
		io.Copy(clientConn, targetConn)
		return
	}

	log.Printf("[HTTP-%s] Forward: %s via %s", mode, r.URL.Host, proxyAddr)
	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns: 100,
		IdleConnTimeout: 90 * time.Second,
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	proxyReq, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
	for k, vv := range r.Header { for _, v := range vv { proxyReq.Header.Add(k, v) } }
	
	resp, err := client.Do(proxyReq)
	if err != nil { http.Error(w, err.Error(), http.StatusBadGateway); return }
	defer resp.Body.Close()
	for k, vv := range resp.Header { for _, v := range vv { w.Header().Add(k, v) } }
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func main() {
	cfg, err := loadConfig("config.yaml")
	if err != nil { log.Fatal(err) }
	config = *cfg

	sPool, rPool := NewProxyPool(), NewProxyPool()
	go func() {
		updateProxyPool(sPool, rPool)
		ticker := time.NewTicker(time.Duration(config.UpdateIntervalMinutes) * time.Minute)
		for range ticker.C { updateProxyPool(sPool, rPool) }
	}()

	muxS, muxR := http.NewServeMux(), http.NewServeMux()
	muxS.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handleHTTPProxy(w, r, sPool, "STRICT") })
	muxR.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handleHTTPProxy(w, r, rPool, "RELAXED") })

	log.Printf("Starting servers on %s and %s", config.Ports.HTTPStrict, config.Ports.HTTPRelaxed)
	go http.ListenAndServe(config.Ports.HTTPStrict, muxS)
	http.ListenAndServe(config.Ports.HTTPRelaxed, muxR)
}
