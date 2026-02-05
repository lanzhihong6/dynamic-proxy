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
	Country string // ISO Country Code (e.g., KR, US)
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

	// Validate config
	if len(cfg.ProxyListURLs) == 0 {
		return nil, fmt.Errorf("at least one proxy_list_url must be specified")
	}
	if cfg.HealthCheckConcurrency <= 0 {
		cfg.HealthCheckConcurrency = 200
	}
	if cfg.UpdateIntervalMinutes <= 0 {
		cfg.UpdateIntervalMinutes = 5
	}
	if cfg.HealthCheck.TotalTimeoutSeconds <= 0 {
		cfg.HealthCheck.TotalTimeoutSeconds = 8
	}
	if cfg.HealthCheck.TLSHandshakeThresholdSeconds <= 0 {
		cfg.HealthCheck.TLSHandshakeThresholdSeconds = 5
	}
	if cfg.Ports.SOCKS5Strict == "" {
		cfg.Ports.SOCKS5Strict = ":17283"
	}
	if cfg.Ports.SOCKS5Relaxed == "" {
		cfg.Ports.SOCKS5Relaxed = ":17284"
	}
	if cfg.Ports.HTTPStrict == "" {
		cfg.Ports.HTTPStrict = ":17285"
	}
	if cfg.Ports.HTTPRelaxed == "" {
		cfg.Ports.HTTPRelaxed = ":17286"
	}

	return &cfg, nil
}

type ProxyPool struct {
	proxies   []ProxyInfo
	mu        sync.RWMutex
	index     uint64
	updating  int32
}

func NewProxyPool() *ProxyPool {
	return &ProxyPool{
		proxies: make([]ProxyInfo, 0),
	}
}

func (p *ProxyPool) Update(proxies []ProxyInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldCount := len(p.proxies)
	p.proxies = proxies
	atomic.StoreUint64(&p.index, 0)

	log.Printf("Proxy pool updated: %d -> %d active proxies", oldCount, len(proxies))
}

func (p *ProxyPool) GetNext(session, country string) (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.proxies) == 0 {
		return "", fmt.Errorf("no available proxies")
	}

	// Filter by country if requested
	var candidates []ProxyInfo
	if country != "" {
		for _, pr := range p.proxies {
			if strings.EqualFold(pr.Country, country) {
				candidates = append(candidates, pr)
			}
		}
		if len(candidates) == 0 {
			return "", fmt.Errorf("no available proxies in country: %s", country)
		}
	} else {
		candidates = p.proxies
	}

	// Sticky session logic
	if session != "" {
		h := fnv.New32a()
		h.Write([]byte(session))
		idx := uint64(h.Sum32()) % uint64(len(candidates))
		return candidates[idx].Addr, nil
	}

	// Round-robin logic
	idx := atomic.AddUint64(&p.index, 1) % uint64(len(candidates))
	return candidates[idx].Addr, nil
}

func (p *ProxyPool) GetAll() []ProxyInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]ProxyInfo, len(p.proxies))
	copy(result, p.proxies)
	return result
}

// parseSpecialProxyURL extracts ip:port using regex
func parseSpecialProxyURL(content string) ([]string, error) {
	var proxies []string
	proxySet := make(map[string]bool)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := simpleProxyRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			proxy := fmt.Sprintf("%s:%s", matches[1], matches[2])
			if !proxySet[proxy] {
				proxySet[proxy] = true
				proxies = append(proxies, proxy)
			}
		}
	}

	return proxies, nil
}

func fetchProxyList() ([]string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	allProxies := make([]string, 0)
	proxySet := make(map[string]bool)

	for _, url := range config.ProxyListURLs {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		scanner := bufio.NewScanner(strings.NewReader(string(body)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "socks5://")
			line = strings.TrimPrefix(line, "socks4://")
			line = strings.TrimPrefix(line, "https://")
			line = strings.TrimPrefix(line, "http://")

			if !proxySet[line] {
				proxySet[line] = true
				allProxies = append(allProxies, line)
			}
		}
	}

	for _, url := range config.SpecialProxyListUrls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		special, _ := parseSpecialProxyURL(string(body))
		for _, p := range special {
			if !proxySet[p] {
				proxySet[p] = true
				allProxies = append(allProxies, p)
			}
		}
	}

	return allProxies, nil
}

// checkProxyHealthWithGeo tests proxy and returns country code
func checkProxyHealthWithGeo(proxyAddr string, strictMode bool) (bool, string) {
	totalTimeout := time.Duration(config.HealthCheck.TotalTimeoutSeconds) * time.Second
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, &net.Dialer{Timeout: totalTimeout})
	if err != nil {
		return false, ""
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !strictMode},
		},
		Timeout: totalTimeout,
	}

	// 1. Health check & GeoIP query
	resp, err := client.Get("http://ip-api.com/json")
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	var geo struct {
		Status  string `json:"status"`
		Country string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil || geo.Status != "success" {
		// Even if Geo lookup fails, the proxy is technically "up"
		return true, "XX"
	}

	return true, geo.Country
}

func healthCheckProxies(proxies []string) HealthCheckResult {
	var wg sync.WaitGroup
	var mu sync.Mutex
	strictHealthy := make([]ProxyInfo, 0)
	relaxedHealthy := make([]ProxyInfo, 0)
	semaphore := make(chan struct{}, config.HealthCheckConcurrency)

	for _, addr := range proxies {
		wg.Add(1)
		go func(proxyAddr string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			ok, country := checkProxyHealthWithGeo(proxyAddr, true)
			if ok {
				mu.Lock()
				info := ProxyInfo{Addr: proxyAddr, Country: country}
				strictHealthy = append(strictHealthy, info)
				relaxedHealthy = append(relaxedHealthy, info)
				mu.Unlock()
			} else {
				okRel, countryRel := checkProxyHealthWithGeo(proxyAddr, false)
				if okRel {
					mu.Lock()
					relaxedHealthy = append(relaxedHealthy, ProxyInfo{Addr: proxyAddr, Country: countryRel})
					mu.Unlock()
				}
			}
		}(addr)
	}
	wg.Wait()
	return HealthCheckResult{Strict: strictHealthy, Relaxed: relaxedHealthy}
}

type HealthCheckResult struct {
	Strict  []ProxyInfo
	Relaxed []ProxyInfo
}

func updateProxyPool(strictPool *ProxyPool, relaxedPool *ProxyPool) {
	if !atomic.CompareAndSwapInt32(&strictPool.updating, 0, 1) {
		return
	}
	defer atomic.StoreInt32(&strictPool.updating, 0)

	proxies, err := fetchProxyList()
	if err != nil {
		return
	}

	result := healthCheckProxies(proxies)
	if len(result.Strict) > 0 {
		strictPool.Update(result.Strict)
	}
	if len(result.Relaxed) > 0 {
		relaxedPool.Update(result.Relaxed)
	}
}

func startProxyUpdater(strictPool *ProxyPool, relaxedPool *ProxyPool, initialSync bool) {
	if initialSync {
		updateProxyPool(strictPool, relaxedPool)
	}
	ticker := time.NewTicker(time.Duration(config.UpdateIntervalMinutes) * time.Minute)
	go func() {
		for range ticker.C {
			updateProxyPool(strictPool, relaxedPool)
		}
	}()
}

// SOCKS5/HTTP Server logic...
type CustomDialer struct {
	pool    *ProxyPool
	mode    string
	session string
	country string
}

func (d *CustomDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	proxyAddr, err := d.pool.GetNext(d.session, d.country)
	if err != nil {
		return nil, err
	}
	dialer, _ := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	return dialer.Dial(network, addr)
}

func startSOCKS5Server(pool *ProxyPool, port string, mode string) error {
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// SOCKS5 doesn't easily carry extra headers, 
			// so session/country would need to be encoded in username or ignored for now.
			dialer := &CustomDialer{pool: pool, mode: mode}
			return dialer.Dial(ctx, network, addr)
		},
	}
	server, _ := socks5.New(conf)
	return server.ListenAndServe("tcp", port)
}

func handleHTTPProxy(w http.ResponseWriter, r *http.Request, pool *ProxyPool, mode string) {
	session := r.Header.Get("X-Proxy-Session")
	country := r.Header.Get("X-Proxy-Country")

	proxyAddr, err := pool.GetNext(session, country)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	log.Printf("[HTTP-%s] Using proxy %s (Session: %s, Country: %s)", mode, proxyAddr, session, country)

	dialer, _ := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if r.Method == http.MethodConnect {
		handleHTTPSProxy(w, r, dialer, proxyAddr, mode)
		return
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	proxyReq, _ := http.NewRequest(r.Method, r.URL.String(), r.Body)
	for key, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleHTTPSProxy(w http.ResponseWriter, r *http.Request, dialer proxy.Dialer, proxyAddr string, mode string) {
	targetConn, err := dialer.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	clientConn, _, _ := hijacker.Hijack()
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(targetConn, clientConn) }()
	go func() { defer wg.Done(); io.Copy(clientConn, targetConn) }()
	wg.Wait()
}

func startHTTPServer(pool *ProxyPool, port string, mode string) error {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleHTTPProxy(w, r, pool, mode)
	})
	server := &http.Server{Addr: port, Handler: handler}
	return server.ListenAndServe()
}

func main() {
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}
	config = *cfg

	strictPool := NewProxyPool()
	relaxedPool := NewProxyPool()
	startProxyUpdater(strictPool, relaxedPool, true)

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); startSOCKS5Server(strictPool, config.Ports.SOCKS5Strict, "STRICT") }()
	go func() { defer wg.Done(); startSOCKS5Server(relaxedPool, config.Ports.SOCKS5Relaxed, "RELAXED") }()
	go func() { defer wg.Done(); startHTTPServer(strictPool, config.Ports.HTTPStrict, "STRICT") }()
	go func() { defer wg.Done(); startHTTPServer(relaxedPool, config.Ports.HTTPRelaxed, "RELAXED") }()

	log.Println("Servers started on ports 17283-17286")
	wg.Wait()
}
