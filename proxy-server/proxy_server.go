// proxy_server.go - Proxy Service
package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var (
	proxyPort  = ":8080"
	userTokens = make(map[string]string) // This should be shared or replaced with a persistent store in production
)

func main() {
	startProxyServer()
}

func startProxyServer() {
	http.HandleFunc("/", proxyHandler)
	fmt.Printf("Proxy Server running on http://0.0.0.0%s\n", proxyPort)
	log.Fatal(http.ListenAndServe(proxyPort, nil))
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}
	token = strings.TrimPrefix(token, "Bearer ")
	targetURL, exists := userTokens[token]
	if !exists {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		if strings.Contains(err.Error(), "connection reset by peer") || strings.Contains(err.Error(), "ECONNRESET") {
			log.Printf("ECONNRESET: %v", err)
			http.Error(w, "Upstream connection reset", http.StatusBadGateway)
			return
		}
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Proxy error", http.StatusBadGateway)
	}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host
		q := req.URL.Query()
		q.Del("token")
		req.URL.RawQuery = q.Encode()
	}
	log.Printf("Proxying request for token %s to %s", token, targetURL)
	start := time.Now()
	proxy.ServeHTTP(w, r)
	duration := time.Since(start)
	log.Printf("Proxied response in %v for %s %s", duration, r.Method, r.RequestURI)
}
