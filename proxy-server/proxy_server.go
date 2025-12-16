// proxy_server.go - Proxy Service
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/elazarl/goproxy"
)

var (
	proxyPort = ":8080"
	publicKey *rsa.PublicKey
)

type TargetRequest struct {
	Target   string `json:"target"`
	DeviceId string `json:"device_id,omitempty"`
}

func main() {
	var err error
	publicKey, err = loadPublicKey("public.pem")
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}
	startProxyServer()
}

func startProxyServer() {
	http.HandleFunc("/", customProxyHandler)
	log.Printf("Proxy Server running on http://0.0.0.0%s", proxyPort)
	log.Fatal(http.ListenAndServe(proxyPort, nil))
}

func customProxyHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		tokenStr = r.URL.Query().Get("token")
	}
	if tokenStr == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	var reqBody TargetRequest
	if r.Method == http.MethodPost {
		defer r.Body.Close()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}
		if err := json.Unmarshal(body, &reqBody); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	if reqBody.Target == "" {
		http.Error(w, "Target required in JSON body", http.StatusBadRequest)
		return
	}

	target, err := url.Parse(reqBody.Target)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Remove token from query and headers, and set Host header
	proxy.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// Remove token from query and headers
			q := req.URL.Query()
			q.Del("token")
			req.URL.RawQuery = q.Encode()
			req.Header.Del("Authorization")
			// Optionally, set Host header to target host
			req.Host = target.Host
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			return req, nil
		},
	)

	// Forward the request to the target
	proxy.ServeHTTP(w, r)
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	return pub, nil
}
