// main.go - Go Proxy Server
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret    = []byte("your-secret-key-change-this") // Change this in production!
	proxyPort    = ":8080"
	apiPort      = ":8081"
	userTokens   = make(map[string]string) // In production, use a database
	proxyTargets = make(map[string]*url.URL)
)

// User structure
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims for JWT
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// LoginRequest structure
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse structure
type LoginResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

// ProxyConfig structure
type ProxyConfig struct {
	TargetURL string `json:"target_url"`
	Token     string `json:"token"`
}

func main() {
	// Start API server for authentication
	go startAPIServer()

	// Start proxy server
	startProxyServer()
}

func startAPIServer() {
	router := mux.NewRouter()

	// Authentication endpoints
	router.HandleFunc("/api/register", registerHandler).Methods("POST")
	router.HandleFunc("/api/login", loginHandler).Methods("POST")
	router.HandleFunc("/api/validate", validateTokenHandler).Methods("GET")
	router.HandleFunc("/api/proxy/register", registerProxyHandler).Methods("POST")

	// Add logging middleware
	loggedRouter := loggingMiddleware(router)

	// Serve API
	fmt.Printf("API Server running on http://localhost%s\n", apiPort)
	log.Fatal(http.ListenAndServe(apiPort, loggedRouter))
}

func startProxyServer() {
	router := mux.NewRouter()

	// Proxy handler with authentication middleware
	router.PathPrefix("/").HandlerFunc(proxyHandler)

	// Add logging middleware
	loggedRouter := loggingMiddleware(router)

	fmt.Printf("Proxy Server running on http://localhost%s\n", proxyPort)
	log.Fatal(http.ListenAndServe(proxyPort, loggedRouter))
}

// loggingMiddleware logs every request and response status/size
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Incoming %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
		lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lrw, r)
		duration := time.Since(start)
		log.Printf("Responded %d (%d bytes) in %v for %s %s", lrw.statusCode, lrw.size, duration, r.Method, r.RequestURI)
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (lrw *loggingResponseWriter) WriteHeader(code int) {
	lrw.statusCode = code
	lrw.ResponseWriter.WriteHeader(code)
}

func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	n, err := lrw.ResponseWriter.Write(b)
	lrw.size += n
	return n, err
}

// Authentication Middleware
func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			// Try to get from query parameter
			token := r.URL.Query().Get("token")
			if token == "" {
				http.Error(w, "Authorization token required", http.StatusUnauthorized)
				return
			}
			authHeader = "Bearer " + token
		}

		// Extract token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]

		// Validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add username to context
		ctx := context.WithValue(r.Context(), "username", claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Proxy handler
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Get target URL from registered proxies
	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.URL.Query().Get("token")
	}

	if token == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}

	// Remove "Bearer " prefix if present
	token = strings.TrimPrefix(token, "Bearer ")

	targetURL, exists := userTokens[token]
	if !exists {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Parse target URL
	target, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, "Invalid target URL", http.StatusBadRequest)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Modify request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = target.Host

		// Remove token from query parameters if present
		q := req.URL.Query()
		q.Del("token")
		req.URL.RawQuery = q.Encode()
	}

	// Log proxying
	log.Printf("Proxying request for token %s to %s", token, targetURL)

	// Wrap the ResponseWriter to log response status and size
	lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	start := time.Now()
	proxy.ServeHTTP(lrw, r)
	duration := time.Since(start)
	log.Printf("Proxied response %d (%d bytes) in %v for %s %s", lrw.statusCode, lrw.size, duration, r.Method, r.RequestURI)
}

// API Handlers
func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Generate random token for proxy access
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	proxyToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// Store user token (in production, use database with hashed passwords)
	userTokens[proxyToken] = "https://www.google.com" // Default proxy target

	// Create JWT token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := LoginResponse{
		Token:   tokenString,
		Message: "Registration successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// In production, validate against database
	// For demo, accept any user

	// Create JWT token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: req.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	response := LoginResponse{
		Token:   tokenString,
		Message: "Login successful",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusBadRequest)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	response := map[string]interface{}{
		"valid":    true,
		"username": claims.Username,
		"expires":  claims.ExpiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func registerProxyHandler(w http.ResponseWriter, r *http.Request) {
	var config ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate JWT token
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(config.Token, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Generate proxy token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	proxyToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// Store proxy configuration
	userTokens[proxyToken] = config.TargetURL

	response := map[string]interface{}{
		"proxy_token": proxyToken,
		"target_url":  config.TargetURL,
		"proxy_url":   fmt.Sprintf("http://localhost%s/?token=%s", proxyPort, proxyToken),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper function to hash passwords
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Helper function to check passwords
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
