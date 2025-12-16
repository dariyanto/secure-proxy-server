// api_gateway.go - API Gateway Service
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret  = []byte("your-secret-key-change-this") // Change this in production!
	apiPort    = ":8081"
	userTokens = make(map[string]string) // In production, use a database or shared store
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

type ProxyConfig struct {
	TargetURL string `json:"target_url"`
	Token     string `json:"token"`
}

// In-memory user store for demonstration (replace with persistent storage in production)
var users = make(map[string]string) // username -> hashed password

func main() {
	startAPIServer()
}

func startAPIServer() {
	router := mux.NewRouter()

	// Authentication endpoints
	router.HandleFunc("/api/register", registerHandler).Methods("POST")
	router.HandleFunc("/api/login", loginHandler).Methods("POST")
	router.HandleFunc("/api/validate", validateTokenHandler).Methods("GET")
	router.HandleFunc("/api/proxy/register", registerProxyHandler).Methods("POST")

	loggedRouter := loggingMiddleware(router)

	fmt.Printf("API Server running on http://0.0.0.0%s\n", apiPort)
	log.Fatal(http.ListenAndServe(apiPort, loggedRouter))
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

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if _, exists := users[req.Username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}
	hashed, err := hashPassword(req.Password)
	if err != nil {
		http.Error(w, "Error processing password", http.StatusInternalServerError)
		return
	}
	users[req.Username] = hashed
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	hashed, exists := users[req.Username]
	if !exists || !checkPasswordHash(req.Password, hashed) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: req.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}
	userTokens[req.Username] = tokenString
	json.NewEncoder(w).Encode(LoginResponse{Token: tokenString, Message: "Login successful"})
}

func validateTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"message": "Token valid", "username": claims.Username})
}

func registerProxyHandler(w http.ResponseWriter, r *http.Request) {
	var req ProxyConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// For demonstration, just echo back the config
	json.NewEncoder(w).Encode(map[string]string{"message": "Proxy registered", "target_url": req.TargetURL})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
