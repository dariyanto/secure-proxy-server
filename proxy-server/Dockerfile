FROM golang:1.21-alpine
WORKDIR /app
# Copy go.mod and go.sum first for better build caching
COPY go.mod .
COPY go.sum .
RUN go mod download
# Copy the source code
COPY ../proxy_server.go .
RUN go build -o proxy-server proxy_server.go
CMD ["./proxy-server"]
