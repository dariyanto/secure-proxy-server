# Start from the official Golang image for building
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the Go app
RUN go build -o secure-proxy-server main.go

# Use a minimal image for running
FROM alpine:latest
WORKDIR /root/

# Copy the binary from the builder
COPY --from=builder /app/secure-proxy-server .

# Expose ports 8080 and 8081
EXPOSE 8080 8081

# Run the binary
CMD ["./secure-proxy-server"]
