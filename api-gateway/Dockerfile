FROM golang:1.21-alpine
WORKDIR /app
# Copy go.mod and go.sum first for better build caching
COPY go.mod .
COPY go.sum .
RUN go mod download
# Copy the source code
COPY ../api_gateway.go .
RUN go build -o api-gateway api_gateway.go
CMD ["./api-gateway"]
