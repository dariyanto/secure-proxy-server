FROM golang:1.25.5-alpine
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o proxy-server proxy_server.go
CMD ["./proxy-server"]
