FROM golang:1.25.5-alpine
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o api-gateway api_gateway.go
CMD ["./api-gateway"]
