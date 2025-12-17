
# Secure Proxy Server (Go + Docker)

This project provides a secure, containerized proxy solution with two Go-based services:

- **API Gateway**: Issues JWT tokens and acts as an authentication entry point.
- **Proxy Server**: Forwards HTTP(S) requests to target servers, validating JWT tokens for secure access.

## Features

- Secure proxying of HTTP/HTTPS requests
- JWT-based authentication and authorization
- Easy deployment with Docker Compose
- Modular Go codebase

## Architecture

```
Client → API Gateway (JWT issuance) → Proxy Server (JWT validation, request forwarding) → Target Service
```

## Prerequisites

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/)
- (Optional) [Go 1.25+](https://golang.org/dl/) for local builds

## Getting Started

### 1. Clone the repository

```sh
git clone https://github.com/dariyanto/secure-proxy-server.git
cd secure-proxy-server
```

### 2. Build and Run with Docker Compose

```sh
docker-compose up --build
```

This will start both the API Gateway (on port 8081) and Proxy Server (on port 8080).

### 3. Build Locally (Optional)

You can also build the binaries directly:

```sh
make build
./api-gateway & ./proxy-server &
```

Or build Docker images individually:

```sh
make docker-build
```

## Usage

### 1. Obtain a JWT Token

Send a POST request to the API Gateway:

```sh
curl -X POST http://localhost:8081/api/generate-token
```

### 2. Use the Proxy Server

Send requests to the Proxy Server with the JWT token in the `Authorization` header:

```sh
curl -H "Authorization: Bearer <your-jwt-token>" -X POST \
  -d '{"target":"http://example.com"}' \
  http://localhost:8080/proxy
```

## Configuration

- Ports can be changed in the source code or Docker Compose file.
- Place your `private.pem` and `public.pem` keys in the respective service directories if required.

## Development

- API Gateway code: `api-gateway/api_gateway.go`
- Proxy Server code: `proxy-server/proxy_server.go`
- Build and deployment: `Makefile`, `docker-compose.yml`

## License

MIT License
