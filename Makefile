# Makefile for secure-proxy-server

API_IMAGE_NAME=dariyanto/api-gateway:latest
PROXY_IMAGE_NAME=dariyanto/proxy-server:latest

.PHONY: all build-api build-proxy docker-build-api docker-build-proxy

build: build-api build-proxy
deploy: docker-build-push

build-api:
	go build -o api-gateway ./api-gateway/api_gateway.go
build-proxy:
	go build -o proxy-server ./proxy-server/proxy_server.go

docker-build-api:
	docker build -t $(API_IMAGE_NAME) ./api-gateway
docker-build-proxy:
	docker build -t $(PROXY_IMAGE_NAME) ./proxy-server

docker-push-api:
	docker push $(API_IMAGE_NAME)
docker-push-proxy:
	docker push $(PROXY_IMAGE_NAME)

docker-push: docker-push-api docker-push-proxy
docker-build: docker-build-api docker-build-proxy
docker-build-push: docker-build docker-push
clean:
	rm -f api-gateway proxy-server
