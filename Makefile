# Makefile for secure-proxy-server

IMAGE_NAME=dariyanto/secure-proxy-server:latest

.PHONY: build push deploy

build:
	docker build -t $(IMAGE_NAME) .

push:
	docker push $(IMAGE_NAME)

deploy: build push

# Usage:
# make build   # Build the Docker image
# make push    # Push the image to Docker Hub
# make deploy  # Build and push in one step
