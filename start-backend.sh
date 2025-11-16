#!/bin/bash

# Ensure Docker socket is accessible
export DOCKER_HOST=unix:///var/run/docker.sock

cd backend
sam local start-api --port 3000 --docker-network rossumxml_default
