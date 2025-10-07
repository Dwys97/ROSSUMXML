#!/bin/bash
echo "Starting database..."
docker-compose up -d db
docker-compose logs -f db