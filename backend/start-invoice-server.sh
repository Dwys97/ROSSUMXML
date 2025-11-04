#!/bin/bash
# Start Invoice API Server (Express, port 3001)

cd "$(dirname "$0")"
export INVOICE_PORT=3001
export POSTGRES_HOST=$(bash get-db-host.sh)

echo "🚀 Starting Invoice API Server on port 3001..."
echo "📊 Database host: $POSTGRES_HOST"

node invoice-server.js
