#!/bin/bash
# Health check for all services (containers + ports)

set -euo pipefail

check_container() {
	local service="$1"
	local label="$2"
	local cid
	cid=$(docker-compose ps -q "$service" 2>/dev/null)

	if [ -z "$cid" ]; then
		echo "❌ $label (not running)"
		return 1
	fi

	local status health
	status=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo "unknown")
	health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-health{{end}}' "$cid" 2>/dev/null || echo "unknown")

	if [[ "$status" == "running" && ("$health" == "healthy" || "$health" == "no-health") ]]; then
		echo "✅ $label (running${health:+, $health})"
		return 0
	fi

	echo "⚠️  $label (status: $status, health: $health)"
	return 1
}

check_http() {
	local label="$1"
	local url="$2"
	if curl -sf --max-time 5 "$url" >/dev/null; then
		echo "✅ $label"
	else
		echo "❌ $label"
	fi
}

check_tcp() {
	local label="$1"
	local host="$2"
	local port="$3"
	if timeout 3 bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1; then
		echo "✅ $label"
	else
		echo "❌ $label"
	fi
}

echo "🏥 Checking service health..."
echo ""

echo "📦 Infrastructure:"
check_container db "PostgreSQL"
check_container redis "Redis"

echo ""
echo "🤖 SmolDocling + Qwen2.5 Microservices:"
check_container docling-service "SmolDocling (container)"
check_http "SmolDocling (HTTP)" "http://localhost:5004/health"
check_container qwen-service "Qwen2.5 (container)"
check_http "Qwen2.5 (HTTP)" "http://localhost:5006/health"
check_container orchestrator-service "Orchestrator (container)"
check_http "Orchestrator (HTTP)" "http://localhost:8000/health"
check_container label-studio "Label Studio (container)"
check_http "Label Studio (HTTP)" "http://localhost:8080/api/health"

echo ""
echo "🌐 Application:"
check_container backend "Backend (container)"
check_http "Backend (HTTP)" "http://localhost:3000"
check_container worker "Worker (container)"
check_tcp "Socket.io (tcp:3001)" "localhost" 3001
check_http "Frontend (HTTP)" "http://localhost:5173"
