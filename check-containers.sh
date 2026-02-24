#!/bin/bash
# Check Docker container status and restart failed services

echo "📊 Docker Container Status:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker-compose ps

echo ""
echo "🔍 Checking for unhealthy or exited containers..."
echo ""

# Check specific services
SERVICES=(db redis backend worker docling-service qwen-service orchestrator-service label-studio)

for service in "${SERVICES[@]}"; do
    STATUS=$(docker-compose ps -q $service 2>/dev/null)
    if [ -z "$STATUS" ]; then
        echo "❌ $service is not running"
    else
        HEALTH=$(docker inspect --format='{{.State.Health.Status}}' $(docker-compose ps -q $service) 2>/dev/null || echo "no-health-check")
        if [ "$HEALTH" = "healthy" ] || [ "$HEALTH" = "no-health-check" ]; then
            echo "✅ $service is running"
        else
            echo "⚠️  $service is $HEALTH"
        fi
    fi
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "To restart all services: bash start-all-detached.sh"
echo "To view logs: docker-compose logs -f <service-name>"
