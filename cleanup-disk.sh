#!/bin/bash

echo "🧹 Disk Cleanup Options"
echo "======================="
echo ""
echo "Current disk usage:"
df -h /workspaces | tail -1
echo ""
echo "Docker usage:"
docker system df
echo ""
echo ""
echo "Choose cleanup actions:"
echo ""
echo "1. Clean Docker build cache (188MB) - SAFE"
echo "2. Remove unused Docker images (798MB potential) - CAREFUL"
echo "3. Remove setup logs (450KB) - SAFE"
echo "4. Prune everything (images + cache) - AGGRESSIVE"
echo "5. Show detailed Docker image list"
echo "6. Exit"
echo ""
read -p "Enter option (1-6): " choice

case $choice in
    1)
        echo "🗑️  Cleaning Docker build cache..."
        docker builder prune -f
        echo "✅ Done! Freed build cache space"
        ;;
    2)
        echo "⚠️  This will remove unused Docker images (dangling images only)"
        docker image prune -f
        echo "✅ Done!"
        ;;
    3)
        echo "🗑️  Removing setup logs..."
        rm -f /workspaces/ROSSUMXML/setup*.log
        echo "✅ Removed setup logs"
        ;;
    4)
        echo "⚠️  AGGRESSIVE CLEANUP: This will remove:"
        echo "   - Unused images"
        echo "   - Build cache"
        echo "   - Stopped containers"
        echo ""
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" == "yes" ]; then
            docker system prune -af
            rm -f /workspaces/ROSSUMXML/setup*.log
            echo "✅ Aggressive cleanup complete!"
        else
            echo "❌ Cancelled"
        fi
        ;;
    5)
        echo ""
        echo "Docker images by size:"
        docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | sort -k3 -hr
        ;;
    6)
        echo "👋 Exiting"
        exit 0
        ;;
    *)
        echo "❌ Invalid option"
        exit 1
        ;;
esac

echo ""
echo "New disk usage:"
df -h /workspaces | tail -1
