#!/bin/bash
# Cleanup old migration files - keep only 012

cd "$(dirname "$0")/migrations"

echo "Cleaning up old migration files..."
echo ""

# Remove FINAL_complete_schema.sql
if [ -f "FINAL_complete_schema.sql" ]; then
    rm "FINAL_complete_schema.sql"
    echo "✓ Deleted FINAL_complete_schema.sql"
fi

# Remove archived directory
if [ -d "archived" ]; then
    rm -rf "archived"
    echo "✓ Deleted archived/ directory"
fi

echo ""
echo "Remaining files:"
ls -lh

echo ""
echo "✅ Cleanup complete!"
echo "   Only migration 012 remains"
