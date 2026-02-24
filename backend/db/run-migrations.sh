#!/bin/bash

# ============================================================================
# Database Migration Runner (Legacy - Use run-final-migration.sh instead)
# ============================================================================
# This script redirects to the new final migration system
# ============================================================================

set -e

echo "============================================"
echo "⚠️  NOTICE: Using legacy migration script"
echo "============================================"
echo ""
echo "This script redirects to the new final migration system."
echo "Please use 'run-final-migration.sh' directly in the future."
echo ""
echo "Redirecting to run-final-migration.sh..."
echo ""

SCRIPT_DIR="$(dirname "$0")"

# Redirect to the new script
exec "$SCRIPT_DIR/run-final-migration.sh"
