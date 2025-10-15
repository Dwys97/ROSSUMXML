#!/bin/bash

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 Browser Cache Debugging - Template Selector Not Visible"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Step 1: Verify code exists in source file..."
if grep -q "templateSelectorSection" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo "✅ Template selector code found in source file"
    LINES=$(grep -n "templateSelectorSection\|Choose from Template Library" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx | head -3)
    echo "$LINES"
else
    echo "❌ Template selector code NOT found!"
    exit 1
fi

echo ""
echo "Step 2: Check if templates state variables exist..."
if grep -q "const \[templates, setTemplates\]" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo "✅ Templates state variable found"
else
    echo "❌ Templates state variable NOT found!"
    exit 1
fi

echo ""
echo "Step 3: Verify loadTemplates function exists..."
if grep -q "const loadTemplates" /workspaces/ROSSUMXML/frontend/src/pages/ApiSettingsPage.jsx; then
    echo "✅ loadTemplates function found"
else
    echo "❌ loadTemplates function NOT found!"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚨 BROWSER CACHE ISSUE DETECTED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "The code is in the file but not appearing in your browser."
echo "This is a BROWSER CACHING issue."
echo ""
echo "Solutions:"
echo ""
echo "1️⃣  HARD REFRESH (Recommended):"
echo "   • Windows/Linux: Ctrl + Shift + R"
echo "   • Mac: Cmd + Shift + R"
echo "   • Or Ctrl+F5 / Cmd+F5"
echo ""
echo "2️⃣  CLEAR BROWSER CACHE:"
echo "   • Chrome: F12 → Network tab → Check 'Disable cache'"
echo "   • Then refresh (F5)"
echo ""
echo "3️⃣  OPEN IN INCOGNITO/PRIVATE MODE:"
echo "   • Ctrl+Shift+N (Chrome) or Ctrl+Shift+P (Firefox)"
echo "   • Navigate to http://localhost:5173/api-settings"
echo ""
echo "4️⃣  MANUAL CACHE CLEAR:"
echo "   • Chrome: Settings → Privacy → Clear browsing data"
echo "   • Check 'Cached images and files'"
echo "   • Time range: Last hour"
echo "   • Click 'Clear data'"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "After clearing cache, you should see:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "In the 'Create New Mapping' modal:"
echo "  📚 Choose from Template Library or Upload Custom:"
echo "  [Dropdown with: -- Custom Upload --, 🚢 Logistics, 💼 ERP]"
echo ""
echo "If you still don't see it after hard refresh:"
echo "  • Open DevTools (F12)"
echo "  • Go to Console tab"
echo "  • Look for any red error messages"
echo "  • Share the error with me"
echo ""
