# AI Button Not Showing - Debug & Fix

## Problem
The AI Suggest button was not appearing in the Editor page.

## Root Cause
The button visibility is controlled by the `hasAIAccess` prop, which comes from the `useAIFeatures()` hook. This hook calls `/api/ai/check-access` which requires:
1. User to be logged in (JWT token)
2. User to have Pro or Enterprise subscription

Since these conditions weren't met during testing, the button was hidden.

## Temporary Fix Applied

### Changed Files:
1. **`frontend/src/pages/EditorPage.jsx`**

### Changes Made:

#### 1. Added Testing Override (Line ~66)
```javascript
// TEMPORARY: Override for testing - always show AI button
const showAIButton = true; // Change to hasAIAccess for production
```

#### 2. Added Debug Logging (Line ~69)
```javascript
useEffect(() => {
    console.log('🔍 AI Feature Debug:', {
        hasAIAccess,
        aiAccessLoading,
        showAIButton,
        token: !!localStorage.getItem('token')
    });
}, [hasAIAccess, aiAccessLoading]);
```

#### 3. Updated SchemaTree Props (Line ~643)
```javascript
hasAIAccess={showAIButton}  // Was: hasAIAccess={hasAIAccess}
```

#### 4. Disabled Access Check in Handler (Line ~278)
```javascript
// TEMPORARY: Skip access check for testing
// if (!hasAIAccess) {
//     setShowUpgradePrompt(true);
//     return;
// }
```

#### 5. Added Console Logging
```javascript
console.log('🎯 AI Suggest clicked for:', targetNode);
console.log('📊 Source nodes found:', sourceNodes.length);
console.log('🚀 Calling AI API...');
console.log('✅ AI Response:', result);
```

## Result

✅ **AI button now ALWAYS shows** on target leaf nodes regardless of:
- User login status
- Subscription level
- API access check

## Testing Now

1. **Refresh the browser** at http://localhost:5173/editor
2. **Upload XML files** (Source and Target)
3. **Look for the purple "✨ AI Suggest" button** next to target elements
4. **Open browser console** (F12) to see debug logs
5. **Click the button** to test the AI functionality

## What to Check in Browser Console

You should see:
```
🔍 AI Feature Debug: {hasAccess: false, aiAccessLoading: false, showAIButton: true, token: false}
```

When you click the AI button:
```
🎯 AI Suggest clicked for: {name: "...", path: "...", ...}
📊 Source nodes found: 15
🚀 Calling AI API...
```

## Known Issues with This Temporary Fix

⚠️ **This is for TESTING ONLY**. The button will try to call the AI API even without authentication, which will fail with a 401 Unauthorized error.

To fix this properly, you need:

### Option 1: Quick Test (Skip Auth)
Temporarily modify the backend to not require auth for AI endpoints (NOT RECOMMENDED for production).

### Option 2: Proper Test (Create Test User)
1. Create a user account
2. Login to get JWT token
3. Add Pro subscription to database:
```sql
INSERT INTO subscriptions (user_id, level, status)
VALUES (YOUR_USER_ID, 'pro', 'active');
```
4. Refresh page
5. AI button will show and work properly

### Option 3: Mock AI Response (Frontend Only)
Comment out the API call and use a mock response:
```javascript
// Mock response for testing
const result = {
    suggestion: {
        sourceElement: sourceNodes[0].path,
        targetElement: targetNode.path,
        confidence: 0.95,
        reasoning: "Mock AI suggestion for testing UI"
    }
};
setAiSuggestion(result.suggestion);
```

## Reverting to Production Code

When ready for production, change:

1. **Line ~66**: 
```javascript
const showAIButton = hasAIAccess; // Change true back to hasAIAccess
```

2. **Line ~278**: Uncomment the access check:
```javascript
if (!hasAIAccess) {
    setShowUpgradePrompt(true);
    return;
}
```

3. **Line ~643**: Use original prop:
```javascript
hasAIAccess={hasAIAccess}  // Change showAIButton back to hasAIAccess
```

4. **Remove debug console.logs** (optional but recommended)

## Why Button Wasn't Showing Before

The button requires ALL of these to be true:
1. ✅ `!isSource` - Target node (RIGHT side tree)
2. ✅ `!hasChildren` - Leaf node (no child elements)
3. ❌ `hasAIAccess` - User has Pro/Enterprise subscription (WAS FALSE)
4. ✅ `onAISuggest` - Handler function is provided

Since #3 was false, the button was hidden.

## Current State

✅ Button now shows on ALL target leaf nodes
✅ Debug logging active
✅ Can test UI components
⚠️ AI API calls will fail without proper auth
⚠️ Need to revert changes before production

## Next Steps

1. **See the button?** → Success! UI is working
2. **Button still not showing?** → Check browser console for errors
3. **Button shows but API fails?** → Expected! Need proper auth or mock response
4. **Ready to test with real AI?** → Set up user account with Pro subscription

---

**Status**: ✅ Debug mode active  
**Button Visibility**: Force enabled  
**Auth Check**: Disabled  
**Purpose**: UI testing only  
**Production Ready**: ❌ Needs revert
