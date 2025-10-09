# Auto-Logout Implementation (Web Browser Only)

## Overview
This document describes the implementation of automatic user logout after 1 hour of inactivity for web browser users.

## How It Works

### 1. **Time-Limited Token Storage**
- Tokens are stored in `localStorage` with activity timestamps
- Every user interaction updates the `last_activity` timestamp
- Tokens expire after **1 hour (3600 seconds) of inactivity**

### 2. **Activity Tracking**
The system tracks the following user activities to reset the inactivity timer:
- Mouse movements
- Mouse clicks
- Keyboard presses
- Scrolling
- Touch events (for mobile/tablet)

### 3. **Activity Updates are Throttled**
- Activity updates are throttled to once per second to avoid excessive processing
- This ensures smooth performance while still maintaining accurate activity tracking

## Key Files

### `/frontend/src/utils/tokenStorage.js`
Central utility for managing time-limited token storage:
- `setToken(token)` - Stores token with current timestamp
- `getToken()` - Returns token only if it hasn't expired due to inactivity
- `updateActivity()` - Updates the last activity timestamp
- `getTimeUntilExpiry()` - Returns milliseconds until auto-logout
- `clearAuth()` - Clears all auth data

### `/frontend/src/contexts/AuthContext.jsx`
Enhanced authentication context with:
- Automatic inactivity timer management
- Activity event listeners
- Auto-logout when timer expires
- Activity reset on user interaction

### `/frontend/src/components/common/SessionTimer.jsx` (Optional)
Visual component to warn users before auto-logout:
- Shows warning when less than 5 minutes remain (configurable)
- Displays countdown timer
- Can be added to any authenticated page

**Usage Example:**
```jsx
import { SessionTimer } from '../components/common/SessionTimer';

function MyPage() {
    return (
        <div>
            <SessionTimer showWarning={true} warningMinutes={5} />
            {/* Rest of your page */}
        </div>
    );
}
```

## User Experience

### For Web Browser Users
1. **Login** - User logs in normally, token + activity timestamp stored
2. **Active Session** - Any interaction (click, type, scroll) resets the 1-hour timer
3. **Inactivity** - After 1 hour with no interaction, user is automatically logged out
4. **Message** - Console message: "⏱️ Session expired due to 1 hour of inactivity. Please log in again."
5. **Redirect** - User is redirected to login page (handled by `ProtectedRoute`)

### For API Users (Future Implementation)
- API keys will have separate validation logic
- API keys remain valid until manually refreshed in user profile
- This distinction ensures API automation is not interrupted by inactivity timeouts

## Configuration

To change the inactivity timeout, modify the constant in `/frontend/src/utils/tokenStorage.js`:

```javascript
// Current: 1 hour = 60 minutes * 60 seconds * 1000 milliseconds
export const INACTIVITY_TIMEOUT = 60 * 60 * 1000;

// Examples:
// 30 minutes: 30 * 60 * 1000
// 2 hours: 120 * 60 * 1000
// 15 minutes: 15 * 60 * 1000
```

## Testing

### Manual Testing Steps
1. **Login** to the application
2. **Verify Active Session**:
   - Use the app normally
   - Check browser console - should see activity updates (throttled to 1/sec)
3. **Test Inactivity**:
   - Leave browser tab inactive for 1 hour
   - Return to tab - should be automatically logged out
4. **Test Page Refresh**:
   - Login again
   - Refresh page immediately - should remain logged in
   - Wait 1 hour, then refresh - should be logged out

### Developer Testing
Open browser console and run:

```javascript
// Check time until logout (in milliseconds)
const tokenStorage = require('./utils/tokenStorage').tokenStorage;
console.log('Time until logout:', tokenStorage.getTimeUntilExpiry() / 1000 / 60, 'minutes');

// Force immediate expiry (for testing)
localStorage.setItem('last_activity', Date.now() - (61 * 60 * 1000)); // 61 minutes ago
// Then refresh page or trigger checkAuth
```

## Security Benefits

1. **Prevents Unauthorized Access** - Unattended browsers automatically logout
2. **Shared Computer Safety** - Users who forget to logout are protected
3. **Session Hijacking Mitigation** - Stolen tokens expire after inactivity
4. **Compliance** - Meets security requirements for financial/healthcare applications

## Backwards Compatibility

- Existing tokens from before this update will still work
- On first load, they will be migrated to the new time-limited system
- No manual user action required

## Notes

- The JWT token issued by the backend has a 24-hour expiration (configured in `backend/routes/auth.routes.js`)
- The frontend 1-hour inactivity timeout is more restrictive and takes precedence
- This provides defense-in-depth security (frontend + backend validation)
