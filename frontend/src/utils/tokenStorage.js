// Token storage utility with expiration tracking
// For web browser users only - API keys are handled separately

const TOKEN_KEY = 'token';
const USER_KEY = 'user';
const TOKEN_TIMESTAMP_KEY = 'token_timestamp';
const LAST_ACTIVITY_KEY = 'last_activity';

// 1 hour inactivity timeout (in milliseconds)
export const INACTIVITY_TIMEOUT = 60 * 60 * 1000; // 1 hour

export const tokenStorage = {
    // Set token with current timestamp
    setToken(token) {
        const now = Date.now();
        localStorage.setItem(TOKEN_KEY, token);
        localStorage.setItem(TOKEN_TIMESTAMP_KEY, now.toString());
        localStorage.setItem(LAST_ACTIVITY_KEY, now.toString());
    },

    // Get token if it's still valid (not expired due to inactivity)
    getToken() {
        const token = localStorage.getItem(TOKEN_KEY);
        if (!token) return null;

        const lastActivity = localStorage.getItem(LAST_ACTIVITY_KEY);
        if (!lastActivity) return null;

        const now = Date.now();
        const timeSinceActivity = now - parseInt(lastActivity, 10);

        // Check if token has expired due to inactivity
        if (timeSinceActivity > INACTIVITY_TIMEOUT) {
            this.clearAuth();
            return null;
        }

        return token;
    },

    // Update last activity timestamp
    updateActivity() {
        const token = localStorage.getItem(TOKEN_KEY);
        if (token) {
            localStorage.setItem(LAST_ACTIVITY_KEY, Date.now().toString());
        }
    },

    // Set user data
    setUser(userData) {
        localStorage.setItem(USER_KEY, JSON.stringify(userData));
    },

    // Get user data
    getUser() {
        const userStr = localStorage.getItem(USER_KEY);
        if (!userStr) return null;
        
        try {
            return JSON.parse(userStr);
        } catch {
            return null;
        }
    },

    // Get time remaining before auto-logout (in milliseconds)
    getTimeUntilExpiry() {
        const lastActivity = localStorage.getItem(LAST_ACTIVITY_KEY);
        if (!lastActivity) return 0;

        const now = Date.now();
        const timeSinceActivity = now - parseInt(lastActivity, 10);
        const timeRemaining = INACTIVITY_TIMEOUT - timeSinceActivity;

        return Math.max(0, timeRemaining);
    },

    // Check if token exists and is valid
    isAuthenticated() {
        return this.getToken() !== null;
    },

    // Clear all auth data
    clearAuth() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        localStorage.removeItem(TOKEN_TIMESTAMP_KEY);
        localStorage.removeItem(LAST_ACTIVITY_KEY);
    }
};
