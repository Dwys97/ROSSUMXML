import React, { createContext, useState, useEffect, useCallback, useRef } from 'react';
import { tokenStorage, INACTIVITY_TIMEOUT } from '../utils/tokenStorage';

export const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const inactivityTimerRef = useRef(null);

    const logout = useCallback(() => {
        tokenStorage.clearAuth();
        setUser(null);
        if (inactivityTimerRef.current) {
            clearTimeout(inactivityTimerRef.current);
            inactivityTimerRef.current = null;
        }
    }, []);

    const checkAuth = useCallback(async () => {
        const token = tokenStorage.getToken();
        const savedUser = tokenStorage.getUser();
        
        if (token && savedUser) {
            try {
                // Verify token is still valid by making a test request
                const response = await fetch('/api/user/profile', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                
                if (response.ok) {
                    setUser(savedUser);
                } else {
                    // Token is invalid, clear it
                    console.log('Token validation failed, clearing auth');
                    logout();
                }
            } catch (error) {
                console.error('Error validating token:', error);
                logout();
            }
        }
        setLoading(false);
    }, [logout]);

    const startInactivityTimer = useCallback(() => {
        // Clear existing timer
        if (inactivityTimerRef.current) {
            clearTimeout(inactivityTimerRef.current);
        }

        const timeUntilExpiry = tokenStorage.getTimeUntilExpiry();
        
        if (timeUntilExpiry > 0) {
            inactivityTimerRef.current = setTimeout(() => {
                console.log('⏱️ Session expired due to 1 hour of inactivity. Please log in again.');
                logout();
            }, timeUntilExpiry);
        } else if (timeUntilExpiry === 0 && tokenStorage.getToken()) {
            // Token has already expired
            console.log('⏱️ Session expired due to inactivity. Please log in again.');
            logout();
        }
    }, [logout]);

    const resetInactivityTimer = useCallback(() => {
        if (user) {
            tokenStorage.updateActivity();
            startInactivityTimer();
        }
    }, [user, startInactivityTimer]);

    useEffect(() => {
        checkAuth();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        if (!user) return;

        // Activity events to track
        const activityEvents = [
            'mousedown',
            'mousemove',
            'keypress',
            'scroll',
            'touchstart',
            'click'
        ];

        // Throttle activity updates to avoid excessive calls
        let activityTimeout = null;
        const handleActivity = () => {
            if (activityTimeout) return;
            
            activityTimeout = setTimeout(() => {
                resetInactivityTimer();
                activityTimeout = null;
            }, 1000); // Update at most once per second
        };

        // Add event listeners
        activityEvents.forEach(event => {
            document.addEventListener(event, handleActivity, true);
        });

        // Cleanup
        return () => {
            activityEvents.forEach(event => {
                document.removeEventListener(event, handleActivity, true);
            });
            if (activityTimeout) {
                clearTimeout(activityTimeout);
            }
            if (inactivityTimerRef.current) {
                clearTimeout(inactivityTimerRef.current);
            }
        };
    }, [user, resetInactivityTimer]);

    const login = useCallback((userData, token) => {
        tokenStorage.setToken(token);
        tokenStorage.setUser(userData);
        setUser(userData);
        startInactivityTimer();
    }, [startInactivityTimer]);

    return (
        <AuthContext.Provider value={{ user, login, logout, checkAuth, loading }}>
            {children}
        </AuthContext.Provider>
    );
};
