import React, { useState, useEffect } from 'react';
import AuthContext from './auth-context';

export function AuthProvider({ children }) {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    // Load user data on mount
    useEffect(() => {
        checkAuth();
    }, []);

    // Check authentication status
    const checkAuth = async () => {
        const token = localStorage.getItem('token');
        const savedUser = localStorage.getItem('user');

        if (!token) {
            setLoading(false);
            return;
        }

        // Use saved user data immediately if available
        if (savedUser) {
            try {
                const userData = JSON.parse(savedUser);
                setUser(userData);
                
                // Silent profile check in background
                fetch('/api/user/profile', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                })
                .then(response => {
                    if (response.ok) {
                        return response.json();
                    }
                })
                .then(data => {
                    if (data) {
                        setUser(data);
                        localStorage.setItem('user', JSON.stringify(data));
                    }
                })
                .catch(error => {
                    console.warn('Silent profile check failed:', error);
                });
                
            } catch (error) {
                console.error('Failed to parse saved user data:', error);
            }
        } else {
            // Try to get fresh profile data
            try {
                const response = await fetch('/api/user/profile', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (response.ok) {
                    const data = await response.json();
                    setUser(data);
                    localStorage.setItem('user', JSON.stringify(data));
                } else {
                    throw new Error('Failed to get user profile');
                }
            } catch (error) {
                console.error('Auth check failed:', error);
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                setUser(null);
            }
        }
        
        setLoading(false);
    };

    // Login function
    const login = async (userData, token) => {
        try {
            // First set the token
            localStorage.setItem('token', token);
            // Then save user data
            localStorage.setItem('user', JSON.stringify(userData));
            // Finally update the state
            setUser(userData);
            // Return success
            return true;
        } catch (error) {
            console.error('Login state management failed:', error);
            // Clean up on error
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            setUser(null);
            return false;
        }
    };

    // Logout function
    const logout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setUser(null);
    };

    return (
        <AuthContext.Provider value={{ user, login, logout, loading, checkAuth }}>
            {loading ? <div>Loading...</div> : children}
        </AuthContext.Provider>
    );
}
