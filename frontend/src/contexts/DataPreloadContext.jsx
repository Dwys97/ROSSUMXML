import React, { createContext, useState, useEffect, useCallback, useContext } from 'react';
import { useAuth } from './useAuth';
import { tokenStorage } from '../utils/tokenStorage';

export const DataPreloadContext = createContext(null);

export const DataPreloadProvider = ({ children }) => {
    const { user } = useAuth();
    
    // API Settings data
    const [apiKeys, setApiKeys] = useState([]);
    const [webhookSettings, setWebhookSettings] = useState(null);
    const [deliverySettings, setDeliverySettings] = useState(null);
    const [mappings, setMappings] = useState([]);
    
    // User Profile data
    const [userProfile, setUserProfile] = useState(null);
    
    // Loading states
    const [apiSettingsLoading, setApiSettingsLoading] = useState(false);
    const [userProfileLoading, setUserProfileLoading] = useState(false);
    
    // Last loaded timestamps for cache invalidation
    const [lastApiSettingsLoad, setLastApiSettingsLoad] = useState(null);
    const [lastUserProfileLoad, setLastUserProfileLoad] = useState(null);

    const apiCall = async (endpoint, options = {}) => {
        const response = await fetch(`/api/api-settings${endpoint}`, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${tokenStorage.getToken()}`,
                ...options.headers
            }
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Request failed');
        }
        
        return response.json();
    };

    // Load API Settings data
    const loadApiSettings = useCallback(async (force = false) => {
        if (!user) return;
        
        // Don't reload if data is fresh (less than 30 seconds old) and not forced
        if (!force && lastApiSettingsLoad && Date.now() - lastApiSettingsLoad < 30000) {
            return;
        }
        
        setApiSettingsLoading(true);
        try {
            const [keysData, webhookData, deliveryData, mappingsData] = await Promise.all([
                apiCall('/keys').catch(() => []),
                apiCall('/webhook').catch(() => null),
                apiCall('/delivery').catch(() => null),
                apiCall('/mappings').catch(() => [])
            ]);
            
            setApiKeys(keysData);
            setWebhookSettings(webhookData);
            setDeliverySettings(deliveryData);
            setMappings(mappingsData);
            setLastApiSettingsLoad(Date.now());
        } catch (error) {
            console.error('Error preloading API settings:', error);
        } finally {
            setApiSettingsLoading(false);
        }
    }, [user, lastApiSettingsLoad]);

    // Load User Profile data
    const loadUserProfile = useCallback(async (force = false) => {
        if (!user) return;
        
        // Don't reload if data is fresh (less than 30 seconds old) and not forced
        if (!force && lastUserProfileLoad && Date.now() - lastUserProfileLoad < 30000) {
            return;
        }
        
        setUserProfileLoading(true);
        try {
            const response = await fetch('/api/user/profile', {
                headers: {
                    'Authorization': `Bearer ${tokenStorage.getToken()}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                setUserProfile(data);
                setLastUserProfileLoad(Date.now());
            }
        } catch (error) {
            console.error('Error preloading user profile:', error);
        } finally {
            setUserProfileLoading(false);
        }
    }, [user, lastUserProfileLoad]);

    // Preload all data when user logs in
    useEffect(() => {
        if (user) {
            loadApiSettings();
            loadUserProfile();
        } else {
            // Clear data when user logs out
            setApiKeys([]);
            setWebhookSettings(null);
            setDeliverySettings(null);
            setMappings([]);
            setUserProfile(null);
            setLastApiSettingsLoad(null);
            setLastUserProfileLoad(null);
        }
    }, [user, loadApiSettings, loadUserProfile]);

    // Invalidate API Settings cache
    const invalidateApiSettings = useCallback(() => {
        setLastApiSettingsLoad(null);
    }, []);

    // Invalidate User Profile cache
    const invalidateUserProfile = useCallback(() => {
        setLastUserProfileLoad(null);
    }, []);

    const value = {
        // API Settings
        apiKeys,
        setApiKeys,
        webhookSettings,
        setWebhookSettings,
        deliverySettings,
        setDeliverySettings,
        mappings,
        setMappings,
        apiSettingsLoading,
        loadApiSettings,
        invalidateApiSettings,
        
        // User Profile
        userProfile,
        setUserProfile,
        userProfileLoading,
        loadUserProfile,
        invalidateUserProfile
    };

    return (
        <DataPreloadContext.Provider value={value}>
            {children}
        </DataPreloadContext.Provider>
    );
};

// Custom hook to use the preload context
export const useDataPreload = () => {
    const context = useContext(DataPreloadContext);
    if (!context) {
        throw new Error('useDataPreload must be used within a DataPreloadProvider');
    }
    return context;
};
