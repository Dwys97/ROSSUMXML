import React, { createContext, useContext, useEffect, useState, useRef } from 'react';
import { io } from 'socket.io-client';

const SocketContext = createContext(null);

export const useSocket = () => {
    const context = useContext(SocketContext);
    if (!context) {
        throw new Error('useSocket must be used within SocketProvider');
    }
    return context;
};

export const SocketProvider = ({ children }) => {
    const [socket, setSocket] = useState(null);
    const [connected, setConnected] = useState(false);
    const socketRef = useRef(null);

    useEffect(() => {
        // Prevent creating multiple socket instances (HMR-safe)
        if (socketRef.current) {
            setSocket(socketRef.current);
            setConnected(socketRef.current.connected);
            return;
        }

        // Use current origin (works in both localhost and Codespaces)
        // Vite will proxy /socket.io to localhost:3001
        const socketUrl = window.location.origin; // e.g., https://...app.github.dev or http://localhost:5173
        console.log('[Socket.IO] Connecting to:', socketUrl);

        // Initialize socket connection. Prefer polling first in dev to avoid websocket transport issues.
        const socketInstance = io(socketUrl, {
            path: '/socket.io',
            transports: ['polling', 'websocket'],
            reconnection: true,
            // keep retrying during development
            reconnectionAttempts: Infinity,
            reconnectionDelay: 1000,
            autoConnect: true
        });

        socketInstance.on('connect', () => {
            console.log('[Socket.IO] Connected:', socketInstance.id);
            setConnected(true);
        });

        socketInstance.on('disconnect', (reason) => {
            console.log('[Socket.IO] Disconnected', reason);
            setConnected(false);
        });

        socketInstance.on('connect_error', (err) => {
            console.error('[Socket.IO] Connection error:', err);
        });

        socketRef.current = socketInstance;
        setSocket(socketInstance);

        // Keep socket alive across HMR mounts; only disconnect on page unload
        const handleBeforeUnload = () => {
            try {
                socketInstance.disconnect();
            } catch (e) {
                console.warn('[Socket.IO] Error disconnecting on unload', e);
            }
        };
        window.addEventListener('beforeunload', handleBeforeUnload);

        // Do not disconnect during component unmount (avoids HMR double-connects)
        return () => {
            window.removeEventListener('beforeunload', handleBeforeUnload);
        };
    }, []);

    const joinInvoice = (invoiceId) => {
        if (socket && connected) {
            console.log(`[Socket.IO] Joining invoice room: ${invoiceId}`);
            socket.emit('join-invoice', invoiceId);
        }
    };

    const leaveInvoice = (invoiceId) => {
        if (socket && connected) {
            console.log(`[Socket.IO] Leaving invoice room: ${invoiceId}`);
            socket.emit('leave-invoice', invoiceId);
        }
    };

    const onFieldUpdate = (callback) => {
        if (socket) {
            socket.on('extraction:field-update', callback);
            return () => socket.off('extraction:field-update', callback);
        }
        return () => {};
    };

    const value = {
        socket,
        connected,
        joinInvoice,
        leaveInvoice,
        onFieldUpdate
    };

    return (
        <SocketContext.Provider value={value}>
            {children}
        </SocketContext.Provider>
    );
};
