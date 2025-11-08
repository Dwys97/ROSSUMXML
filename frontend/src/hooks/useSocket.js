/**
 * useSocket Hook
 * React hook for managing Socket.io connection and events
 */

import { useEffect, useRef, useState } from 'react';
import { io } from 'socket.io-client';

const SOCKET_URL = import.meta.env.VITE_API_URL?.replace('/api', '') || 'http://localhost:3000';

/**
 * Hook for Socket.io connection
 * @param {Object} options - Socket options
 * @returns {Object} Socket instance and connection status
 */
export function useSocket(options = {}) {
    const [isConnected, setIsConnected] = useState(false);
    const socketRef = useRef(null);

    useEffect(() => {
        // Create socket connection
        socketRef.current = io(SOCKET_URL, {
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 10,
            ...options
        });

        const socket = socketRef.current;

        // Connection events
        socket.on('connect', () => {
            console.log('✅ Socket.io connected');
            setIsConnected(true);
        });

        socket.on('disconnect', () => {
            console.log('❌ Socket.io disconnected');
            setIsConnected(false);
        });

        socket.on('connect_error', (error) => {
            console.error('Socket.io connection error:', error);
            setIsConnected(false);
        });

        // Cleanup on unmount
        return () => {
            if (socket) {
                socket.disconnect();
            }
        };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return {
        socket: socketRef.current,
        isConnected
    };
}

/**
 * Hook for extraction real-time updates
 * @param {string} invoiceId - Invoice UUID
 * @param {Object} callbacks - Event callbacks
 * @returns {Object} Socket instance and extraction state
 */
export function useExtractionSocket(invoiceId, callbacks = {}) {
    const { socket, isConnected } = useSocket();
    const [extractionState, setExtractionState] = useState({
        progress: 0,
        stage: '',
        isExtracting: false,
        hasError: false,
        errorMessage: null,
        result: null
    });

    useEffect(() => {
        if (!socket || !invoiceId) return;

        // Join invoice room
        socket.emit('join:invoice', invoiceId);
        console.log(`Joined room: invoice:${invoiceId}`);

        // Listen for extraction events
        socket.on('extraction:started', (data) => {
            console.log('Extraction started:', data);
            setExtractionState({
                progress: 0,
                stage: 'Starting extraction...',
                isExtracting: true,
                hasError: false,
                errorMessage: null,
                result: null
            });
            callbacks.onStarted?.(data);
        });

        socket.on('extraction:progress', (data) => {
            console.log('Extraction progress:', data);
            setExtractionState(prev => ({
                ...prev,
                progress: data.progress,
                stage: data.stage,
                isExtracting: true
            }));
            callbacks.onProgress?.(data);
        });

        socket.on('extraction:completed', (data) => {
            console.log('Extraction completed:', data);
            setExtractionState({
                progress: 100,
                stage: 'Completed',
                isExtracting: false,
                hasError: false,
                errorMessage: null,
                result: data.result
            });
            callbacks.onCompleted?.(data);
        });

        socket.on('extraction:failed', (data) => {
            console.error('Extraction failed:', data);
            setExtractionState({
                progress: 0,
                stage: 'Failed',
                isExtracting: false,
                hasError: true,
                errorMessage: data.error,
                result: null
            });
            callbacks.onFailed?.(data);
        });

        // Cleanup
        return () => {
            socket.emit('leave:invoice', invoiceId);
            socket.off('extraction:started');
            socket.off('extraction:progress');
            socket.off('extraction:completed');
            socket.off('extraction:failed');
        };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [socket, invoiceId]);

    return {
        socket,
        isConnected,
        extractionState,
        resetExtractionState: () => setExtractionState({
            progress: 0,
            stage: '',
            isExtracting: false,
            hasError: false,
            errorMessage: null,
            result: null
        })
    };
}

/**
 * Hook for training real-time updates
 * @param {string} vendorId - Vendor profile UUID
 * @param {Object} callbacks - Event callbacks
 * @returns {Object} Socket instance and training state
 */
export function useTrainingSocket(vendorId, callbacks = {}) {
    const { socket, isConnected } = useSocket();
    const [trainingState, setTrainingState] = useState({
        progress: 0,
        stage: '',
        isTraining: false,
        hasError: false,
        errorMessage: null,
        metrics: null
    });

    useEffect(() => {
        if (!socket || !vendorId) return;

        // Join vendor room
        socket.emit('join:vendor', vendorId);

        // Listen for training events
        socket.on('training:started', (data) => {
            setTrainingState({
                progress: 0,
                stage: 'Starting training...',
                isTraining: true,
                hasError: false,
                errorMessage: null,
                metrics: null
            });
            callbacks.onStarted?.(data);
        });

        socket.on('training:progress', (data) => {
            setTrainingState(prev => ({
                ...prev,
                progress: data.progress,
                stage: data.stage,
                isTraining: true
            }));
            callbacks.onProgress?.(data);
        });

        socket.on('training:completed', (data) => {
            setTrainingState({
                progress: 100,
                stage: 'Completed',
                isTraining: false,
                hasError: false,
                errorMessage: null,
                metrics: data.metrics
            });
            callbacks.onCompleted?.(data);
        });

        // Cleanup
        return () => {
            socket.emit('leave:vendor', vendorId);
            socket.off('training:started');
            socket.off('training:progress');
            socket.off('training:completed');
        };
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [socket, vendorId]);

    return {
        socket,
        isConnected,
        trainingState
    };
}
