import React, { createContext, useContext, useEffect, useState, useRef, ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';
import { useSelector } from 'react-redux';
import { RootState } from '../store';

interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: number;
}

interface WebSocketContextType {
  socket: Socket | null;
  connected: boolean;
  messages: WebSocketMessage[];
  sendMessage: (type: string, data: any) => void;
  subscribe: (event: string, handler: (data: any) => void) => void;
  unsubscribe: (event: string, handler: (data: any) => void) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};

interface WebSocketProviderProps {
  children: ReactNode;
}

export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({ children }) => {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const messageQueueRef = useRef<WebSocketMessage[]>([]);
  const { token } = useSelector((state: RootState) => state.auth);

  useEffect(() => {
    if (!token) {
      return;
    }

    const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:5380';
    const newSocket = io(wsUrl, {
      auth: {
        token,
      },
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
    });

    newSocket.on('connect', () => {
      console.log('WebSocket connected');
      setConnected(true);
      
      // Send any queued messages
      while (messageQueueRef.current.length > 0) {
        const msg = messageQueueRef.current.shift();
        if (msg) {
          newSocket.emit(msg.type, msg.data);
        }
      }
    });

    newSocket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setConnected(false);
    });

    newSocket.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    // Listen for various event types
    const eventTypes = [
      'query-update',
      'zone-update',
      'alert',
      'metric-update',
      'cache-update',
      'health-check-update',
    ];

    eventTypes.forEach((eventType) => {
      newSocket.on(eventType, (data) => {
        const message: WebSocketMessage = {
          type: eventType,
          data,
          timestamp: Date.now(),
        };
        setMessages((prev) => [...prev.slice(-99), message]); // Keep last 100 messages
      });
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [token]);

  const sendMessage = (type: string, data: any) => {
    const message: WebSocketMessage = {
      type,
      data,
      timestamp: Date.now(),
    };

    if (socket && connected) {
      socket.emit(type, data);
    } else {
      // Queue message if not connected
      messageQueueRef.current.push(message);
    }
  };

  const subscribe = (event: string, handler: (data: any) => void) => {
    if (socket) {
      socket.on(event, handler);
    }
  };

  const unsubscribe = (event: string, handler: (data: any) => void) => {
    if (socket) {
      socket.off(event, handler);
    }
  };

  const value: WebSocketContextType = {
    socket,
    connected,
    messages,
    sendMessage,
    subscribe,
    unsubscribe,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};