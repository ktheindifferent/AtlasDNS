import { useEffect, useState, useRef } from 'react';
import io, { Socket } from 'socket.io-client';

interface WebSocketMessage {
  type: string;
  data: any;
  timestamp: Date;
}

export const useWebSocket = (namespace: string = '/') => {
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    const wsUrl = process.env.REACT_APP_WS_URL || 'ws://localhost:5380';
    
    socketRef.current = io(`${wsUrl}${namespace}`, {
      transports: ['websocket'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
    });

    socketRef.current.on('connect', () => {
      setConnected(true);
      console.log(`Connected to WebSocket namespace: ${namespace}`);
    });

    socketRef.current.on('disconnect', () => {
      setConnected(false);
      console.log(`Disconnected from WebSocket namespace: ${namespace}`);
    });

    socketRef.current.on('message', (data: any) => {
      setMessages(prev => [...prev.slice(-99), {
        type: data.type || 'message',
        data: data.payload || data,
        timestamp: new Date(),
      }]);
    });

    socketRef.current.on('query-update', (data: any) => {
      setMessages(prev => [...prev.slice(-99), {
        type: 'query-update',
        data,
        timestamp: new Date(),
      }]);
    });

    socketRef.current.on('error', (error: any) => {
      console.error('WebSocket error:', error);
    });

    return () => {
      if (socketRef.current) {
        socketRef.current.disconnect();
      }
    };
  }, [namespace]);

  const sendMessage = (type: string, data: any) => {
    if (socketRef.current && connected) {
      socketRef.current.emit(type, data);
    }
  };

  return {
    connected,
    messages,
    sendMessage,
    socket: socketRef.current,
  };
};