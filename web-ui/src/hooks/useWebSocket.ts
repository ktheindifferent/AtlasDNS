import { useState, useEffect } from 'react';

interface WebSocketMessage {
  type: string;
  data: any;
}

export const useWebSocket = (path: string) => {
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    // Placeholder WebSocket implementation
    setConnected(true);
    
    // Simulate receiving messages
    const interval = setInterval(() => {
      setMessages(prev => [...prev, {
        type: 'query-update',
        data: {
          timestamp: new Date().toISOString(),
          queries: Math.floor(Math.random() * 100),
          responseTime: Math.floor(Math.random() * 50)
        }
      }]);
    }, 5000);

    return () => clearInterval(interval);
  }, [path]);

  return { messages, connected };
};