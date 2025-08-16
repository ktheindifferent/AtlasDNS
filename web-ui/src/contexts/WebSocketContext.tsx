import React, { createContext, useContext, ReactNode } from 'react';
import { useWebSocket } from '../hooks/useWebSocket';

interface WebSocketContextType {
  connected: boolean;
  messages: any[];
  sendMessage: (type: string, data: any) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const useWebSocketContext = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocketContext must be used within a WebSocketProvider');
  }
  return context;
};

export const WebSocketProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { connected, messages, sendMessage } = useWebSocket('/');

  return (
    <WebSocketContext.Provider value={{ connected, messages, sendMessage }}>
      {children}
    </WebSocketContext.Provider>
  );
};