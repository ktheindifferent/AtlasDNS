import { useEffect, useState, useCallback, useRef } from 'react';
import { useWebSocket as useWebSocketContext } from '../contexts/WebSocketContext';

interface UseWebSocketOptions {
  onMessage?: (data: any) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  autoReconnect?: boolean;
}

export const useWebSocket = (channel?: string, options?: UseWebSocketOptions) => {
  const { socket, connected, messages, sendMessage, subscribe, unsubscribe } = useWebSocketContext();
  const [channelMessages, setChannelMessages] = useState<any[]>([]);
  const handlersRef = useRef<{ [key: string]: (data: any) => void }>({});

  useEffect(() => {
    if (!channel) return;

    const filteredMessages = messages.filter(msg => msg.type === channel);
    setChannelMessages(filteredMessages);
  }, [messages, channel]);

  useEffect(() => {
    if (connected && options?.onConnect) {
      options.onConnect();
    }
    if (!connected && options?.onDisconnect) {
      options.onDisconnect();
    }
  }, [connected, options]);

  useEffect(() => {
    if (channelMessages.length > 0 && options?.onMessage) {
      const latestMessage = channelMessages[channelMessages.length - 1];
      options.onMessage(latestMessage.data);
    }
  }, [channelMessages, options]);

  const emit = useCallback((eventType: string, data: any) => {
    sendMessage(eventType, data);
  }, [sendMessage]);

  const on = useCallback((eventType: string, handler: (data: any) => void) => {
    handlersRef.current[eventType] = handler;
    subscribe(eventType, handler);
  }, [subscribe]);

  const off = useCallback((eventType: string) => {
    const handler = handlersRef.current[eventType];
    if (handler) {
      unsubscribe(eventType, handler);
      delete handlersRef.current[eventType];
    }
  }, [unsubscribe]);

  // Cleanup handlers on unmount
  useEffect(() => {
    return () => {
      Object.entries(handlersRef.current).forEach(([eventType, handler]) => {
        unsubscribe(eventType, handler);
      });
    };
  }, [unsubscribe]);

  return {
    socket,
    connected,
    messages: channel ? channelMessages : messages,
    emit,
    on,
    off,
    sendMessage,
  };
};