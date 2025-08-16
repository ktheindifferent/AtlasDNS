import React, { createContext, useContext, useEffect, useState, useRef, ReactNode } from 'react';
import { io, Socket } from 'socket.io-client';
import { useSelector, useDispatch } from 'react-redux';
import { RootState } from '../store';
import { addNotification } from '../store/slices/notificationSlice';
import NotificationService from '../services/notificationService';
import {
  NotificationCategory,
  NotificationPriority,
  NotificationChannel,
} from '../types/notification.types';

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
  subscribeToChannel: (channel: string) => void;
  unsubscribeFromChannel: (channel: string) => void;
  emit: (event: string, data: any) => void;
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

export const EnhancedWebSocketProvider: React.FC<WebSocketProviderProps> = ({ children }) => {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const messageQueueRef = useRef<WebSocketMessage[]>([]);
  const subscribedChannels = useRef<Set<string>>(new Set());
  const { token } = useSelector((state: RootState) => state.auth);
  const dispatch = useDispatch();
  const notificationService = NotificationService.getInstance();

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
      transports: ['websocket', 'polling'],
    });

    newSocket.on('connect', () => {
      console.log('WebSocket connected');
      setConnected(true);
      
      // Re-subscribe to channels after reconnection
      subscribedChannels.current.forEach(channel => {
        newSocket.emit('subscribe', { channel });
      });
      
      // Send any queued messages
      while (messageQueueRef.current.length > 0) {
        const msg = messageQueueRef.current.shift();
        if (msg) {
          newSocket.emit(msg.type, msg.data);
        }
      }
      
      // Notify user of connection
      dispatch(addNotification({
        title: 'Connected',
        message: 'Real-time connection established',
        category: NotificationCategory.SYSTEM,
        priority: NotificationPriority.LOW,
        channels: [NotificationChannel.IN_APP],
      }));
    });

    newSocket.on('disconnect', () => {
      console.log('WebSocket disconnected');
      setConnected(false);
      
      dispatch(addNotification({
        title: 'Disconnected',
        message: 'Real-time connection lost. Attempting to reconnect...',
        category: NotificationCategory.SYSTEM,
        priority: NotificationPriority.MEDIUM,
        channels: [NotificationChannel.IN_APP],
      }));
    });

    newSocket.on('error', (error) => {
      console.error('WebSocket error:', error);
      
      dispatch(addNotification({
        title: 'Connection Error',
        message: 'Failed to establish real-time connection',
        category: NotificationCategory.SYSTEM,
        priority: NotificationPriority.HIGH,
        channels: [NotificationChannel.IN_APP],
      }));
    });

    // Notification-specific events
    newSocket.on('notification', (data) => {
      handleNotification(data);
    });

    newSocket.on('notification-batch', (data) => {
      data.forEach((notification: any) => handleNotification(notification));
    });

    // DNS-specific events
    const dnsEvents = [
      'zone-created',
      'zone-updated',
      'zone-deleted',
      'record-created',
      'record-updated',
      'record-deleted',
      'zone-transfer-started',
      'zone-transfer-completed',
      'zone-transfer-failed',
    ];

    dnsEvents.forEach(eventType => {
      newSocket.on(eventType, (data) => {
        handleDNSEvent(eventType, data);
      });
    });

    // Performance and health events
    const systemEvents = [
      'query-spike',
      'cache-miss-rate-high',
      'memory-threshold-exceeded',
      'cpu-threshold-exceeded',
      'health-check-failed',
      'service-degraded',
      'service-recovered',
    ];

    systemEvents.forEach(eventType => {
      newSocket.on(eventType, (data) => {
        handleSystemEvent(eventType, data);
      });
    });

    // Security events
    const securityEvents = [
      'ddos-detected',
      'suspicious-query-pattern',
      'unauthorized-zone-transfer',
      'rate-limit-exceeded',
      'blacklist-hit',
      'dnssec-validation-failed',
    ];

    securityEvents.forEach(eventType => {
      newSocket.on(eventType, (data) => {
        handleSecurityEvent(eventType, data);
      });
    });

    // Generic event handler for other events
    newSocket.on('event', (data) => {
      const message: WebSocketMessage = {
        type: data.type || 'unknown',
        data: data.payload,
        timestamp: Date.now(),
      };
      setMessages(prev => [...prev.slice(-99), message]);
    });

    setSocket(newSocket);
    notificationService.setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [token, dispatch]);

  const handleNotification = (data: any) => {
    dispatch(addNotification({
      title: data.title,
      message: data.message,
      category: data.category || NotificationCategory.INFO,
      priority: data.priority || NotificationPriority.MEDIUM,
      channels: data.channels || [NotificationChannel.IN_APP],
      actions: data.actions,
      metadata: data.metadata,
    }));
  };

  const handleDNSEvent = (eventType: string, data: any) => {
    const eventConfig: Record<string, any> = {
      'zone-created': {
        title: 'Zone Created',
        message: `Zone ${data.zone} has been created`,
        category: NotificationCategory.ZONE,
        priority: NotificationPriority.MEDIUM,
      },
      'zone-updated': {
        title: 'Zone Updated',
        message: `Zone ${data.zone} has been updated`,
        category: NotificationCategory.ZONE,
        priority: NotificationPriority.LOW,
      },
      'zone-deleted': {
        title: 'Zone Deleted',
        message: `Zone ${data.zone} has been deleted`,
        category: NotificationCategory.ZONE,
        priority: NotificationPriority.MEDIUM,
      },
      'record-created': {
        title: 'Record Created',
        message: `Record ${data.name} (${data.type}) created in ${data.zone}`,
        category: NotificationCategory.RECORD,
        priority: NotificationPriority.LOW,
      },
      'record-updated': {
        title: 'Record Updated',
        message: `Record ${data.name} (${data.type}) updated in ${data.zone}`,
        category: NotificationCategory.RECORD,
        priority: NotificationPriority.LOW,
      },
      'record-deleted': {
        title: 'Record Deleted',
        message: `Record ${data.name} (${data.type}) deleted from ${data.zone}`,
        category: NotificationCategory.RECORD,
        priority: NotificationPriority.LOW,
      },
      'zone-transfer-started': {
        title: 'Zone Transfer Started',
        message: `Zone transfer initiated for ${data.zone}`,
        category: NotificationCategory.ZONE,
        priority: NotificationPriority.MEDIUM,
      },
      'zone-transfer-completed': {
        title: 'Zone Transfer Completed',
        message: `Zone transfer completed for ${data.zone}`,
        category: NotificationCategory.ZONE,
        priority: NotificationPriority.LOW,
      },
      'zone-transfer-failed': {
        title: 'Zone Transfer Failed',
        message: `Zone transfer failed for ${data.zone}: ${data.error}`,
        category: NotificationCategory.ZONE,
        priority: NotificationPriority.HIGH,
      },
    };

    const config = eventConfig[eventType];
    if (config) {
      dispatch(addNotification({
        ...config,
        channels: [NotificationChannel.IN_APP],
        metadata: {
          eventType,
          ...data,
        },
      }));
    }

    const message: WebSocketMessage = {
      type: eventType,
      data,
      timestamp: Date.now(),
    };
    setMessages(prev => [...prev.slice(-99), message]);
  };

  const handleSystemEvent = (eventType: string, data: any) => {
    const eventConfig: Record<string, any> = {
      'query-spike': {
        title: 'Query Spike Detected',
        message: `Query rate exceeded threshold: ${data.rate} qps`,
        category: NotificationCategory.PERFORMANCE,
        priority: NotificationPriority.HIGH,
      },
      'cache-miss-rate-high': {
        title: 'High Cache Miss Rate',
        message: `Cache miss rate at ${data.rate}%`,
        category: NotificationCategory.PERFORMANCE,
        priority: NotificationPriority.MEDIUM,
      },
      'memory-threshold-exceeded': {
        title: 'Memory Usage Warning',
        message: `Memory usage at ${data.usage}%`,
        category: NotificationCategory.HEALTH,
        priority: NotificationPriority.HIGH,
      },
      'cpu-threshold-exceeded': {
        title: 'CPU Usage Warning',
        message: `CPU usage at ${data.usage}%`,
        category: NotificationCategory.HEALTH,
        priority: NotificationPriority.HIGH,
      },
      'health-check-failed': {
        title: 'Health Check Failed',
        message: `Health check failed for ${data.service}`,
        category: NotificationCategory.HEALTH,
        priority: NotificationPriority.URGENT,
      },
      'service-degraded': {
        title: 'Service Degraded',
        message: `Service ${data.service} is experiencing issues`,
        category: NotificationCategory.HEALTH,
        priority: NotificationPriority.HIGH,
      },
      'service-recovered': {
        title: 'Service Recovered',
        message: `Service ${data.service} has recovered`,
        category: NotificationCategory.HEALTH,
        priority: NotificationPriority.MEDIUM,
      },
    };

    const config = eventConfig[eventType];
    if (config) {
      dispatch(addNotification({
        ...config,
        channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL],
        metadata: {
          eventType,
          ...data,
        },
      }));
    }
  };

  const handleSecurityEvent = (eventType: string, data: any) => {
    const eventConfig: Record<string, any> = {
      'ddos-detected': {
        title: 'DDoS Attack Detected',
        message: `Possible DDoS attack from ${data.source}`,
        category: NotificationCategory.SECURITY,
        priority: NotificationPriority.URGENT,
      },
      'suspicious-query-pattern': {
        title: 'Suspicious Query Pattern',
        message: `Suspicious queries detected from ${data.source}`,
        category: NotificationCategory.SECURITY,
        priority: NotificationPriority.HIGH,
      },
      'unauthorized-zone-transfer': {
        title: 'Unauthorized Zone Transfer',
        message: `Unauthorized zone transfer attempt for ${data.zone}`,
        category: NotificationCategory.SECURITY,
        priority: NotificationPriority.URGENT,
      },
      'rate-limit-exceeded': {
        title: 'Rate Limit Exceeded',
        message: `Rate limit exceeded by ${data.source}`,
        category: NotificationCategory.SECURITY,
        priority: NotificationPriority.MEDIUM,
      },
      'blacklist-hit': {
        title: 'Blacklist Hit',
        message: `Query from blacklisted source: ${data.source}`,
        category: NotificationCategory.SECURITY,
        priority: NotificationPriority.HIGH,
      },
      'dnssec-validation-failed': {
        title: 'DNSSEC Validation Failed',
        message: `DNSSEC validation failed for ${data.domain}`,
        category: NotificationCategory.SECURITY,
        priority: NotificationPriority.HIGH,
      },
    };

    const config = eventConfig[eventType];
    if (config) {
      dispatch(addNotification({
        ...config,
        channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL, NotificationChannel.SLACK],
        actions: [
          {
            id: 'view-details',
            label: 'View Details',
            primary: true,
          },
          {
            id: 'block-source',
            label: 'Block Source',
          },
        ],
        metadata: {
          eventType,
          ...data,
        },
      }));
    }
  };

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

  const subscribeToChannel = (channel: string) => {
    if (socket && connected) {
      socket.emit('subscribe', { channel });
      subscribedChannels.current.add(channel);
    }
  };

  const unsubscribeFromChannel = (channel: string) => {
    if (socket && connected) {
      socket.emit('unsubscribe', { channel });
      subscribedChannels.current.delete(channel);
    }
  };

  const emit = (event: string, data: any) => {
    if (socket && connected) {
      socket.emit(event, data);
    }
  };

  const value: WebSocketContextType = {
    socket,
    connected,
    messages,
    sendMessage,
    subscribe,
    unsubscribe,
    subscribeToChannel,
    unsubscribeFromChannel,
    emit,
  };

  return (
    <WebSocketContext.Provider value={value}>
      {children}
    </WebSocketContext.Provider>
  );
};

export default EnhancedWebSocketProvider;