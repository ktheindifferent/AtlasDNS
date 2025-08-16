import React, { createContext, useContext, useEffect, useRef, useState, useCallback } from 'react';
import * as Y from 'yjs';
import { WebsocketProvider } from 'y-websocket';
import { IndexeddbPersistence } from 'y-indexeddb';
import { useDispatch, useSelector } from 'react-redux';
import { RootState, AppDispatch } from '../store';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  addActiveUser,
  removeActiveUser,
  updateCursor,
  removeCursor,
  addComment,
  updateComment,
  deleteComment,
  addChangeHistory,
  addActivity,
  setTyping,
  acquireEditLock,
  releaseEditLock,
  updatePresence,
  User,
  Cursor,
  Comment,
  ChangeHistoryItem,
  Activity,
} from '../store/slices/collaborationSlice';

interface CollaborationContextType {
  ydoc: Y.Doc | null;
  provider: WebsocketProvider | null;
  awareness: any;
  sendCursor: (x: number, y: number, page: string) => void;
  sendComment: (comment: Omit<Comment, 'id' | 'createdAt' | 'updatedAt'>) => void;
  sendTyping: (location: string, isTyping: boolean) => void;
  requestEditLock: (entityId: string) => Promise<boolean>;
  releaseEditLock: (entityId: string) => void;
  trackChange: (change: Omit<ChangeHistoryItem, 'id' | 'timestamp'>) => void;
  trackActivity: (activity: Omit<Activity, 'id' | 'timestamp'>) => void;
  mentionUser: (userId: string, context: string) => void;
  getSharedData: (key: string) => any;
  setSharedData: (key: string, data: any) => void;
}

const CollaborationContext = createContext<CollaborationContextType | undefined>(undefined);

export const useCollaboration = () => {
  const context = useContext(CollaborationContext);
  if (!context) {
    throw new Error('useCollaboration must be used within a CollaborationProvider');
  }
  return context;
};

interface CollaborationProviderProps {
  children: React.ReactNode;
}

export const CollaborationProvider: React.FC<CollaborationProviderProps> = ({ children }) => {
  const dispatch = useDispatch<AppDispatch>();
  const { user } = useSelector((state: RootState) => state.auth);
  const { emit, on, off, connected } = useWebSocket();
  const [ydoc, setYdoc] = useState<Y.Doc | null>(null);
  const [provider, setProvider] = useState<WebsocketProvider | null>(null);
  const [awareness, setAwareness] = useState<any>(null);
  const ydocRef = useRef<Y.Doc | null>(null);
  const providerRef = useRef<WebsocketProvider | null>(null);

  useEffect(() => {
    if (!user || !connected) return;

    const doc = new Y.Doc();
    ydocRef.current = doc;

    const wsUrl = process.env.REACT_APP_YJS_WS_URL || 'ws://localhost:5381';
    const roomName = 'atlas-dns-collaboration';

    const wsProvider = new WebsocketProvider(wsUrl, roomName, doc, {
      params: {
        auth: user.id,
      },
    });

    providerRef.current = wsProvider;

    const persistence = new IndexeddbPersistence('atlas-dns-collab', doc);

    persistence.on('synced', () => {
      console.log('Local IndexedDB synced');
    });

    const awarenessInstance = wsProvider.awareness;
    
    awarenessInstance.setLocalStateField('user', {
      id: user.id,
      name: user.name || user.email,
      email: user.email,
      color: generateUserColor(user.id),
      avatar: user.avatar,
    });

    awarenessInstance.on('change', (changes: any) => {
      const states = Array.from(awarenessInstance.getStates().entries());
      const activeUsers = states
        .map(([clientId, state]: [number, any]) => state.user)
        .filter((u: any) => u && u.id !== user.id);

      activeUsers.forEach((u: User) => {
        dispatch(addActiveUser(u));
      });

      changes.removed.forEach((clientId: number) => {
        const state = awarenessInstance.getStates().get(clientId);
        if (state?.user) {
          dispatch(removeActiveUser(state.user.id));
        }
      });
    });

    setYdoc(doc);
    setProvider(wsProvider);
    setAwareness(awarenessInstance);

    return () => {
      wsProvider.destroy();
      persistence.destroy();
      doc.destroy();
    };
  }, [user, connected, dispatch]);

  useEffect(() => {
    if (!connected) return;

    const handleUserJoined = (data: { user: User }) => {
      dispatch(addActiveUser(data.user));
      dispatch(addActivity({
        id: '',
        userId: data.user.id,
        user: data.user,
        action: 'joined',
        entityType: 'system',
        timestamp: new Date().toISOString(),
      }));
    };

    const handleUserLeft = (data: { userId: string }) => {
      dispatch(removeActiveUser(data.userId));
      dispatch(removeCursor(data.userId));
    };

    const handleCursorUpdate = (data: Cursor) => {
      dispatch(updateCursor(data));
    };

    const handleNewComment = (data: Comment) => {
      dispatch(addComment(data));
      dispatch(addActivity({
        id: '',
        userId: data.userId,
        user: data.user,
        action: 'commented',
        entityType: data.entityType,
        entityId: data.entityId,
        timestamp: data.createdAt,
      }));
    };

    const handleCommentUpdate = (data: Comment) => {
      dispatch(updateComment(data));
    };

    const handleCommentDelete = (data: { commentId: string }) => {
      dispatch(deleteComment(data.commentId));
    };

    const handleChangeHistory = (data: ChangeHistoryItem) => {
      dispatch(addChangeHistory(data));
      dispatch(addActivity({
        id: '',
        userId: data.userId,
        user: data.user,
        action: data.action,
        entityType: data.entityType,
        entityId: data.entityId,
        timestamp: data.timestamp,
        details: data.description,
      }));
    };

    const handleTypingStatus = (data: { userId: string; location: string; isTyping: boolean }) => {
      dispatch(setTyping(data));
    };

    const handleEditLock = (data: { entityId: string; userId: string; acquired: boolean }) => {
      if (data.acquired) {
        dispatch(acquireEditLock({ entityId: data.entityId, userId: data.userId }));
      } else {
        dispatch(releaseEditLock(data.entityId));
      }
    };

    const handlePresenceUpdate = (data: { userId: string; status: 'online' | 'idle' | 'away' }) => {
      dispatch(updatePresence({
        userId: data.userId,
        status: data.status,
        lastSeen: new Date().toISOString(),
      }));
    };

    on('user:joined', handleUserJoined);
    on('user:left', handleUserLeft);
    on('cursor:update', handleCursorUpdate);
    on('comment:new', handleNewComment);
    on('comment:update', handleCommentUpdate);
    on('comment:delete', handleCommentDelete);
    on('change:history', handleChangeHistory);
    on('typing:status', handleTypingStatus);
    on('edit:lock', handleEditLock);
    on('presence:update', handlePresenceUpdate);

    return () => {
      off('user:joined');
      off('user:left');
      off('cursor:update');
      off('comment:new');
      off('comment:update');
      off('comment:delete');
      off('change:history');
      off('typing:status');
      off('edit:lock');
      off('presence:update');
    };
  }, [connected, on, off, dispatch]);

  const sendCursor = useCallback((x: number, y: number, page: string) => {
    if (!user) return;
    
    const cursor: Cursor = {
      userId: user.id,
      x,
      y,
      page,
      timestamp: Date.now(),
    };

    emit('cursor:update', cursor);
    
    if (awareness) {
      awareness.setLocalStateField('cursor', cursor);
    }
  }, [user, emit, awareness]);

  const sendComment = useCallback((comment: Omit<Comment, 'id' | 'createdAt' | 'updatedAt'>) => {
    if (!user) return;

    const fullComment: Comment = {
      ...comment,
      id: generateId(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    emit('comment:new', fullComment);
  }, [user, emit]);

  const sendTyping = useCallback((location: string, isTyping: boolean) => {
    if (!user) return;

    emit('typing:status', {
      userId: user.id,
      location,
      isTyping,
    });
  }, [user, emit]);

  const requestEditLock = useCallback(async (entityId: string): Promise<boolean> => {
    if (!user) return false;

    return new Promise((resolve) => {
      const handleResponse = (data: { entityId: string; userId: string; granted: boolean }) => {
        if (data.entityId === entityId) {
          off('edit:lock:response');
          resolve(data.granted);
        }
      };

      on('edit:lock:response', handleResponse);
      emit('edit:lock:request', { entityId, userId: user.id });

      setTimeout(() => {
        off('edit:lock:response');
        resolve(false);
      }, 5000);
    });
  }, [user, emit, on, off]);

  const releaseEditLock = useCallback((entityId: string) => {
    if (!user) return;

    emit('edit:lock:release', { entityId, userId: user.id });
  }, [user, emit]);

  const trackChange = useCallback((change: Omit<ChangeHistoryItem, 'id' | 'timestamp'>) => {
    if (!user) return;

    const fullChange: ChangeHistoryItem = {
      ...change,
      id: generateId(),
      timestamp: new Date().toISOString(),
    };

    emit('change:history', fullChange);
  }, [user, emit]);

  const trackActivity = useCallback((activity: Omit<Activity, 'id' | 'timestamp'>) => {
    if (!user) return;

    const fullActivity: Activity = {
      ...activity,
      id: generateId(),
      timestamp: new Date().toISOString(),
    };

    emit('activity:track', fullActivity);
  }, [user, emit]);

  const mentionUser = useCallback((userId: string, context: string) => {
    emit('mention:user', { userId, context, mentionedBy: user?.id });
  }, [user, emit]);

  const getSharedData = useCallback((key: string) => {
    if (!ydoc) return null;
    const map = ydoc.getMap('shared');
    return map.get(key);
  }, [ydoc]);

  const setSharedData = useCallback((key: string, data: any) => {
    if (!ydoc) return;
    const map = ydoc.getMap('shared');
    map.set(key, data);
  }, [ydoc]);

  const value: CollaborationContextType = {
    ydoc,
    provider,
    awareness,
    sendCursor,
    sendComment,
    sendTyping,
    requestEditLock,
    releaseEditLock,
    trackChange,
    trackActivity,
    mentionUser,
    getSharedData,
    setSharedData,
  };

  return (
    <CollaborationContext.Provider value={value}>
      {children}
    </CollaborationContext.Provider>
  );
};

function generateUserColor(userId: string): string {
  const colors = [
    '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8',
    '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B739', '#52C234',
  ];
  
  let hash = 0;
  for (let i = 0; i < userId.length; i++) {
    hash = userId.charCodeAt(i) + ((hash << 5) - hash);
  }
  
  return colors[Math.abs(hash) % colors.length];
}

function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}