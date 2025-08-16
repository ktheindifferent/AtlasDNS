import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit';
import {
  Notification,
  NotificationFilter,
  NotificationGroup,
  NotificationPreferences,
  NotificationPriority,
  NotificationStatus,
  NotificationCategory,
  NotificationChannel,
  NotificationRule,
  DoNotDisturbConfig,
  NotificationStats,
} from '../../types/notification.types';

interface NotificationState {
  notifications: Notification[];
  groups: NotificationGroup[];
  filter: NotificationFilter;
  preferences: NotificationPreferences;
  rules: NotificationRule[];
  stats: NotificationStats;
  unreadCount: number;
  loading: boolean;
  error: string | null;
  selectedNotificationId: string | null;
  searchQuery: string;
}

const initialState: NotificationState = {
  notifications: [],
  groups: [],
  filter: {},
  preferences: {
    channels: {
      [NotificationChannel.IN_APP]: { enabled: true },
      [NotificationChannel.EMAIL]: { enabled: false },
      [NotificationChannel.PUSH]: { enabled: true },
      [NotificationChannel.SMS]: { enabled: false },
      [NotificationChannel.SLACK]: { enabled: false },
    },
    doNotDisturb: {
      enabled: false,
      allowUrgent: true,
      allowedCategories: [NotificationCategory.SECURITY, NotificationCategory.ALERT],
    },
    grouping: {
      enabled: true,
      timeWindow: 300000, // 5 minutes
      maxGroupSize: 10,
    },
    sound: true,
    vibration: true,
    desktop: true,
  },
  rules: [],
  stats: {
    total: 0,
    unread: 0,
    byCategory: {} as Record<NotificationCategory, number>,
    byPriority: {} as Record<NotificationPriority, number>,
    byChannel: {} as Record<NotificationChannel, number>,
    todayCount: 0,
    weekCount: 0,
  },
  unreadCount: 0,
  loading: false,
  error: null,
  selectedNotificationId: null,
  searchQuery: '',
};

// Helper functions
const shouldNotify = (
  notification: Notification,
  preferences: NotificationPreferences
): boolean => {
  const dnd = preferences.doNotDisturb;
  
  if (!dnd.enabled) return true;
  
  if (dnd.allowUrgent && notification.priority === NotificationPriority.URGENT) {
    return true;
  }
  
  if (dnd.allowedCategories?.includes(notification.category)) {
    return true;
  }
  
  const now = new Date();
  if (dnd.schedule) {
    const { startTime, endTime, daysOfWeek } = dnd.schedule;
    const currentDay = now.getDay();
    
    if (daysOfWeek && !daysOfWeek.includes(currentDay)) {
      return true;
    }
    
    if (startTime && endTime) {
      const [startHour, startMinute] = startTime.split(':').map(Number);
      const [endHour, endMinute] = endTime.split(':').map(Number);
      const currentMinutes = now.getHours() * 60 + now.getMinutes();
      const startMinutes = startHour * 60 + startMinute;
      const endMinutes = endHour * 60 + endMinute;
      
      if (currentMinutes < startMinutes || currentMinutes > endMinutes) {
        return true;
      }
    }
  }
  
  return false;
};

const groupNotifications = (
  notifications: Notification[],
  preferences: NotificationPreferences
): NotificationGroup[] => {
  if (!preferences.grouping.enabled) {
    return [];
  }
  
  const groups: Map<string, NotificationGroup> = new Map();
  const { timeWindow, maxGroupSize } = preferences.grouping;
  
  const sorted = [...notifications].sort((a, b) => b.timestamp - a.timestamp);
  
  sorted.forEach(notification => {
    const groupKey = `${notification.category}-${notification.priority}`;
    let group = groups.get(groupKey);
    
    if (!group) {
      group = {
        id: `group-${groupKey}-${Date.now()}`,
        title: `${notification.category} notifications`,
        category: notification.category,
        count: 0,
        notifications: [],
        firstTimestamp: notification.timestamp,
        lastTimestamp: notification.timestamp,
        read: true,
        collapsed: true,
      };
      groups.set(groupKey, group);
    }
    
    const timeDiff = group.lastTimestamp - notification.timestamp;
    
    if (timeDiff <= timeWindow && group.notifications.length < maxGroupSize) {
      group.notifications.push(notification);
      group.count++;
      group.firstTimestamp = Math.min(group.firstTimestamp, notification.timestamp);
      group.lastTimestamp = Math.max(group.lastTimestamp, notification.timestamp);
      group.read = group.read && notification.read;
      notification.groupId = group.id;
    } else {
      const newGroup: NotificationGroup = {
        id: `group-${groupKey}-${notification.timestamp}`,
        title: `${notification.category} notifications`,
        category: notification.category,
        count: 1,
        notifications: [notification],
        firstTimestamp: notification.timestamp,
        lastTimestamp: notification.timestamp,
        read: notification.read,
        collapsed: true,
      };
      groups.set(`${groupKey}-${notification.timestamp}`, newGroup);
      notification.groupId = newGroup.id;
    }
  });
  
  return Array.from(groups.values()).filter(g => g.count > 1);
};

const filterNotifications = (
  notifications: Notification[],
  filter: NotificationFilter
): Notification[] => {
  return notifications.filter(notification => {
    if (filter.categories?.length && !filter.categories.includes(notification.category)) {
      return false;
    }
    
    if (filter.priorities?.length && !filter.priorities.includes(notification.priority)) {
      return false;
    }
    
    if (filter.statuses?.length && !filter.statuses.includes(notification.status)) {
      return false;
    }
    
    if (filter.channels?.length) {
      const hasChannel = filter.channels.some(channel => 
        notification.channels.includes(channel)
      );
      if (!hasChannel) return false;
    }
    
    if (filter.search) {
      const searchLower = filter.search.toLowerCase();
      if (
        !notification.title.toLowerCase().includes(searchLower) &&
        !notification.message.toLowerCase().includes(searchLower)
      ) {
        return false;
      }
    }
    
    if (filter.dateFrom && notification.timestamp < filter.dateFrom) {
      return false;
    }
    
    if (filter.dateTo && notification.timestamp > filter.dateTo) {
      return false;
    }
    
    if (filter.read !== undefined && notification.read !== filter.read) {
      return false;
    }
    
    if (filter.groupId && notification.groupId !== filter.groupId) {
      return false;
    }
    
    return true;
  });
};

const calculateStats = (notifications: Notification[]): NotificationStats => {
  const now = Date.now();
  const todayStart = new Date().setHours(0, 0, 0, 0);
  const weekStart = now - 7 * 24 * 60 * 60 * 1000;
  
  const stats: NotificationStats = {
    total: notifications.length,
    unread: notifications.filter(n => !n.read).length,
    byCategory: {} as Record<NotificationCategory, number>,
    byPriority: {} as Record<NotificationPriority, number>,
    byChannel: {} as Record<NotificationChannel, number>,
    todayCount: 0,
    weekCount: 0,
  };
  
  notifications.forEach(notification => {
    stats.byCategory[notification.category] = (stats.byCategory[notification.category] || 0) + 1;
    stats.byPriority[notification.priority] = (stats.byPriority[notification.priority] || 0) + 1;
    
    notification.channels.forEach(channel => {
      stats.byChannel[channel] = (stats.byChannel[channel] || 0) + 1;
    });
    
    if (notification.timestamp >= todayStart) {
      stats.todayCount++;
    }
    
    if (notification.timestamp >= weekStart) {
      stats.weekCount++;
    }
  });
  
  return stats;
};

// Async thunks
export const fetchNotifications = createAsyncThunk(
  'notifications/fetch',
  async (filter?: NotificationFilter) => {
    // This would be replaced with actual API call
    return {
      notifications: [],
      total: 0,
    };
  }
);

export const sendNotification = createAsyncThunk(
  'notifications/send',
  async (notification: Partial<Notification>) => {
    // This would be replaced with actual API call
    return notification;
  }
);

const notificationSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    addNotification: (state, action: PayloadAction<Omit<Notification, 'id' | 'timestamp' | 'status'>>) => {
      const notification: Notification = {
        ...action.payload,
        id: `notif-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        timestamp: Date.now(),
        status: NotificationStatus.PENDING,
        read: false,
      };
      
      if (shouldNotify(notification, state.preferences)) {
        notification.status = NotificationStatus.DELIVERED;
        state.notifications.unshift(notification);
        state.unreadCount++;
        state.groups = groupNotifications(state.notifications, state.preferences);
        state.stats = calculateStats(state.notifications);
      } else {
        notification.status = NotificationStatus.SNOOZED;
      }
    },
    
    markAsRead: (state, action: PayloadAction<string>) => {
      const notification = state.notifications.find(n => n.id === action.payload);
      if (notification && !notification.read) {
        notification.read = true;
        notification.readAt = Date.now();
        notification.status = NotificationStatus.READ;
        state.unreadCount = Math.max(0, state.unreadCount - 1);
        state.stats = calculateStats(state.notifications);
      }
    },
    
    markMultipleAsRead: (state, action: PayloadAction<string[]>) => {
      action.payload.forEach(id => {
        const notification = state.notifications.find(n => n.id === id);
        if (notification && !notification.read) {
          notification.read = true;
          notification.readAt = Date.now();
          notification.status = NotificationStatus.READ;
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
      });
      state.stats = calculateStats(state.notifications);
    },
    
    markAllAsRead: (state) => {
      state.notifications.forEach(n => {
        if (!n.read) {
          n.read = true;
          n.readAt = Date.now();
          n.status = NotificationStatus.READ;
        }
      });
      state.unreadCount = 0;
      state.stats = calculateStats(state.notifications);
    },
    
    snoozeNotification: (state, action: PayloadAction<{ id: string; until: number }>) => {
      const notification = state.notifications.find(n => n.id === action.payload.id);
      if (notification) {
        notification.status = NotificationStatus.SNOOZED;
        notification.snoozedUntil = action.payload.until;
        if (!notification.read) {
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
      }
    },
    
    archiveNotification: (state, action: PayloadAction<string>) => {
      const notification = state.notifications.find(n => n.id === action.payload);
      if (notification) {
        notification.status = NotificationStatus.ARCHIVED;
        if (!notification.read) {
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
      }
    },
    
    deleteNotification: (state, action: PayloadAction<string>) => {
      const index = state.notifications.findIndex(n => n.id === action.payload);
      if (index !== -1) {
        if (!state.notifications[index].read) {
          state.unreadCount = Math.max(0, state.unreadCount - 1);
        }
        state.notifications.splice(index, 1);
        state.groups = groupNotifications(state.notifications, state.preferences);
        state.stats = calculateStats(state.notifications);
      }
    },
    
    deleteMultiple: (state, action: PayloadAction<string[]>) => {
      action.payload.forEach(id => {
        const index = state.notifications.findIndex(n => n.id === id);
        if (index !== -1) {
          if (!state.notifications[index].read) {
            state.unreadCount = Math.max(0, state.unreadCount - 1);
          }
          state.notifications.splice(index, 1);
        }
      });
      state.groups = groupNotifications(state.notifications, state.preferences);
      state.stats = calculateStats(state.notifications);
    },
    
    clearNotifications: (state, action: PayloadAction<NotificationFilter | undefined>) => {
      if (action.payload) {
        const toRemove = filterNotifications(state.notifications, action.payload);
        toRemove.forEach(notification => {
          const index = state.notifications.indexOf(notification);
          if (index !== -1) {
            if (!notification.read) {
              state.unreadCount = Math.max(0, state.unreadCount - 1);
            }
            state.notifications.splice(index, 1);
          }
        });
      } else {
        state.notifications = [];
        state.unreadCount = 0;
      }
      state.groups = groupNotifications(state.notifications, state.preferences);
      state.stats = calculateStats(state.notifications);
    },
    
    setFilter: (state, action: PayloadAction<NotificationFilter>) => {
      state.filter = action.payload;
    },
    
    updatePreferences: (state, action: PayloadAction<Partial<NotificationPreferences>>) => {
      state.preferences = { ...state.preferences, ...action.payload };
      state.groups = groupNotifications(state.notifications, state.preferences);
    },
    
    setDoNotDisturb: (state, action: PayloadAction<DoNotDisturbConfig>) => {
      state.preferences.doNotDisturb = action.payload;
    },
    
    addRule: (state, action: PayloadAction<NotificationRule>) => {
      state.rules.push(action.payload);
    },
    
    updateRule: (state, action: PayloadAction<NotificationRule>) => {
      const index = state.rules.findIndex(r => r.id === action.payload.id);
      if (index !== -1) {
        state.rules[index] = action.payload;
      }
    },
    
    deleteRule: (state, action: PayloadAction<string>) => {
      state.rules = state.rules.filter(r => r.id !== action.payload);
    },
    
    toggleGroupCollapse: (state, action: PayloadAction<string>) => {
      const group = state.groups.find(g => g.id === action.payload);
      if (group) {
        group.collapsed = !group.collapsed;
      }
    },
    
    setSearchQuery: (state, action: PayloadAction<string>) => {
      state.searchQuery = action.payload;
      state.filter.search = action.payload;
    },
    
    selectNotification: (state, action: PayloadAction<string | null>) => {
      state.selectedNotificationId = action.payload;
    },
    
    processSnoozedNotifications: (state) => {
      const now = Date.now();
      state.notifications.forEach(notification => {
        if (
          notification.status === NotificationStatus.SNOOZED &&
          notification.snoozedUntil &&
          notification.snoozedUntil <= now
        ) {
          notification.status = NotificationStatus.DELIVERED;
          notification.snoozedUntil = undefined;
          if (!notification.read) {
            state.unreadCount++;
          }
        }
      });
      state.stats = calculateStats(state.notifications);
    },
    
    processScheduledNotifications: (state) => {
      const now = Date.now();
      state.notifications.forEach(notification => {
        if (
          notification.status === NotificationStatus.PENDING &&
          notification.scheduledFor &&
          notification.scheduledFor <= now
        ) {
          if (shouldNotify(notification, state.preferences)) {
            notification.status = NotificationStatus.DELIVERED;
          }
        }
      });
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchNotifications.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchNotifications.fulfilled, (state, action) => {
        state.loading = false;
        // Handle fetched notifications
      })
      .addCase(fetchNotifications.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to fetch notifications';
      });
  },
});

export const {
  addNotification,
  markAsRead,
  markMultipleAsRead,
  markAllAsRead,
  snoozeNotification,
  archiveNotification,
  deleteNotification,
  deleteMultiple,
  clearNotifications,
  setFilter,
  updatePreferences,
  setDoNotDisturb,
  addRule,
  updateRule,
  deleteRule,
  toggleGroupCollapse,
  setSearchQuery,
  selectNotification,
  processSnoozedNotifications,
  processScheduledNotifications,
} = notificationSlice.actions;

export default notificationSlice.reducer;