import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export interface User {
  id: string;
  name: string;
  email: string;
  avatar?: string;
  color: string;
}

export interface Cursor {
  userId: string;
  x: number;
  y: number;
  page: string;
  timestamp: number;
}

export interface Comment {
  id: string;
  userId: string;
  user: User;
  content: string;
  entityType: 'zone' | 'record';
  entityId: string;
  parentId?: string;
  mentions: string[];
  createdAt: string;
  updatedAt: string;
  resolved?: boolean;
}

export interface ChangeHistoryItem {
  id: string;
  userId: string;
  user: User;
  action: 'create' | 'update' | 'delete';
  entityType: 'zone' | 'record';
  entityId: string;
  changes: {
    field: string;
    oldValue: any;
    newValue: any;
  }[];
  timestamp: string;
  description?: string;
}

export interface Activity {
  id: string;
  userId: string;
  user: User;
  action: string;
  entityType: 'zone' | 'record' | 'user' | 'system';
  entityId?: string;
  entityName?: string;
  details?: string;
  timestamp: string;
}

interface CollaborationState {
  activeUsers: User[];
  cursors: Cursor[];
  comments: Comment[];
  changeHistory: ChangeHistoryItem[];
  activities: Activity[];
  typing: { [key: string]: { userId: string; location: string } };
  editingLocks: { [key: string]: string };
  presence: { [userId: string]: { status: 'online' | 'idle' | 'away'; lastSeen: string } };
}

const initialState: CollaborationState = {
  activeUsers: [],
  cursors: [],
  comments: [],
  changeHistory: [],
  activities: [],
  typing: {},
  editingLocks: {},
  presence: {},
};

const collaborationSlice = createSlice({
  name: 'collaboration',
  initialState,
  reducers: {
    setActiveUsers(state, action: PayloadAction<User[]>) {
      state.activeUsers = action.payload;
    },
    addActiveUser(state, action: PayloadAction<User>) {
      if (!state.activeUsers.find(u => u.id === action.payload.id)) {
        state.activeUsers.push(action.payload);
      }
    },
    removeActiveUser(state, action: PayloadAction<string>) {
      state.activeUsers = state.activeUsers.filter(u => u.id !== action.payload);
      delete state.presence[action.payload];
      state.cursors = state.cursors.filter(c => c.userId !== action.payload);
    },
    updateCursor(state, action: PayloadAction<Cursor>) {
      const index = state.cursors.findIndex(c => c.userId === action.payload.userId);
      if (index >= 0) {
        state.cursors[index] = action.payload;
      } else {
        state.cursors.push(action.payload);
      }
    },
    removeCursor(state, action: PayloadAction<string>) {
      state.cursors = state.cursors.filter(c => c.userId !== action.payload);
    },
    addComment(state, action: PayloadAction<Comment>) {
      state.comments.push(action.payload);
    },
    updateComment(state, action: PayloadAction<Comment>) {
      const index = state.comments.findIndex(c => c.id === action.payload.id);
      if (index >= 0) {
        state.comments[index] = action.payload;
      }
    },
    deleteComment(state, action: PayloadAction<string>) {
      state.comments = state.comments.filter(c => c.id !== action.payload);
    },
    setComments(state, action: PayloadAction<Comment[]>) {
      state.comments = action.payload;
    },
    addChangeHistory(state, action: PayloadAction<ChangeHistoryItem>) {
      state.changeHistory.unshift(action.payload);
      if (state.changeHistory.length > 100) {
        state.changeHistory = state.changeHistory.slice(0, 100);
      }
    },
    setChangeHistory(state, action: PayloadAction<ChangeHistoryItem[]>) {
      state.changeHistory = action.payload;
    },
    addActivity(state, action: PayloadAction<Activity>) {
      state.activities.unshift(action.payload);
      if (state.activities.length > 50) {
        state.activities = state.activities.slice(0, 50);
      }
    },
    setActivities(state, action: PayloadAction<Activity[]>) {
      state.activities = action.payload;
    },
    setTyping(state, action: PayloadAction<{ location: string; userId: string; isTyping: boolean }>) {
      const key = `${action.payload.location}`;
      if (action.payload.isTyping) {
        state.typing[key] = { userId: action.payload.userId, location: action.payload.location };
      } else {
        delete state.typing[key];
      }
    },
    acquireEditLock(state, action: PayloadAction<{ entityId: string; userId: string }>) {
      state.editingLocks[action.payload.entityId] = action.payload.userId;
    },
    releaseEditLock(state, action: PayloadAction<string>) {
      delete state.editingLocks[action.payload];
    },
    updatePresence(state, action: PayloadAction<{ userId: string; status: 'online' | 'idle' | 'away'; lastSeen: string }>) {
      state.presence[action.payload.userId] = {
        status: action.payload.status,
        lastSeen: action.payload.lastSeen,
      };
    },
    clearCollaborationData(state) {
      return initialState;
    },
  },
});

export const {
  setActiveUsers,
  addActiveUser,
  removeActiveUser,
  updateCursor,
  removeCursor,
  addComment,
  updateComment,
  deleteComment,
  setComments,
  addChangeHistory,
  setChangeHistory,
  addActivity,
  setActivities,
  setTyping,
  acquireEditLock,
  releaseEditLock,
  updatePresence,
  clearCollaborationData,
} = collaborationSlice.actions;

export default collaborationSlice.reducer;