import { createSlice, PayloadAction, createAsyncThunk } from '@reduxjs/toolkit';
import {
  HelpContext,
  HelpInteraction,
  HelpSuggestion,
  FAQItem,
  ChatMessage,
  TroubleshootingWizard,
  UserHelpContent,
  HelpAnalytics,
  VideoSnippet,
  HelpSearchResult,
} from '../../components/HelpSystem/types';
import { helpApi } from '../../services/helpApi';

interface HelpState {
  currentContext: HelpContext;
  chatMessages: ChatMessage[];
  chatOpen: boolean;
  suggestions: HelpSuggestion[];
  activeSuggestion: HelpSuggestion | null;
  interactions: HelpInteraction[];
  faqs: FAQItem[];
  troubleshootingWizards: TroubleshootingWizard[];
  userContent: UserHelpContent[];
  videos: VideoSnippet[];
  searchResults: HelpSearchResult[];
  analytics: HelpAnalytics | null;
  sessionId: string;
  loading: boolean;
  error: string | null;
  helpPanelOpen: boolean;
  helpPanelContent: any;
  proactiveHelpEnabled: boolean;
  userBehaviorTracking: {
    mouseMovements: Array<{ x: number; y: number; timestamp: number }>;
    clicks: Array<{ element: string; timestamp: number }>;
    dwellTime: Record<string, number>;
    frustrationEvents: Array<{ type: string; timestamp: number }>;
  };
}

const initialState: HelpState = {
  currentContext: { page: 'dashboard' },
  chatMessages: [],
  chatOpen: false,
  suggestions: [],
  activeSuggestion: null,
  interactions: [],
  faqs: [],
  troubleshootingWizards: [],
  userContent: [],
  videos: [],
  searchResults: [],
  analytics: null,
  sessionId: `help-session-${Date.now()}`,
  loading: false,
  error: null,
  helpPanelOpen: false,
  helpPanelContent: null,
  proactiveHelpEnabled: true,
  userBehaviorTracking: {
    mouseMovements: [],
    clicks: [],
    dwellTime: {},
    frustrationEvents: [],
  },
};

// Async thunks
export const sendChatMessage = createAsyncThunk(
  'help/sendChatMessage',
  async ({ message, context }: { message: string; context: HelpContext }) => {
    const response = await helpApi.sendChatMessage({ message, context });
    return response.data;
  }
);

export const searchHelp = createAsyncThunk(
  'help/search',
  async ({ query, context }: { query: string; context?: HelpContext }) => {
    const response = await helpApi.searchHelp({ query, context });
    return response.data;
  }
);

export const loadFAQs = createAsyncThunk(
  'help/loadFAQs',
  async (context?: HelpContext) => {
    const response = await helpApi.getFAQs(context);
    return response.data;
  }
);

export const loadContextualHelp = createAsyncThunk(
  'help/loadContextualHelp',
  async (context: HelpContext) => {
    const response = await helpApi.getContextualHelp(context);
    return response.data;
  }
);

export const submitUserContent = createAsyncThunk(
  'help/submitUserContent',
  async (content: Partial<UserHelpContent>) => {
    const response = await helpApi.submitUserContent(content);
    return response.data;
  }
);

export const recordInteraction = createAsyncThunk(
  'help/recordInteraction',
  async (interaction: Partial<HelpInteraction>) => {
    const response = await helpApi.recordInteraction(interaction);
    return response.data;
  }
);

export const loadAnalytics = createAsyncThunk(
  'help/loadAnalytics',
  async () => {
    const response = await helpApi.getAnalytics();
    return response.data;
  }
);

export const startTroubleshooting = createAsyncThunk(
  'help/startTroubleshooting',
  async (wizardId: string) => {
    const response = await helpApi.getTroubleshootingWizard(wizardId);
    return response.data;
  }
);

const helpSlice = createSlice({
  name: 'help',
  initialState,
  reducers: {
    setContext: (state, action: PayloadAction<HelpContext>) => {
      state.currentContext = action.payload;
      // Clear previous suggestions when context changes
      state.suggestions = [];
      state.activeSuggestion = null;
    },
    toggleChat: (state) => {
      state.chatOpen = !state.chatOpen;
      if (state.chatOpen) {
        // Add welcome message when chat opens
        if (state.chatMessages.length === 0) {
          state.chatMessages.push({
            id: `msg-${Date.now()}`,
            type: 'assistant',
            content: `Hello! I'm your AI assistant. I can help you with ${state.currentContext.page} features. What would you like to know?`,
            timestamp: new Date(),
            context: state.currentContext,
          });
        }
      }
    },
    addChatMessage: (state, action: PayloadAction<ChatMessage>) => {
      state.chatMessages.push(action.payload);
    },
    clearChat: (state) => {
      state.chatMessages = [];
    },
    toggleHelpPanel: (state) => {
      state.helpPanelOpen = !state.helpPanelOpen;
    },
    setHelpPanelContent: (state, action: PayloadAction<any>) => {
      state.helpPanelContent = action.payload;
      state.helpPanelOpen = true;
    },
    addSuggestion: (state, action: PayloadAction<HelpSuggestion>) => {
      if (!state.suggestions.find(s => s.id === action.payload.id)) {
        state.suggestions.push(action.payload);
      }
    },
    dismissSuggestion: (state, action: PayloadAction<string>) => {
      state.suggestions = state.suggestions.filter(s => s.id !== action.payload);
      if (state.activeSuggestion?.id === action.payload) {
        state.activeSuggestion = null;
      }
    },
    setActiveSuggestion: (state, action: PayloadAction<HelpSuggestion | null>) => {
      state.activeSuggestion = action.payload;
    },
    toggleProactiveHelp: (state) => {
      state.proactiveHelpEnabled = !state.proactiveHelpEnabled;
    },
    trackUserBehavior: (state, action: PayloadAction<{
      type: 'mouse' | 'click' | 'dwell' | 'frustration';
      data: any;
    }>) => {
      const { type, data } = action.payload;
      const tracking = state.userBehaviorTracking;
      
      switch (type) {
        case 'mouse':
          tracking.mouseMovements.push({ ...data, timestamp: Date.now() });
          // Keep only last 100 movements
          if (tracking.mouseMovements.length > 100) {
            tracking.mouseMovements.shift();
          }
          break;
        case 'click':
          tracking.clicks.push({ element: data.element, timestamp: Date.now() });
          break;
        case 'dwell':
          const key = `${data.page}-${data.component}`;
          tracking.dwellTime[key] = (tracking.dwellTime[key] || 0) + data.duration;
          break;
        case 'frustration':
          tracking.frustrationEvents.push({ type: data.type, timestamp: Date.now() });
          break;
      }
    },
    markFAQHelpful: (state, action: PayloadAction<{ id: string; helpful: boolean }>) => {
      const faq = state.faqs.find(f => f.id === action.payload.id);
      if (faq) {
        if (action.payload.helpful) {
          faq.helpfulCount++;
        } else {
          faq.notHelpfulCount++;
        }
      }
    },
    incrementFAQView: (state, action: PayloadAction<string>) => {
      const faq = state.faqs.find(f => f.id === action.payload);
      if (faq) {
        faq.viewCount++;
      }
    },
    voteUserContent: (state, action: PayloadAction<{ id: string; helpful: boolean }>) => {
      const content = state.userContent.find(c => c.id === action.payload.id);
      if (content) {
        if (action.payload.helpful) {
          content.votes.helpful++;
        } else {
          content.votes.notHelpful++;
        }
      }
    },
    provideFeedback: (state, action: PayloadAction<{
      messageId: string;
      helpful: boolean;
      comment?: string;
    }>) => {
      const message = state.chatMessages.find(m => m.id === action.payload.messageId);
      if (message) {
        message.feedback = {
          helpful: action.payload.helpful,
          comment: action.payload.comment,
        };
      }
    },
  },
  extraReducers: (builder) => {
    builder
      // Send chat message
      .addCase(sendChatMessage.pending, (state) => {
        state.loading = true;
      })
      .addCase(sendChatMessage.fulfilled, (state, action) => {
        state.loading = false;
        state.chatMessages.push(action.payload);
      })
      .addCase(sendChatMessage.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Failed to send message';
      })
      // Search help
      .addCase(searchHelp.pending, (state) => {
        state.loading = true;
        state.searchResults = [];
      })
      .addCase(searchHelp.fulfilled, (state, action) => {
        state.loading = false;
        state.searchResults = action.payload;
      })
      .addCase(searchHelp.rejected, (state, action) => {
        state.loading = false;
        state.error = action.error.message || 'Search failed';
      })
      // Load FAQs
      .addCase(loadFAQs.fulfilled, (state, action) => {
        state.faqs = action.payload;
      })
      // Load contextual help
      .addCase(loadContextualHelp.fulfilled, (state, action) => {
        const { suggestions, videos, faqs, wizards } = action.payload;
        state.suggestions = suggestions || [];
        state.videos = videos || [];
        if (faqs) state.faqs = faqs;
        if (wizards) state.troubleshootingWizards = wizards;
      })
      // Submit user content
      .addCase(submitUserContent.fulfilled, (state, action) => {
        state.userContent.push(action.payload);
      })
      // Record interaction
      .addCase(recordInteraction.fulfilled, (state, action) => {
        state.interactions.push(action.payload);
      })
      // Load analytics
      .addCase(loadAnalytics.fulfilled, (state, action) => {
        state.analytics = action.payload;
      })
      // Start troubleshooting
      .addCase(startTroubleshooting.fulfilled, (state, action) => {
        // Add wizard to state if not already present
        const wizard = action.payload;
        if (!state.troubleshootingWizards.find(w => w.id === wizard.id)) {
          state.troubleshootingWizards.push(wizard);
        }
      });
  },
});

export const {
  setContext,
  toggleChat,
  addChatMessage,
  clearChat,
  toggleHelpPanel,
  setHelpPanelContent,
  addSuggestion,
  dismissSuggestion,
  setActiveSuggestion,
  toggleProactiveHelp,
  trackUserBehavior,
  markFAQHelpful,
  incrementFAQView,
  voteUserContent,
  provideFeedback,
} = helpSlice.actions;

export default helpSlice.reducer;