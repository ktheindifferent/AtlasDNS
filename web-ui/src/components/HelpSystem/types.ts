export interface HelpContext {
  page: string;
  component?: string;
  feature?: string;
  action?: string;
  data?: Record<string, any>;
}

export interface HelpInteraction {
  id: string;
  timestamp: Date;
  userId?: string;
  type: 'chat' | 'tooltip' | 'video' | 'faq' | 'search' | 'wizard' | 'suggestion';
  context: HelpContext;
  query?: string;
  response?: string;
  helpful?: boolean;
  feedback?: string;
  sessionId: string;
  resolved: boolean;
  duration?: number;
}

export interface HelpSuggestion {
  id: string;
  title: string;
  description: string;
  type: 'tip' | 'warning' | 'info' | 'tutorial';
  priority: number;
  context: HelpContext;
  action?: {
    label: string;
    handler: () => void;
  };
  dismissible: boolean;
  shown: boolean;
}

export interface FAQItem {
  id: string;
  question: string;
  answer: string;
  category: string;
  tags: string[];
  viewCount: number;
  helpfulCount: number;
  notHelpfulCount: number;
  relatedQuestions?: string[];
  videoUrl?: string;
  docsUrl?: string;
  lastUpdated: Date;
  context?: HelpContext[];
}

export interface VideoSnippet {
  id: string;
  title: string;
  description: string;
  url: string;
  thumbnailUrl?: string;
  duration: number;
  context: HelpContext;
  tags: string[];
  transcript?: string;
  timestamps?: {
    time: number;
    label: string;
    action?: string;
  }[];
}

export interface TroubleshootingStep {
  id: string;
  title: string;
  description: string;
  checks: {
    id: string;
    label: string;
    action: () => Promise<boolean>;
    solution?: string;
    documentation?: string;
  }[];
  nextSteps?: string[];
}

export interface TroubleshootingWizard {
  id: string;
  title: string;
  description: string;
  category: string;
  steps: TroubleshootingStep[];
  commonIssues: string[];
  estimatedTime: number;
}

export interface UserHelpContent {
  id: string;
  userId: string;
  userName: string;
  type: 'tip' | 'solution' | 'workaround' | 'guide';
  title: string;
  content: string;
  context: HelpContext;
  votes: {
    helpful: number;
    notHelpful: number;
  };
  verified: boolean;
  created: Date;
  updated: Date;
  tags: string[];
}

export interface HelpAnalytics {
  totalInteractions: number;
  resolvedQueries: number;
  averageResolutionTime: number;
  mostSearchedTopics: Array<{ topic: string; count: number }>;
  userSatisfaction: number;
  commonIssues: Array<{ issue: string; frequency: number }>;
  peakHelpHours: Array<{ hour: number; count: number }>;
  contextualPatterns: Array<{
    context: HelpContext;
    frequency: number;
    resolutionRate: number;
  }>;
}

export interface ChatMessage {
  id: string;
  type: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  context?: HelpContext;
  attachments?: Array<{
    type: 'image' | 'file' | 'link';
    url: string;
    name: string;
  }>;
  actions?: Array<{
    label: string;
    action: string;
    data?: any;
  }>;
  feedback?: {
    helpful?: boolean;
    comment?: string;
  };
}

export interface HelpSearchResult {
  id: string;
  type: 'faq' | 'documentation' | 'video' | 'user-content' | 'tutorial';
  title: string;
  snippet: string;
  url?: string;
  relevanceScore: number;
  context?: HelpContext;
  highlights?: string[];
}