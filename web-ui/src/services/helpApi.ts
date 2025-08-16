import { api } from './api';
import {
  HelpContext,
  HelpInteraction,
  FAQItem,
  ChatMessage,
  TroubleshootingWizard,
  UserHelpContent,
  HelpAnalytics,
  VideoSnippet,
  HelpSearchResult,
  HelpSuggestion,
} from '../components/HelpSystem/types';

// Help API endpoints
export const helpApi = {
  // Chat API
  sendChatMessage: async (data: { message: string; context: HelpContext }) => {
    // In production, this would call the actual LLM API
    // For now, we'll simulate intelligent responses
    const response = await simulateLLMResponse(data.message, data.context);
    return {
      data: {
        id: `msg-${Date.now()}`,
        type: 'assistant' as const,
        content: response.content,
        timestamp: new Date(),
        context: data.context,
        actions: response.actions,
      } as ChatMessage,
    };
  },

  // Search API
  searchHelp: async (data: { query: string; context?: HelpContext }) => {
    // Simulate search with natural language processing
    const results = await simulateSearch(data.query, data.context);
    return { data: results };
  },

  // FAQ API
  getFAQs: async (context?: HelpContext) => {
    // Get context-specific FAQs
    const faqs = getContextualFAQs(context);
    return { data: faqs };
  },

  // Contextual Help API
  getContextualHelp: async (context: HelpContext) => {
    const suggestions = generateSuggestions(context);
    const videos = getContextualVideos(context);
    const faqs = getContextualFAQs(context);
    const wizards = getContextualWizards(context);
    
    return {
      data: {
        suggestions,
        videos,
        faqs,
        wizards,
      },
    };
  },

  // User Content API
  submitUserContent: async (content: Partial<UserHelpContent>) => {
    const newContent: UserHelpContent = {
      id: `uc-${Date.now()}`,
      userId: 'current-user',
      userName: 'Current User',
      type: content.type || 'tip',
      title: content.title || '',
      content: content.content || '',
      context: content.context || { page: 'general' },
      votes: { helpful: 0, notHelpful: 0 },
      verified: false,
      created: new Date(),
      updated: new Date(),
      tags: content.tags || [],
    };
    return { data: newContent };
  },

  // Interaction Tracking API
  recordInteraction: async (interaction: Partial<HelpInteraction>) => {
    const record: HelpInteraction = {
      id: `int-${Date.now()}`,
      timestamp: new Date(),
      type: interaction.type || 'chat',
      context: interaction.context || { page: 'unknown' },
      sessionId: interaction.sessionId || '',
      resolved: interaction.resolved || false,
      ...interaction,
    };
    return { data: record };
  },

  // Analytics API
  getAnalytics: async () => {
    const analytics: HelpAnalytics = {
      totalInteractions: 1234,
      resolvedQueries: 987,
      averageResolutionTime: 45,
      mostSearchedTopics: [
        { topic: 'DNS Records', count: 234 },
        { topic: 'DNSSEC', count: 189 },
        { topic: 'GeoDNS', count: 156 },
        { topic: 'Health Checks', count: 142 },
        { topic: 'Traffic Policies', count: 98 },
      ],
      userSatisfaction: 4.2,
      commonIssues: [
        { issue: 'DNS propagation delays', frequency: 78 },
        { issue: 'DNSSEC validation errors', frequency: 56 },
        { issue: 'Record configuration', frequency: 45 },
      ],
      peakHelpHours: [
        { hour: 10, count: 156 },
        { hour: 14, count: 189 },
        { hour: 16, count: 167 },
      ],
      contextualPatterns: [
        {
          context: { page: 'records', action: 'create' },
          frequency: 234,
          resolutionRate: 0.89,
        },
        {
          context: { page: 'dnssec', action: 'enable' },
          frequency: 167,
          resolutionRate: 0.76,
        },
      ],
    };
    return { data: analytics };
  },

  // Troubleshooting API
  getTroubleshootingWizard: async (wizardId: string) => {
    const wizard = troubleshootingWizards.find(w => w.id === wizardId);
    return { data: wizard };
  },

  // Documentation fetch
  fetchDocumentation: async (topic: string) => {
    // This would use WebFetch in production
    return {
      data: {
        content: `Documentation for ${topic}`,
        url: `https://docs.atlasdns.com/${topic}`,
      },
    };
  },
};

// Simulate LLM responses with context awareness
async function simulateLLMResponse(message: string, context: HelpContext) {
  const lowerMessage = message.toLowerCase();
  
  // Context-aware responses based on current page
  if (context.page === 'records') {
    if (lowerMessage.includes('add') || lowerMessage.includes('create')) {
      return {
        content: `To add a new DNS record:
1. Click the "Add Record" button
2. Select the record type (A, AAAA, CNAME, etc.)
3. Enter the hostname and value
4. Set the TTL (Time To Live)
5. Click "Save"

Would you like me to guide you through adding a specific type of record?`,
        actions: [
          { label: 'Add A Record', action: 'openAddRecord', data: { type: 'A' } },
          { label: 'Add MX Record', action: 'openAddRecord', data: { type: 'MX' } },
          { label: 'View Tutorial', action: 'playVideo', data: { id: 'add-record-tutorial' } },
        ],
      };
    }
    if (lowerMessage.includes('ttl')) {
      return {
        content: `TTL (Time To Live) determines how long DNS resolvers cache your record:
• Short TTL (300-3600): Faster updates but more DNS queries
• Medium TTL (3600-86400): Balanced performance
• Long TTL (86400+): Better caching but slower propagation

For records that change frequently, use a shorter TTL. For stable records, a longer TTL improves performance.`,
        actions: [
          { label: 'Learn More', action: 'openDocs', data: { topic: 'ttl' } },
        ],
      };
    }
  }
  
  if (context.page === 'dnssec') {
    if (lowerMessage.includes('enable') || lowerMessage.includes('setup')) {
      return {
        content: `To enable DNSSEC for your zone:
1. Navigate to the DNSSEC tab
2. Click "Enable DNSSEC"
3. Choose your key algorithm (RSA or ECDSA)
4. Copy the DS records
5. Add them to your domain registrar

DNSSEC adds cryptographic signatures to prevent DNS spoofing. Would you like to start the DNSSEC wizard?`,
        actions: [
          { label: 'Start DNSSEC Wizard', action: 'startWizard', data: { wizard: 'dnssec' } },
          { label: 'View Requirements', action: 'openDocs', data: { topic: 'dnssec-requirements' } },
        ],
      };
    }
  }
  
  // General helpful response
  return {
    content: `I understand you're asking about "${message}" in the ${context.page} section. 
Let me help you with that. Can you provide more specific details about what you're trying to accomplish?

In the meantime, here are some relevant resources:`,
    actions: [
      { label: 'Search Documentation', action: 'search', data: { query: message } },
      { label: 'View FAQs', action: 'openFAQs', data: { context } },
      { label: 'Start Troubleshooting', action: 'troubleshoot', data: { context } },
    ],
  };
}

// Simulate intelligent search
async function simulateSearch(query: string, context?: HelpContext): Promise<HelpSearchResult[]> {
  const results: HelpSearchResult[] = [];
  const lowerQuery = query.toLowerCase();
  
  // Search through FAQs
  const faqResults = allFAQs.filter(faq => 
    faq.question.toLowerCase().includes(lowerQuery) ||
    faq.answer.toLowerCase().includes(lowerQuery) ||
    faq.tags.some(tag => tag.toLowerCase().includes(lowerQuery))
  ).map(faq => ({
    id: faq.id,
    type: 'faq' as const,
    title: faq.question,
    snippet: faq.answer.substring(0, 150) + '...',
    relevanceScore: calculateRelevance(query, faq.question + ' ' + faq.answer),
    context: context,
    highlights: [],
  }));
  
  results.push(...faqResults);
  
  // Add documentation results
  if (lowerQuery.includes('record') || lowerQuery.includes('dns')) {
    results.push({
      id: 'doc-1',
      type: 'documentation',
      title: 'DNS Record Types Guide',
      snippet: 'Complete guide to DNS record types including A, AAAA, CNAME, MX, TXT, and more...',
      relevanceScore: 0.85,
      url: 'https://docs.atlasdns.com/records',
    });
  }
  
  // Add video results
  if (lowerQuery.includes('tutorial') || lowerQuery.includes('how')) {
    results.push({
      id: 'video-1',
      type: 'video',
      title: 'Getting Started with AtlasDNS',
      snippet: 'Learn the basics of DNS management with our comprehensive video tutorial...',
      relevanceScore: 0.75,
      url: 'https://videos.atlasdns.com/getting-started',
    });
  }
  
  // Sort by relevance
  results.sort((a, b) => b.relevanceScore - a.relevanceScore);
  
  return results.slice(0, 10);
}

// Calculate relevance score
function calculateRelevance(query: string, content: string): number {
  const queryWords = query.toLowerCase().split(' ');
  const contentLower = content.toLowerCase();
  let score = 0;
  
  queryWords.forEach(word => {
    if (contentLower.includes(word)) {
      score += 1;
    }
  });
  
  return Math.min(score / queryWords.length, 1);
}

// Generate context-aware suggestions
function generateSuggestions(context: HelpContext): HelpSuggestion[] {
  const suggestions: HelpSuggestion[] = [];
  
  if (context.page === 'records' && context.action === 'create') {
    suggestions.push({
      id: 'sug-1',
      title: 'Pro Tip: Use Templates',
      description: 'Save time by using record templates for common configurations',
      type: 'tip',
      priority: 1,
      context,
      action: {
        label: 'View Templates',
        handler: () => console.log('Opening templates'),
      },
      dismissible: true,
      shown: false,
    });
  }
  
  if (context.page === 'zones' && !context.action) {
    suggestions.push({
      id: 'sug-2',
      title: 'Quick Action: Import Zone',
      description: 'Import existing DNS zones from BIND format or another provider',
      type: 'info',
      priority: 2,
      context,
      action: {
        label: 'Import Zone',
        handler: () => console.log('Opening import dialog'),
      },
      dismissible: true,
      shown: false,
    });
  }
  
  return suggestions;
}

// Get contextual videos
function getContextualVideos(context?: HelpContext): VideoSnippet[] {
  const videos: VideoSnippet[] = [
    {
      id: 'vid-1',
      title: 'DNS Records Explained',
      description: 'Understanding different DNS record types',
      url: 'https://videos.atlasdns.com/dns-records',
      duration: 300,
      context: { page: 'records' },
      tags: ['dns', 'records', 'tutorial'],
      timestamps: [
        { time: 0, label: 'Introduction' },
        { time: 60, label: 'A Records' },
        { time: 120, label: 'CNAME Records' },
        { time: 180, label: 'MX Records' },
        { time: 240, label: 'TXT Records' },
      ],
    },
    {
      id: 'vid-2',
      title: 'Setting Up DNSSEC',
      description: 'Step-by-step DNSSEC configuration',
      url: 'https://videos.atlasdns.com/dnssec-setup',
      duration: 420,
      context: { page: 'dnssec' },
      tags: ['dnssec', 'security', 'tutorial'],
    },
  ];
  
  if (!context) return videos;
  
  return videos.filter(v => v.context.page === context.page);
}

// Get contextual FAQs
function getContextualFAQs(context?: HelpContext): FAQItem[] {
  if (!context) return allFAQs;
  
  return allFAQs.filter(faq => 
    !faq.context || faq.context.some(c => c.page === context.page)
  );
}

// Get contextual troubleshooting wizards
function getContextualWizards(context?: HelpContext): TroubleshootingWizard[] {
  if (!context) return troubleshootingWizards;
  
  return troubleshootingWizards.filter(wizard => 
    wizard.category === context.page || wizard.category === 'general'
  );
}

// Sample FAQ data
const allFAQs: FAQItem[] = [
  {
    id: 'faq-1',
    question: 'What is DNS propagation and how long does it take?',
    answer: 'DNS propagation is the time it takes for DNS changes to be updated across all DNS servers worldwide. It typically takes 24-48 hours but can be faster with lower TTL values.',
    category: 'general',
    tags: ['dns', 'propagation', 'ttl'],
    viewCount: 1234,
    helpfulCount: 987,
    notHelpfulCount: 23,
    relatedQuestions: ['faq-2', 'faq-3'],
    docsUrl: 'https://docs.atlasdns.com/propagation',
    lastUpdated: new Date(),
    context: [{ page: 'records' }, { page: 'zones' }],
  },
  {
    id: 'faq-2',
    question: 'How do I add an A record?',
    answer: 'To add an A record: 1) Go to DNS Records, 2) Click Add Record, 3) Select A from the type dropdown, 4) Enter the hostname and IPv4 address, 5) Set TTL, 6) Click Save.',
    category: 'records',
    tags: ['records', 'a-record', 'ipv4'],
    viewCount: 876,
    helpfulCount: 765,
    notHelpfulCount: 12,
    videoUrl: 'https://videos.atlasdns.com/add-a-record',
    lastUpdated: new Date(),
    context: [{ page: 'records' }],
  },
  {
    id: 'faq-3',
    question: 'What is DNSSEC and should I enable it?',
    answer: 'DNSSEC adds cryptographic signatures to DNS records to prevent DNS spoofing. Enable it for enhanced security, especially for sensitive domains.',
    category: 'security',
    tags: ['dnssec', 'security', 'dns'],
    viewCount: 654,
    helpfulCount: 543,
    notHelpfulCount: 8,
    docsUrl: 'https://docs.atlasdns.com/dnssec',
    lastUpdated: new Date(),
    context: [{ page: 'dnssec' }],
  },
];

// Sample troubleshooting wizards
const troubleshootingWizards: TroubleshootingWizard[] = [
  {
    id: 'wizard-1',
    title: 'DNS Resolution Issues',
    description: 'Troubleshoot problems with DNS resolution',
    category: 'general',
    steps: [
      {
        id: 'step-1',
        title: 'Check DNS Records',
        description: 'Verify that DNS records are correctly configured',
        checks: [
          {
            id: 'check-1',
            label: 'Are A/AAAA records present?',
            action: async () => true,
            solution: 'Add missing A or AAAA records',
            documentation: 'https://docs.atlasdns.com/records',
          },
        ],
        nextSteps: ['step-2'],
      },
    ],
    commonIssues: ['DNS not resolving', 'Wrong IP returned', 'Slow resolution'],
    estimatedTime: 5,
  },
];

export default helpApi;