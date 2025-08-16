import { useState, useCallback, useEffect } from 'react';
import { useCommandHistory } from './useCommandHistory';

interface SearchPattern {
  pattern: RegExp;
  suggestions: string[];
}

// AI-like search patterns and suggestions
const searchPatterns: SearchPattern[] = [
  {
    pattern: /create|add|new/i,
    suggestions: [
      'Create new DNS zone',
      'Add DNS record',
      'Create health check',
      'Add new user'
    ]
  },
  {
    pattern: /search|find|lookup/i,
    suggestions: [
      'Search DNS zones',
      'Find DNS records',
      'Search logs',
      'Lookup domain'
    ]
  },
  {
    pattern: /config|setting|preference/i,
    suggestions: [
      'Open settings',
      'Configure DNS',
      'System preferences',
      'User settings'
    ]
  },
  {
    pattern: /monitor|health|status/i,
    suggestions: [
      'View health checks',
      'Monitor services',
      'System status',
      'Check DNS health'
    ]
  },
  {
    pattern: /analytic|stat|metric/i,
    suggestions: [
      'View analytics',
      'DNS statistics',
      'Performance metrics',
      'Traffic analysis'
    ]
  },
  {
    pattern: /zone|domain/i,
    suggestions: [
      'Manage DNS zones',
      'Create new zone',
      'Import zone file',
      'Export zones'
    ]
  },
  {
    pattern: /record|dns/i,
    suggestions: [
      'Add DNS record',
      'Search records',
      'Edit record',
      'Delete record'
    ]
  },
  {
    pattern: /cache|flush|clear/i,
    suggestions: [
      'Flush DNS cache',
      'Clear cache',
      'Purge records',
      'Reset cache'
    ]
  },
  {
    pattern: /export|download|backup/i,
    suggestions: [
      'Export zones',
      'Download records',
      'Backup configuration',
      'Export analytics'
    ]
  },
  {
    pattern: /import|upload|restore/i,
    suggestions: [
      'Import zone file',
      'Upload records',
      'Restore backup',
      'Import configuration'
    ]
  }
];

export const useAISearch = () => {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const { getFrequentCommands, getCommandStats } = useCommandHistory();

  // Simulate AI-powered search suggestions
  const getSuggestions = useCallback(async (query: string) => {
    setIsLoading(true);
    
    // Simulate network delay for AI processing
    await new Promise(resolve => setTimeout(resolve, 100));
    
    try {
      const lowerQuery = query.toLowerCase();
      const suggestedItems: string[] = [];
      
      // Find matching patterns
      searchPatterns.forEach(({ pattern, suggestions }) => {
        if (pattern.test(lowerQuery)) {
          // Filter suggestions based on the specific query
          const filtered = suggestions.filter(s => 
            s.toLowerCase().includes(lowerQuery) ||
            lowerQuery.split(' ').some(word => s.toLowerCase().includes(word))
          );
          suggestedItems.push(...filtered);
        }
      });
      
      // Add contextual suggestions based on query structure
      if (query.includes(' in ')) {
        const parts = query.split(' in ');
        const action = parts[0];
        const context = parts[1];
        suggestedItems.push(
          `Search for ${action} in ${context}`,
          `Find ${action} in ${context}`,
          `${action} within ${context}`
        );
      }
      
      // Add smart suggestions based on incomplete queries
      if (query.endsWith(' ')) {
        const baseQuery = query.trim();
        suggestedItems.push(
          `${baseQuery} all`,
          `${baseQuery} recent`,
          `${baseQuery} today`,
          `${baseQuery} this week`
        );
      }
      
      // Remove duplicates and limit results
      const unique = Array.from(new Set(suggestedItems)).slice(0, 5);
      
      setSuggestions(unique);
    } catch (error) {
      console.error('Failed to get AI suggestions:', error);
      setSuggestions([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Get contextual suggestions based on user behavior
  const getContextualSuggestions = useCallback((currentPath: string) => {
    const contextSuggestions: string[] = [];
    
    // Suggest based on current page
    switch (currentPath) {
      case '/zones':
        contextSuggestions.push(
          'Create new zone',
          'Import zone file',
          'Search zones',
          'Export all zones'
        );
        break;
      case '/analytics':
        contextSuggestions.push(
          'View today\'s stats',
          'Export analytics data',
          'Compare periods',
          'Generate report'
        );
        break;
      case '/health-checks':
        contextSuggestions.push(
          'Create health check',
          'View failed checks',
          'Configure alerts',
          'Test all endpoints'
        );
        break;
      default:
        // Generic suggestions
        const frequentCommands = getFrequentCommands(3);
        if (frequentCommands.length > 0) {
          contextSuggestions.push(...frequentCommands.map(cmd => 
            `Run: ${cmd.replace(/-/g, ' ')}`
          ));
        }
    }
    
    return contextSuggestions;
  }, [getFrequentCommands]);

  // Learn from user behavior
  const learnFromSelection = useCallback((query: string, selected: string) => {
    // In a real implementation, this would send data to an AI service
    // to improve future suggestions
    console.log('Learning from selection:', { query, selected });
    
    // Store the association locally for now
    try {
      const learningKey = 'atlas-dns-ai-learning';
      const existing = localStorage.getItem(learningKey);
      const data = existing ? JSON.parse(existing) : {};
      
      if (!data[query]) {
        data[query] = [];
      }
      
      data[query].push({
        selected,
        timestamp: Date.now()
      });
      
      // Keep only recent entries
      if (data[query].length > 10) {
        data[query] = data[query].slice(-10);
      }
      
      localStorage.setItem(learningKey, JSON.stringify(data));
    } catch (error) {
      console.error('Failed to store learning data:', error);
    }
  }, []);

  // Get smart predictions based on time of day and user patterns
  const getSmartPredictions = useCallback(() => {
    const hour = new Date().getHours();
    const predictions: string[] = [];
    
    // Morning predictions (6 AM - 12 PM)
    if (hour >= 6 && hour < 12) {
      predictions.push(
        'View dashboard',
        'Check system health',
        'Review overnight logs'
      );
    }
    // Afternoon predictions (12 PM - 6 PM)
    else if (hour >= 12 && hour < 18) {
      predictions.push(
        'View analytics',
        'Manage DNS zones',
        'Check performance metrics'
      );
    }
    // Evening predictions (6 PM - 12 AM)
    else if (hour >= 18) {
      predictions.push(
        'Export daily report',
        'Review today\'s changes',
        'Backup configuration'
      );
    }
    // Night predictions (12 AM - 6 AM)
    else {
      predictions.push(
        'View system logs',
        'Check alert status',
        'Monitor health checks'
      );
    }
    
    return predictions;
  }, []);

  return {
    suggestions,
    isLoading,
    getSuggestions,
    getContextualSuggestions,
    learnFromSelection,
    getSmartPredictions
  };
};