import { useState, useEffect, useCallback } from 'react';

const STORAGE_KEY = 'atlas-dns-command-history';
const MAX_HISTORY_SIZE = 50;

export interface CommandHistoryEntry {
  commandId: string;
  timestamp: number;
  count: number;
}

export const useCommandHistory = () => {
  const [history, setHistory] = useState<CommandHistoryEntry[]>([]);

  // Load history from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        setHistory(parsed);
      }
    } catch (error) {
      console.error('Failed to load command history:', error);
    }
  }, []);

  // Save history to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    } catch (error) {
      console.error('Failed to save command history:', error);
    }
  }, [history]);

  // Add a command to history
  const addToHistory = useCallback((commandId: string) => {
    setHistory(prev => {
      const existing = prev.find(entry => entry.commandId === commandId);
      
      if (existing) {
        // Update existing entry
        const updated = prev.map(entry =>
          entry.commandId === commandId
            ? { ...entry, timestamp: Date.now(), count: entry.count + 1 }
            : entry
        );
        // Sort by timestamp (most recent first)
        return updated.sort((a, b) => b.timestamp - a.timestamp);
      } else {
        // Add new entry
        const newEntry: CommandHistoryEntry = {
          commandId,
          timestamp: Date.now(),
          count: 1
        };
        
        const updated = [newEntry, ...prev];
        
        // Keep only the most recent entries
        if (updated.length > MAX_HISTORY_SIZE) {
          updated.pop();
        }
        
        return updated;
      }
    });
  }, []);

  // Get recent commands
  const getRecentCommands = useCallback((limit: number = 5): string[] => {
    return history
      .slice(0, limit)
      .map(entry => entry.commandId);
  }, [history]);

  // Get frequently used commands
  const getFrequentCommands = useCallback((limit: number = 5): string[] => {
    return [...history]
      .sort((a, b) => b.count - a.count)
      .slice(0, limit)
      .map(entry => entry.commandId);
  }, [history]);

  // Clear history
  const clearHistory = useCallback(() => {
    setHistory([]);
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  // Get command usage stats
  const getCommandStats = useCallback((commandId: string) => {
    const entry = history.find(e => e.commandId === commandId);
    return entry || null;
  }, [history]);

  return {
    history,
    addToHistory,
    getRecentCommands,
    getFrequentCommands,
    clearHistory,
    getCommandStats
  };
};