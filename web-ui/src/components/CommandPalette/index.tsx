import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Command } from 'cmdk';
import Fuse from 'fuse.js';
import { 
  HomeIcon,
  CogIcon,
  UserGroupIcon,
  ChartBarIcon,
  GlobeAltIcon,
  ShieldCheckIcon,
  ServerIcon,
  DocumentTextIcon,
  MagnifyingGlassIcon,
  ClockIcon,
  CommandLineIcon,
  ArrowRightIcon,
  XMarkIcon
} from '@heroicons/react/24/outline';
import './styles.css';
import { useCommandHistory } from '../../hooks/useCommandHistory';
import { useAISearch } from '../../hooks/useAISearch';

export interface CommandItem {
  id: string;
  title: string;
  subtitle?: string;
  icon?: React.ComponentType<{ className?: string }>;
  action: () => void;
  keywords?: string[];
  category?: string;
  shortcut?: string;
  aliases?: string[];
}

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const CommandPalette: React.FC<CommandPaletteProps> = ({ open, onOpenChange }) => {
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const { history, addToHistory, getRecentCommands } = useCommandHistory();
  const { suggestions, getSuggestions } = useAISearch();

  // Command definitions with categories, shortcuts, and aliases
  const commands: CommandItem[] = useMemo(() => [
    // Navigation Commands
    {
      id: 'nav-dashboard',
      title: 'Dashboard',
      subtitle: 'View system overview',
      icon: HomeIcon,
      action: () => navigate('/dashboard'),
      keywords: ['home', 'overview', 'main'],
      category: 'Navigation',
      shortcut: 'cmd+d',
      aliases: ['home', 'main']
    },
    {
      id: 'nav-zones',
      title: 'DNS Zones',
      subtitle: 'Manage DNS zones',
      icon: GlobeAltIcon,
      action: () => navigate('/zones'),
      keywords: ['dns', 'domains', 'zones'],
      category: 'Navigation',
      shortcut: 'cmd+z',
      aliases: ['domains']
    },
    {
      id: 'nav-health',
      title: 'Health Checks',
      subtitle: 'Monitor service health',
      icon: ShieldCheckIcon,
      action: () => navigate('/health-checks'),
      keywords: ['monitor', 'health', 'status'],
      category: 'Navigation',
      shortcut: 'cmd+h',
      aliases: ['monitoring', 'status']
    },
    {
      id: 'nav-analytics',
      title: 'Analytics',
      subtitle: 'View DNS analytics',
      icon: ChartBarIcon,
      action: () => navigate('/analytics'),
      keywords: ['stats', 'metrics', 'data'],
      category: 'Navigation',
      shortcut: 'cmd+a',
      aliases: ['stats', 'metrics']
    },
    {
      id: 'nav-users',
      title: 'Users',
      subtitle: 'Manage users',
      icon: UserGroupIcon,
      action: () => navigate('/users'),
      keywords: ['people', 'accounts', 'team'],
      category: 'Navigation',
      shortcut: 'cmd+u',
      aliases: ['team', 'accounts']
    },
    {
      id: 'nav-settings',
      title: 'Settings',
      subtitle: 'System configuration',
      icon: CogIcon,
      action: () => navigate('/settings'),
      keywords: ['config', 'preferences', 'setup'],
      category: 'Navigation',
      shortcut: 'cmd+,',
      aliases: ['preferences', 'config']
    },
    
    // Zone Management Actions
    {
      id: 'action-create-zone',
      title: 'Create New Zone',
      subtitle: 'Add a new DNS zone',
      icon: GlobeAltIcon,
      action: () => {
        navigate('/zones');
        // Trigger create zone modal (would need to be implemented)
        setTimeout(() => {
          const event = new CustomEvent('openCreateZoneModal');
          window.dispatchEvent(event);
        }, 100);
      },
      keywords: ['add', 'new', 'zone', 'domain'],
      category: 'Actions',
      shortcut: 'cmd+n',
      aliases: ['add zone', 'new domain']
    },
    {
      id: 'action-import-zone',
      title: 'Import Zone File',
      subtitle: 'Import DNS records from file',
      icon: DocumentTextIcon,
      action: () => {
        navigate('/zones');
        setTimeout(() => {
          const event = new CustomEvent('openImportZoneModal');
          window.dispatchEvent(event);
        }, 100);
      },
      keywords: ['import', 'upload', 'zone', 'file'],
      category: 'Actions',
      aliases: ['upload zone']
    },
    
    // Record Management Actions
    {
      id: 'action-add-record',
      title: 'Add DNS Record',
      subtitle: 'Create a new DNS record',
      icon: ServerIcon,
      action: () => {
        const event = new CustomEvent('openAddRecordModal');
        window.dispatchEvent(event);
      },
      keywords: ['add', 'record', 'dns', 'create'],
      category: 'Actions',
      shortcut: 'cmd+r',
      aliases: ['new record', 'create record']
    },
    
    // Search Actions
    {
      id: 'search-zones',
      title: 'Search Zones',
      subtitle: 'Find DNS zones',
      icon: MagnifyingGlassIcon,
      action: () => {
        navigate('/zones');
        setTimeout(() => {
          const searchInput = document.querySelector('[data-search="zones"]') as HTMLInputElement;
          if (searchInput) {
            searchInput.focus();
          }
        }, 100);
      },
      keywords: ['find', 'search', 'zone', 'lookup'],
      category: 'Search',
      shortcut: 'cmd+shift+z',
      aliases: ['find zone']
    },
    {
      id: 'search-records',
      title: 'Search DNS Records',
      subtitle: 'Find specific DNS records',
      icon: MagnifyingGlassIcon,
      action: () => {
        const event = new CustomEvent('openGlobalRecordSearch');
        window.dispatchEvent(event);
      },
      keywords: ['find', 'search', 'record', 'lookup'],
      category: 'Search',
      shortcut: 'cmd+shift+r',
      aliases: ['find record']
    },
    {
      id: 'search-logs',
      title: 'Search Logs',
      subtitle: 'Search system logs',
      icon: DocumentTextIcon,
      action: () => {
        navigate('/logs');
        setTimeout(() => {
          const searchInput = document.querySelector('[data-search="logs"]') as HTMLInputElement;
          if (searchInput) {
            searchInput.focus();
          }
        }, 100);
      },
      keywords: ['logs', 'history', 'audit'],
      category: 'Search',
      shortcut: 'cmd+shift+l',
      aliases: ['view logs']
    },
    
    // System Actions
    {
      id: 'action-flush-cache',
      title: 'Flush DNS Cache',
      subtitle: 'Clear DNS resolver cache',
      icon: CommandLineIcon,
      action: () => {
        const event = new CustomEvent('flushDNSCache');
        window.dispatchEvent(event);
      },
      keywords: ['flush', 'clear', 'cache', 'dns'],
      category: 'System',
      aliases: ['clear cache']
    },
    {
      id: 'action-reload-config',
      title: 'Reload Configuration',
      subtitle: 'Reload system configuration',
      icon: CogIcon,
      action: () => {
        const event = new CustomEvent('reloadConfiguration');
        window.dispatchEvent(event);
      },
      keywords: ['reload', 'refresh', 'config'],
      category: 'System',
      aliases: ['refresh config']
    },
    {
      id: 'action-export-data',
      title: 'Export Data',
      subtitle: 'Export zones and records',
      icon: DocumentTextIcon,
      action: () => {
        const event = new CustomEvent('openExportModal');
        window.dispatchEvent(event);
      },
      keywords: ['export', 'download', 'backup'],
      category: 'System',
      aliases: ['download data', 'backup']
    }
  ], [navigate]);

  // Fuzzy search setup
  const fuse = useMemo(() => {
    return new Fuse(commands, {
      keys: ['title', 'subtitle', 'keywords', 'aliases'],
      threshold: 0.3,
      includeScore: true
    });
  }, [commands]);

  // Filter commands based on search
  const filteredCommands = useMemo(() => {
    if (!search) {
      // Show recent commands when no search
      const recentIds = getRecentCommands(5);
      const recent = commands.filter(cmd => recentIds.includes(cmd.id));
      const others = commands.filter(cmd => !recentIds.includes(cmd.id));
      return [...recent, ...others];
    }
    
    const results = fuse.search(search);
    return results.map(result => result.item);
  }, [search, fuse, commands, getRecentCommands]);

  // Group commands by category
  const groupedCommands = useMemo(() => {
    const groups: Record<string, CommandItem[]> = {};
    
    filteredCommands.forEach(command => {
      const category = command.category || 'Other';
      if (!groups[category]) {
        groups[category] = [];
      }
      groups[category].push(command);
    });
    
    return groups;
  }, [filteredCommands]);

  // Handle command execution
  const executeCommand = useCallback((command: CommandItem) => {
    addToHistory(command.id);
    command.action();
    onOpenChange(false);
    setSearch('');
  }, [addToHistory, onOpenChange]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (open) {
        // ESC to close
        if (e.key === 'Escape') {
          onOpenChange(false);
        }
        return;
      }

      // Global shortcut to open (Cmd/Ctrl + K)
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        onOpenChange(true);
      }

      // Direct command shortcuts when palette is closed
      commands.forEach(command => {
        if (command.shortcut) {
          const parts = command.shortcut.split('+');
          const modifierKey = parts[0];
          const key = parts[parts.length - 1];
          
          const modifierPressed = 
            (modifierKey.includes('cmd') && (e.metaKey || e.ctrlKey)) ||
            (modifierKey.includes('shift') && e.shiftKey);
          
          if (modifierPressed && e.key.toLowerCase() === key.toLowerCase()) {
            e.preventDefault();
            executeCommand(command);
          }
        }
      });
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, onOpenChange, commands, executeCommand]);

  // AI-powered suggestions
  useEffect(() => {
    if (search.length > 2) {
      getSuggestions(search);
    }
  }, [search, getSuggestions]);

  return (
    <Command.Dialog 
      open={open} 
      onOpenChange={onOpenChange}
      label="Command Palette"
      className="command-palette-dialog"
    >
      <div className="command-palette-header">
        <MagnifyingGlassIcon className="search-icon" />
        <Command.Input
          value={search}
          onValueChange={setSearch}
          placeholder="Type a command or search..."
          className="command-input"
        />
        <button 
          onClick={() => onOpenChange(false)}
          className="close-button"
        >
          <XMarkIcon className="close-icon" />
        </button>
      </div>

      <Command.List className="command-list">
        {search && suggestions.length > 0 && (
          <Command.Group heading="AI Suggestions" className="command-group">
            {suggestions.map((suggestion, index) => (
              <Command.Item
                key={`ai-${index}`}
                value={suggestion}
                onSelect={() => setSearch(suggestion)}
                className="command-item ai-suggestion"
              >
                <MagnifyingGlassIcon className="item-icon" />
                <span>{suggestion}</span>
              </Command.Item>
            ))}
          </Command.Group>
        )}

        {!search && getRecentCommands(5).length > 0 && (
          <Command.Group heading="Recent" className="command-group">
            {getRecentCommands(5).map(id => {
              const command = commands.find(cmd => cmd.id === id);
              if (!command) return null;
              
              const Icon = command.icon || ArrowRightIcon;
              return (
                <Command.Item
                  key={command.id}
                  value={command.title}
                  onSelect={() => executeCommand(command)}
                  className="command-item"
                >
                  <div className="item-content">
                    <Icon className="item-icon" />
                    <div className="item-text">
                      <span className="item-title">{command.title}</span>
                      {command.subtitle && (
                        <span className="item-subtitle">{command.subtitle}</span>
                      )}
                    </div>
                    {command.shortcut && (
                      <span className="item-shortcut">{command.shortcut}</span>
                    )}
                  </div>
                </Command.Item>
              );
            })}
          </Command.Group>
        )}

        {Object.entries(groupedCommands).map(([category, items]) => (
          <Command.Group key={category} heading={category} className="command-group">
            {items.map(command => {
              const Icon = command.icon || ArrowRightIcon;
              return (
                <Command.Item
                  key={command.id}
                  value={`${command.title} ${command.aliases?.join(' ') || ''}`}
                  onSelect={() => executeCommand(command)}
                  className="command-item"
                >
                  <div className="item-content">
                    <Icon className="item-icon" />
                    <div className="item-text">
                      <span className="item-title">{command.title}</span>
                      {command.subtitle && (
                        <span className="item-subtitle">{command.subtitle}</span>
                      )}
                    </div>
                    {command.shortcut && (
                      <span className="item-shortcut">{command.shortcut}</span>
                    )}
                  </div>
                </Command.Item>
              );
            })}
          </Command.Group>
        ))}

        <Command.Empty className="command-empty">
          No results found for "{search}"
        </Command.Empty>
      </Command.List>

      <div className="command-footer">
        <div className="footer-hints">
          <span className="hint">
            <kbd>↑↓</kbd> Navigate
          </span>
          <span className="hint">
            <kbd>↵</kbd> Select
          </span>
          <span className="hint">
            <kbd>ESC</kbd> Close
          </span>
        </div>
      </div>
    </Command.Dialog>
  );
};

export default CommandPalette;