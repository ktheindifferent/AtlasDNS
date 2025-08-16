import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Paper,
  TextField,
  InputAdornment,
  IconButton,
  Button,
  Card,
  CardContent,
  CardActions,
  Typography,
  Chip,
  Avatar,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondaryAction,
  Divider,
  CircularProgress,
  Alert,
  Tabs,
  Tab,
  Badge,
  Tooltip,
  Fade,
  LinearProgress,
  Menu,
  MenuItem,
  FormControlLabel,
  Switch,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Search as SearchIcon,
  Mic as MicIcon,
  MicOff as MicOffIcon,
  Clear as ClearIcon,
  Tune as TuneIcon,
  Psychology as AIIcon,
  Article as DocsIcon,
  QuestionAnswer as FAQIcon,
  PlayCircle as VideoIcon,
  People as CommunityIcon,
  Code as CodeIcon,
  Lightbulb as TipIcon,
  History as HistoryIcon,
  TrendingUp as TrendingIcon,
  AutoAwesome as AutoAwesomeIcon,
  FilterList as FilterIcon,
  OpenInNew as OpenIcon,
  ContentCopy as CopyIcon,
  Bookmark as BookmarkIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import { searchHelp, recordInteraction } from '../../store/slices/helpSlice';
import { HelpSearchResult } from './types';
import ReactMarkdown from 'react-markdown';

interface NaturalLanguageSearchProps {
  embedded?: boolean;
  onResultSelect?: (result: HelpSearchResult) => void;
  placeholder?: string;
  autoFocus?: boolean;
}

interface SearchFilters {
  types: Set<string>;
  dateRange: 'all' | 'day' | 'week' | 'month' | 'year';
  sortBy: 'relevance' | 'date' | 'popularity';
  contextAware: boolean;
}

const NaturalLanguageSearch: React.FC<NaturalLanguageSearchProps> = ({
  embedded = false,
  onResultSelect,
  placeholder = "Ask me anything about AtlasDNS...",
  autoFocus = false,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch();
  const inputRef = useRef<HTMLInputElement>(null);
  
  const {
    searchResults,
    loading,
    currentContext,
    sessionId,
  } = useSelector((state: RootState) => state.help);
  
  const [query, setQuery] = useState('');
  const [isListening, setIsListening] = useState(false);
  const [searchHistory, setSearchHistory] = useState<string[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [filters, setFilters] = useState<SearchFilters>({
    types: new Set(['faq', 'documentation', 'video', 'user-content', 'tutorial']),
    dateRange: 'all',
    sortBy: 'relevance',
    contextAware: true,
  });
  const [filterMenuAnchor, setFilterMenuAnchor] = useState<null | HTMLElement>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [bookmarkedResults, setBookmarkedResults] = useState<Set<string>>(new Set());
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [searchMetrics, setSearchMetrics] = useState({
    totalResults: 0,
    searchTime: 0,
    confidence: 0,
  });
  
  // Load search history from localStorage
  useEffect(() => {
    const history = localStorage.getItem('help-search-history');
    if (history) {
      setSearchHistory(JSON.parse(history));
    }
  }, []);
  
  // Generate search suggestions based on input
  useEffect(() => {
    if (query.length > 2) {
      // Simulate intelligent suggestions
      const contextualSuggestions = generateSuggestions(query, currentContext);
      setSuggestions(contextualSuggestions);
    } else {
      setSuggestions([]);
    }
  }, [query, currentContext]);
  
  // Auto-focus input
  useEffect(() => {
    if (autoFocus && inputRef.current) {
      inputRef.current.focus();
    }
  }, [autoFocus]);
  
  // Handle search
  const handleSearch = async (searchQuery?: string) => {
    const finalQuery = searchQuery || query;
    if (!finalQuery.trim()) return;
    
    const startTime = Date.now();
    
    // Record interaction
    dispatch(recordInteraction({
      type: 'search',
      context: filters.contextAware ? currentContext : undefined,
      query: finalQuery,
      sessionId,
    }));
    
    // Add to search history
    const newHistory = [finalQuery, ...searchHistory.filter(h => h !== finalQuery)].slice(0, 10);
    setSearchHistory(newHistory);
    localStorage.setItem('help-search-history', JSON.stringify(newHistory));
    
    try {
      const result = await dispatch(searchHelp({
        query: finalQuery,
        context: filters.contextAware ? currentContext : undefined,
      })).unwrap();
      
      // Calculate search metrics
      setSearchMetrics({
        totalResults: result.length,
        searchTime: Date.now() - startTime,
        confidence: calculateSearchConfidence(result),
      });
    } catch (error) {
      console.error('Search failed:', error);
    }
  };
  
  // Handle voice search
  const handleVoiceSearch = () => {
    if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
      const SpeechRecognition = (window as any).webkitSpeechRecognition || (window as any).SpeechRecognition;
      const recognition = new SpeechRecognition();
      
      recognition.continuous = false;
      recognition.interimResults = false;
      recognition.lang = 'en-US';
      
      if (isListening) {
        recognition.stop();
        setIsListening(false);
      } else {
        recognition.start();
        setIsListening(true);
        
        recognition.onresult = (event: any) => {
          const transcript = event.results[0][0].transcript;
          setQuery(transcript);
          setIsListening(false);
          handleSearch(transcript);
        };
        
        recognition.onerror = () => {
          setIsListening(false);
        };
        
        recognition.onend = () => {
          setIsListening(false);
        };
      }
    }
  };
  
  // Generate intelligent suggestions
  const generateSuggestions = (input: string, context: any): string[] => {
    const suggestions: string[] = [];
    const lowerInput = input.toLowerCase();
    
    // Context-aware suggestions
    if (context?.page === 'records') {
      if (lowerInput.includes('add') || lowerInput.includes('create')) {
        suggestions.push('How to add A record');
        suggestions.push('Create MX record for email');
        suggestions.push('Add CNAME record');
      }
      if (lowerInput.includes('delete') || lowerInput.includes('remove')) {
        suggestions.push('How to delete DNS records');
        suggestions.push('Remove all records for subdomain');
      }
    }
    
    // General intelligent suggestions
    if (lowerInput.includes('error') || lowerInput.includes('problem')) {
      suggestions.push(`Troubleshoot ${input}`);
      suggestions.push(`Common ${input} solutions`);
    }
    
    if (lowerInput.includes('how')) {
      suggestions.push(`${input} tutorial`);
      suggestions.push(`${input} step by step`);
    }
    
    // Add trending searches
    suggestions.push('DNS propagation time');
    suggestions.push('DNSSEC setup guide');
    suggestions.push('Configure email records');
    
    return suggestions.slice(0, 5);
  };
  
  // Calculate search confidence
  const calculateSearchConfidence = (results: HelpSearchResult[]): number => {
    if (results.length === 0) return 0;
    
    const avgRelevance = results.reduce((sum, r) => sum + r.relevanceScore, 0) / results.length;
    return Math.round(avgRelevance * 100);
  };
  
  // Filter results based on active filters
  const filteredResults = searchResults.filter(result => {
    if (!filters.types.has(result.type)) return false;
    
    // Additional filtering logic here
    
    return true;
  });
  
  // Group results by type
  const groupedResults = filteredResults.reduce((acc, result) => {
    if (!acc[result.type]) acc[result.type] = [];
    acc[result.type].push(result);
    return acc;
  }, {} as Record<string, HelpSearchResult[]>);
  
  // Handle result selection
  const handleResultClick = (result: HelpSearchResult) => {
    if (onResultSelect) {
      onResultSelect(result);
    } else if (result.url) {
      window.open(result.url, '_blank');
    }
  };
  
  // Handle bookmark toggle
  const handleBookmark = (resultId: string) => {
    setBookmarkedResults(prev => {
      const newSet = new Set(prev);
      if (newSet.has(resultId)) {
        newSet.delete(resultId);
      } else {
        newSet.add(resultId);
      }
      return newSet;
    });
  };
  
  // Copy result to clipboard
  const handleCopy = (content: string) => {
    navigator.clipboard.writeText(content);
  };
  
  // Get icon for result type
  const getResultIcon = (type: string) => {
    switch (type) {
      case 'faq':
        return <FAQIcon />;
      case 'documentation':
        return <DocsIcon />;
      case 'video':
        return <VideoIcon />;
      case 'user-content':
        return <CommunityIcon />;
      case 'tutorial':
        return <CodeIcon />;
      default:
        return <DocsIcon />;
    }
  };
  
  // Get color for result type
  const getResultColor = (type: string) => {
    switch (type) {
      case 'faq':
        return theme.palette.info.main;
      case 'documentation':
        return theme.palette.primary.main;
      case 'video':
        return theme.palette.error.main;
      case 'user-content':
        return theme.palette.success.main;
      case 'tutorial':
        return theme.palette.warning.main;
      default:
        return theme.palette.grey[500];
    }
  };
  
  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Search Header */}
      <Paper
        sx={{
          p: 2,
          mb: 2,
          background: embedded ? 'transparent' : `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)}, ${alpha(theme.palette.secondary.main, 0.05)})`,
        }}
      >
        {!embedded && (
          <Box display="flex" alignItems="center" gap={2} mb={2}>
            <AutoAwesomeIcon color="primary" />
            <Typography variant="h5">Natural Language Search</Typography>
            <Chip
              icon={<AIIcon />}
              label="AI-Powered"
              color="primary"
              size="small"
            />
          </Box>
        )}
        
        {/* Search Input */}
        <TextField
          ref={inputRef}
          fullWidth
          placeholder={placeholder}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyPress={(e) => {
            if (e.key === 'Enter') {
              handleSearch();
            }
          }}
          onFocus={() => setShowHistory(true)}
          onBlur={() => setTimeout(() => setShowHistory(false), 200)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
            endAdornment: (
              <InputAdornment position="end">
                {query && (
                  <IconButton size="small" onClick={() => setQuery('')}>
                    <ClearIcon />
                  </IconButton>
                )}
                <IconButton
                  size="small"
                  onClick={handleVoiceSearch}
                  color={isListening ? 'error' : 'default'}
                >
                  {isListening ? <MicOffIcon /> : <MicIcon />}
                </IconButton>
                <IconButton
                  size="small"
                  onClick={(e) => setFilterMenuAnchor(e.currentTarget)}
                >
                  <FilterIcon />
                </IconButton>
                <Button
                  variant="contained"
                  size="small"
                  onClick={() => handleSearch()}
                  disabled={!query.trim() || loading}
                  sx={{ ml: 1 }}
                >
                  Search
                </Button>
              </InputAdornment>
            ),
          }}
          sx={{
            '& .MuiOutlinedInput-root': {
              borderRadius: 3,
            },
          }}
        />
        
        {/* Search History Dropdown */}
        {showHistory && searchHistory.length > 0 && !query && (
          <Paper
            elevation={8}
            sx={{
              position: 'absolute',
              mt: 1,
              p: 1,
              zIndex: 1000,
              width: '100%',
              maxWidth: 600,
            }}
          >
            <List dense>
              <ListItem>
                <ListItemIcon>
                  <HistoryIcon />
                </ListItemIcon>
                <ListItemText primary="Recent Searches" />
              </ListItem>
              {searchHistory.map((item, index) => (
                <ListItem
                  key={index}
                  button
                  onClick={() => {
                    setQuery(item);
                    handleSearch(item);
                  }}
                >
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>
        )}
        
        {/* Suggestions */}
        {suggestions.length > 0 && (
          <Box mt={2}>
            <Typography variant="caption" color="text.secondary">
              Suggested searches:
            </Typography>
            <Box display="flex" gap={0.5} flexWrap="wrap" mt={1}>
              {suggestions.map((suggestion, index) => (
                <Chip
                  key={index}
                  label={suggestion}
                  size="small"
                  icon={<TipIcon />}
                  onClick={() => {
                    setQuery(suggestion);
                    handleSearch(suggestion);
                  }}
                  sx={{ cursor: 'pointer' }}
                />
              ))}
            </Box>
          </Box>
        )}
        
        {/* Search Metrics */}
        {searchMetrics.totalResults > 0 && (
          <Box display="flex" alignItems="center" gap={2} mt={2}>
            <Typography variant="body2" color="text.secondary">
              Found {searchMetrics.totalResults} results in {searchMetrics.searchTime}ms
            </Typography>
            <Chip
              label={`${searchMetrics.confidence}% confidence`}
              size="small"
              color={searchMetrics.confidence > 80 ? 'success' : searchMetrics.confidence > 50 ? 'warning' : 'default'}
            />
          </Box>
        )}
      </Paper>
      
      {/* Filter Menu */}
      <Menu
        anchorEl={filterMenuAnchor}
        open={Boolean(filterMenuAnchor)}
        onClose={() => setFilterMenuAnchor(null)}
      >
        <Box sx={{ p: 2, minWidth: 250 }}>
          <Typography variant="subtitle2" gutterBottom>
            Result Types
          </Typography>
          {['faq', 'documentation', 'video', 'user-content', 'tutorial'].map(type => (
            <FormControlLabel
              key={type}
              control={
                <Switch
                  checked={filters.types.has(type)}
                  onChange={(e) => {
                    const newTypes = new Set(filters.types);
                    if (e.target.checked) {
                      newTypes.add(type);
                    } else {
                      newTypes.delete(type);
                    }
                    setFilters({ ...filters, types: newTypes });
                  }}
                />
              }
              label={type.charAt(0).toUpperCase() + type.slice(1).replace('-', ' ')}
            />
          ))}
          
          <Divider sx={{ my: 2 }} />
          
          <FormControlLabel
            control={
              <Switch
                checked={filters.contextAware}
                onChange={(e) => setFilters({ ...filters, contextAware: e.target.checked })}
              />
            }
            label="Context-aware search"
          />
        </Box>
      </Menu>
      
      {/* Results Tabs */}
      {searchResults.length > 0 && (
        <Paper sx={{ mb: 2 }}>
          <Tabs
            value={activeTab}
            onChange={(e, value) => setActiveTab(value)}
            variant="scrollable"
            scrollButtons="auto"
          >
            <Tab label={`All (${filteredResults.length})`} />
            {Object.entries(groupedResults).map(([type, results]) => (
              <Tab
                key={type}
                label={
                  <Box display="flex" alignItems="center" gap={0.5}>
                    {getResultIcon(type)}
                    <span>{type.replace('-', ' ')} ({results.length})</span>
                  </Box>
                }
              />
            ))}
          </Tabs>
        </Paper>
      )}
      
      {/* Results */}
      <Box sx={{ flex: 1, overflow: 'auto' }}>
        {loading ? (
          <Box display="flex" justifyContent="center" p={4}>
            <CircularProgress />
          </Box>
        ) : filteredResults.length === 0 && query ? (
          <Alert severity="info">
            No results found for "{query}". Try rephrasing your question or using different keywords.
          </Alert>
        ) : (
          <Box>
            {activeTab === 0 ? (
              // All results
              filteredResults.map((result) => (
                <Card key={result.id} sx={{ mb: 2 }}>
                  <CardContent>
                    <Box display="flex" alignItems="flex-start" gap={2}>
                      <Avatar
                        sx={{
                          bgcolor: alpha(getResultColor(result.type), 0.1),
                          color: getResultColor(result.type),
                        }}
                      >
                        {getResultIcon(result.type)}
                      </Avatar>
                      
                      <Box flex={1}>
                        <Box display="flex" alignItems="center" gap={1} mb={1}>
                          <Typography variant="h6">
                            {result.title}
                          </Typography>
                          <Chip
                            label={result.type}
                            size="small"
                            sx={{
                              bgcolor: alpha(getResultColor(result.type), 0.1),
                              color: getResultColor(result.type),
                            }}
                          />
                          <Chip
                            label={`${Math.round(result.relevanceScore * 100)}% match`}
                            size="small"
                            variant="outlined"
                          />
                        </Box>
                        
                        <Typography variant="body2" color="text.secondary" paragraph>
                          {result.snippet}
                        </Typography>
                        
                        {result.highlights && result.highlights.length > 0 && (
                          <Box mb={2}>
                            {result.highlights.map((highlight, index) => (
                              <Typography
                                key={index}
                                variant="body2"
                                sx={{
                                  bgcolor: alpha(theme.palette.warning.main, 0.1),
                                  p: 0.5,
                                  borderRadius: 1,
                                  mb: 0.5,
                                }}
                              >
                                <ReactMarkdown>{highlight}</ReactMarkdown>
                              </Typography>
                            ))}
                          </Box>
                        )}
                      </Box>
                    </Box>
                  </CardContent>
                  
                  <CardActions>
                    <Button
                      size="small"
                      startIcon={<OpenIcon />}
                      onClick={() => handleResultClick(result)}
                    >
                      View
                    </Button>
                    <IconButton
                      size="small"
                      onClick={() => handleCopy(result.snippet)}
                    >
                      <CopyIcon />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={() => handleBookmark(result.id)}
                      color={bookmarkedResults.has(result.id) ? 'primary' : 'default'}
                    >
                      <BookmarkIcon />
                    </IconButton>
                  </CardActions>
                </Card>
              ))
            ) : (
              // Filtered by type
              Object.entries(groupedResults).map(([type, results], index) => {
                if (index + 1 !== activeTab) return null;
                
                return results.map((result) => (
                  <Card key={result.id} sx={{ mb: 2 }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom>
                        {result.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {result.snippet}
                      </Typography>
                    </CardContent>
                    <CardActions>
                      <Button
                        size="small"
                        onClick={() => handleResultClick(result)}
                      >
                        View
                      </Button>
                    </CardActions>
                  </Card>
                ));
              })
            )}
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default NaturalLanguageSearch;