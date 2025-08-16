import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  InputAdornment,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  AccordionActions,
  Chip,
  Button,
  IconButton,
  Rating,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Card,
  CardContent,
  CardActions,
  Tab,
  Tabs,
  Badge,
  Menu,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  LinearProgress,
  Skeleton,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Search as SearchIcon,
  ExpandMore as ExpandMoreIcon,
  ThumbUp as ThumbUpIcon,
  ThumbDown as ThumbDownIcon,
  TrendingUp as TrendingIcon,
  NewReleases as NewIcon,
  Star as StarIcon,
  Category as CategoryIcon,
  Sort as SortIcon,
  FilterList as FilterIcon,
  Lightbulb as SuggestIcon,
  AutoAwesome as AIIcon,
  Share as ShareIcon,
  Bookmark as BookmarkIcon,
  Edit as EditIcon,
  Add as AddIcon,
  QuestionAnswer as QAIcon,
  Psychology as PsychologyIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import {
  loadFAQs,
  markFAQHelpful,
  incrementFAQView,
  searchHelp,
} from '../../store/slices/helpSlice';
import { FAQItem } from './types';

interface SmartFAQProps {
  embedded?: boolean;
  maxHeight?: string | number;
  context?: any;
}

const SmartFAQ: React.FC<SmartFAQProps> = ({
  embedded = false,
  maxHeight = '100%',
  context,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch();
  
  const { faqs, loading, currentContext } = useSelector((state: RootState) => state.help);
  
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'relevance' | 'popular' | 'recent' | 'helpful'>('relevance');
  const [viewMode, setViewMode] = useState<'accordion' | 'cards'>('accordion');
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
  const [bookmarkedItems, setBookmarkedItems] = useState<Set<string>>(new Set());
  const [filterAnchor, setFilterAnchor] = useState<null | HTMLElement>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [userFeedback, setUserFeedback] = useState<Map<string, boolean>>(new Map());
  const [suggestedQuestions, setSuggestedQuestions] = useState<string[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  
  // Load FAQs on mount and context change
  useEffect(() => {
    dispatch(loadFAQs(context || currentContext));
  }, [dispatch, context, currentContext]);
  
  // Generate suggested questions based on search and context
  useEffect(() => {
    if (searchQuery.length > 2) {
      // Simulate AI-generated related questions
      const suggestions = [
        `How to configure ${searchQuery}?`,
        `Best practices for ${searchQuery}`,
        `Troubleshooting ${searchQuery} issues`,
        `${searchQuery} vs alternatives`,
      ];
      setSuggestedQuestions(suggestions);
    } else {
      setSuggestedQuestions([]);
    }
  }, [searchQuery]);
  
  // Get unique categories
  const categories = useMemo(() => {
    const cats = new Set<string>();
    faqs.forEach(faq => cats.add(faq.category));
    return Array.from(cats);
  }, [faqs]);
  
  // Filter and sort FAQs
  const filteredFAQs = useMemo(() => {
    let filtered = faqs;
    
    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(faq =>
        faq.question.toLowerCase().includes(query) ||
        faq.answer.toLowerCase().includes(query) ||
        faq.tags.some(tag => tag.toLowerCase().includes(query))
      );
    }
    
    // Filter by category
    if (selectedCategory !== 'all') {
      filtered = filtered.filter(faq => faq.category === selectedCategory);
    }
    
    // Sort
    switch (sortBy) {
      case 'popular':
        return [...filtered].sort((a, b) => b.viewCount - a.viewCount);
      case 'recent':
        return [...filtered].sort((a, b) => 
          new Date(b.lastUpdated).getTime() - new Date(a.lastUpdated).getTime()
        );
      case 'helpful':
        return [...filtered].sort((a, b) => {
          const aRatio = a.helpfulCount / (a.helpfulCount + a.notHelpfulCount || 1);
          const bRatio = b.helpfulCount / (b.helpfulCount + b.notHelpfulCount || 1);
          return bRatio - aRatio;
        });
      case 'relevance':
      default:
        // Use relevance scoring based on search query
        if (searchQuery) {
          return [...filtered].sort((a, b) => {
            const aScore = calculateRelevanceScore(a, searchQuery);
            const bScore = calculateRelevanceScore(b, searchQuery);
            return bScore - aScore;
          });
        }
        return filtered;
    }
  }, [faqs, searchQuery, selectedCategory, sortBy]);
  
  // Calculate relevance score for search
  const calculateRelevanceScore = (faq: FAQItem, query: string): number => {
    const lowerQuery = query.toLowerCase();
    let score = 0;
    
    // Title match (highest weight)
    if (faq.question.toLowerCase().includes(lowerQuery)) {
      score += 10;
    }
    
    // Answer match
    if (faq.answer.toLowerCase().includes(lowerQuery)) {
      score += 5;
    }
    
    // Tag match
    faq.tags.forEach(tag => {
      if (tag.toLowerCase().includes(lowerQuery)) {
        score += 3;
      }
    });
    
    // Popularity bonus
    score += Math.log(faq.viewCount + 1) * 0.5;
    
    // Helpfulness bonus
    const helpfulRatio = faq.helpfulCount / (faq.helpfulCount + faq.notHelpfulCount || 1);
    score += helpfulRatio * 2;
    
    return score;
  };
  
  // Handle FAQ expansion
  const handleExpand = (faqId: string) => {
    setExpandedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(faqId)) {
        newSet.delete(faqId);
      } else {
        newSet.add(faqId);
        dispatch(incrementFAQView(faqId));
      }
      return newSet;
    });
  };
  
  // Handle helpfulness feedback
  const handleFeedback = (faqId: string, helpful: boolean) => {
    dispatch(markFAQHelpful({ id: faqId, helpful }));
    setUserFeedback(prev => new Map(prev).set(faqId, helpful));
  };
  
  // Handle bookmark toggle
  const handleBookmark = (faqId: string) => {
    setBookmarkedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(faqId)) {
        newSet.delete(faqId);
      } else {
        newSet.add(faqId);
      }
      return newSet;
    });
  };
  
  // Handle AI search
  const handleAISearch = async () => {
    setIsSearching(true);
    try {
      await dispatch(searchHelp({ query: searchQuery, context })).unwrap();
    } finally {
      setIsSearching(false);
    }
  };
  
  // Get trending FAQs
  const trendingFAQs = useMemo(() => {
    return [...faqs]
      .sort((a, b) => b.viewCount - a.viewCount)
      .slice(0, 5);
  }, [faqs]);
  
  // Get recently updated FAQs
  const recentFAQs = useMemo(() => {
    return [...faqs]
      .sort((a, b) => 
        new Date(b.lastUpdated).getTime() - new Date(a.lastUpdated).getTime()
      )
      .slice(0, 5);
  }, [faqs]);
  
  // Render FAQ item as accordion
  const renderAccordionItem = (faq: FAQItem) => (
    <Accordion
      key={faq.id}
      expanded={expandedItems.has(faq.id)}
      onChange={() => handleExpand(faq.id)}
      sx={{ mb: 1 }}
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box display="flex" alignItems="center" gap={1} width="100%">
          <Box flex={1}>
            <Typography variant="subtitle1">{faq.question}</Typography>
            <Box display="flex" gap={0.5} mt={0.5}>
              <Chip label={faq.category} size="small" />
              {faq.viewCount > 100 && (
                <Chip
                  icon={<TrendingIcon />}
                  label="Popular"
                  size="small"
                  color="primary"
                />
              )}
              {new Date(faq.lastUpdated) > new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) && (
                <Chip
                  icon={<NewIcon />}
                  label="Updated"
                  size="small"
                  color="success"
                />
              )}
            </Box>
          </Box>
          <Box display="flex" alignItems="center" gap={1}>
            <Typography variant="caption" color="text.secondary">
              {faq.viewCount} views
            </Typography>
            {faq.helpfulCount > 0 && (
              <Chip
                label={`${Math.round((faq.helpfulCount / (faq.helpfulCount + faq.notHelpfulCount)) * 100)}%`}
                size="small"
                color="success"
                variant="outlined"
              />
            )}
          </Box>
        </Box>
      </AccordionSummary>
      
      <AccordionDetails>
        <Typography variant="body2" paragraph>
          {faq.answer}
        </Typography>
        
        {faq.relatedQuestions && faq.relatedQuestions.length > 0 && (
          <Box mt={2}>
            <Typography variant="subtitle2" gutterBottom>
              Related Questions:
            </Typography>
            <Box display="flex" gap={0.5} flexWrap="wrap">
              {faq.relatedQuestions.map((qId) => {
                const relatedFaq = faqs.find(f => f.id === qId);
                return relatedFaq ? (
                  <Chip
                    key={qId}
                    label={relatedFaq.question}
                    size="small"
                    variant="outlined"
                    onClick={() => handleExpand(qId)}
                  />
                ) : null;
              })}
            </Box>
          </Box>
        )}
        
        {faq.tags.length > 0 && (
          <Box display="flex" gap={0.5} mt={2}>
            {faq.tags.map(tag => (
              <Chip
                key={tag}
                label={tag}
                size="small"
                variant="outlined"
                onClick={() => setSearchQuery(tag)}
              />
            ))}
          </Box>
        )}
      </AccordionDetails>
      
      <AccordionActions>
        <Box display="flex" alignItems="center" justifyContent="space-between" width="100%">
          <Box display="flex" alignItems="center" gap={1}>
            <Typography variant="body2">Was this helpful?</Typography>
            <IconButton
              size="small"
              onClick={() => handleFeedback(faq.id, true)}
              color={userFeedback.get(faq.id) === true ? 'success' : 'default'}
            >
              <ThumbUpIcon fontSize="small" />
            </IconButton>
            <Typography variant="caption">{faq.helpfulCount}</Typography>
            <IconButton
              size="small"
              onClick={() => handleFeedback(faq.id, false)}
              color={userFeedback.get(faq.id) === false ? 'error' : 'default'}
            >
              <ThumbDownIcon fontSize="small" />
            </IconButton>
            <Typography variant="caption">{faq.notHelpfulCount}</Typography>
          </Box>
          
          <Box display="flex" gap={1}>
            {faq.videoUrl && (
              <Button size="small" href={faq.videoUrl} target="_blank">
                Watch Video
              </Button>
            )}
            {faq.docsUrl && (
              <Button size="small" href={faq.docsUrl} target="_blank">
                View Docs
              </Button>
            )}
            <IconButton
              size="small"
              onClick={() => handleBookmark(faq.id)}
              color={bookmarkedItems.has(faq.id) ? 'primary' : 'default'}
            >
              <BookmarkIcon fontSize="small" />
            </IconButton>
            <IconButton size="small">
              <ShareIcon fontSize="small" />
            </IconButton>
          </Box>
        </Box>
      </AccordionActions>
    </Accordion>
  );
  
  // Render FAQ item as card
  const renderCardItem = (faq: FAQItem) => (
    <Card key={faq.id} sx={{ mb: 2 }}>
      <CardContent>
        <Box display="flex" justifyContent="space-between" alignItems="flex-start" mb={1}>
          <Typography variant="h6">{faq.question}</Typography>
          <IconButton
            size="small"
            onClick={() => handleBookmark(faq.id)}
            color={bookmarkedItems.has(faq.id) ? 'primary' : 'default'}
          >
            <BookmarkIcon />
          </IconButton>
        </Box>
        
        <Typography variant="body2" color="text.secondary" paragraph>
          {expandedItems.has(faq.id) ? faq.answer : `${faq.answer.substring(0, 150)}...`}
        </Typography>
        
        <Box display="flex" gap={0.5} mb={2}>
          <Chip label={faq.category} size="small" />
          {faq.tags.slice(0, 3).map(tag => (
            <Chip key={tag} label={tag} size="small" variant="outlined" />
          ))}
        </Box>
        
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box display="flex" alignItems="center" gap={2}>
            <Typography variant="caption" color="text.secondary">
              {faq.viewCount} views
            </Typography>
            <Box display="flex" alignItems="center">
              <ThumbUpIcon fontSize="small" color="success" />
              <Typography variant="caption" sx={{ ml: 0.5 }}>
                {Math.round((faq.helpfulCount / (faq.helpfulCount + faq.notHelpfulCount || 1)) * 100)}%
              </Typography>
            </Box>
          </Box>
          
          <Button
            size="small"
            onClick={() => handleExpand(faq.id)}
          >
            {expandedItems.has(faq.id) ? 'Show Less' : 'Read More'}
          </Button>
        </Box>
      </CardContent>
      
      {expandedItems.has(faq.id) && (
        <CardActions>
          <Button
            size="small"
            startIcon={<ThumbUpIcon />}
            onClick={() => handleFeedback(faq.id, true)}
          >
            Helpful
          </Button>
          <Button
            size="small"
            startIcon={<ThumbDownIcon />}
            onClick={() => handleFeedback(faq.id, false)}
          >
            Not Helpful
          </Button>
          {faq.videoUrl && (
            <Button size="small" href={faq.videoUrl} target="_blank">
              Video
            </Button>
          )}
          {faq.docsUrl && (
            <Button size="small" href={faq.docsUrl} target="_blank">
              Docs
            </Button>
          )}
        </CardActions>
      )}
    </Card>
  );
  
  return (
    <Box
      sx={{
        height: maxHeight,
        display: 'flex',
        flexDirection: 'column',
        bgcolor: embedded ? 'transparent' : 'background.default',
      }}
    >
      {/* Header */}
      {!embedded && (
        <Paper sx={{ p: 2, mb: 2 }}>
          <Box display="flex" alignItems="center" gap={2} mb={2}>
            <QAIcon color="primary" />
            <Typography variant="h5">Smart FAQ</Typography>
            <Chip
              icon={<PsychologyIcon />}
              label="AI-Powered"
              color="primary"
              variant="outlined"
            />
          </Box>
          
          <Typography variant="body2" color="text.secondary">
            Find answers quickly with our intelligent FAQ system that learns from user interactions
          </Typography>
        </Paper>
      )}
      
      {/* Search and Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box display="flex" gap={2} alignItems="center" mb={2}>
          <TextField
            fullWidth
            placeholder="Search FAQs or ask a question..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
              endAdornment: isSearching && (
                <InputAdornment position="end">
                  <CircularProgress size={20} />
                </InputAdornment>
              ),
            }}
          />
          <Button
            variant="contained"
            startIcon={<AIIcon />}
            onClick={handleAISearch}
            disabled={!searchQuery || isSearching}
          >
            AI Search
          </Button>
        </Box>
        
        {/* Suggested questions */}
        {suggestedQuestions.length > 0 && (
          <Box mb={2}>
            <Typography variant="caption" color="text.secondary" gutterBottom>
              Suggested questions:
            </Typography>
            <Box display="flex" gap={0.5} flexWrap="wrap" mt={1}>
              {suggestedQuestions.map((question, index) => (
                <Chip
                  key={index}
                  label={question}
                  size="small"
                  icon={<SuggestIcon />}
                  onClick={() => setSearchQuery(question)}
                  sx={{ cursor: 'pointer' }}
                />
              ))}
            </Box>
          </Box>
        )}
        
        {/* Filters and View Options */}
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box display="flex" gap={2}>
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Category</InputLabel>
              <Select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                label="Category"
              >
                <MenuItem value="all">All Categories</MenuItem>
                {categories.map(cat => (
                  <MenuItem key={cat} value={cat}>{cat}</MenuItem>
                ))}
              </Select>
            </FormControl>
            
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Sort By</InputLabel>
              <Select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                label="Sort By"
              >
                <MenuItem value="relevance">Relevance</MenuItem>
                <MenuItem value="popular">Most Popular</MenuItem>
                <MenuItem value="recent">Recently Updated</MenuItem>
                <MenuItem value="helpful">Most Helpful</MenuItem>
              </Select>
            </FormControl>
          </Box>
          
          <ToggleButtonGroup
            value={viewMode}
            exclusive
            onChange={(e, value) => value && setViewMode(value)}
            size="small"
          >
            <ToggleButton value="accordion">
              <Tooltip title="Accordion View">
                <ExpandMoreIcon />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="cards">
              <Tooltip title="Card View">
                <CategoryIcon />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>
      </Paper>
      
      {/* Tabs for different sections */}
      <Paper sx={{ mb: 2 }}>
        <Tabs
          value={activeTab}
          onChange={(e, value) => setActiveTab(value)}
          variant="fullWidth"
        >
          <Tab
            label="All FAQs"
            icon={<Badge badgeContent={filteredFAQs.length} color="primary">
              <QAIcon />
            </Badge>}
            iconPosition="start"
          />
          <Tab
            label="Trending"
            icon={<TrendingIcon />}
            iconPosition="start"
          />
          <Tab
            label="Recent"
            icon={<NewIcon />}
            iconPosition="start"
          />
          <Tab
            label="Bookmarked"
            icon={<Badge badgeContent={bookmarkedItems.size} color="primary">
              <BookmarkIcon />
            </Badge>}
            iconPosition="start"
          />
        </Tabs>
      </Paper>
      
      {/* Content */}
      <Box sx={{ flex: 1, overflow: 'auto' }}>
        {loading ? (
          <>
            <Skeleton variant="rectangular" height={100} sx={{ mb: 1 }} />
            <Skeleton variant="rectangular" height={100} sx={{ mb: 1 }} />
            <Skeleton variant="rectangular" height={100} />
          </>
        ) : (
          <>
            {/* All FAQs Tab */}
            {activeTab === 0 && (
              <>
                {filteredFAQs.length === 0 ? (
                  <Alert severity="info">
                    No FAQs found matching your criteria. Try adjusting your search or filters.
                  </Alert>
                ) : (
                  <>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Found {filteredFAQs.length} FAQs
                    </Typography>
                    {viewMode === 'accordion' 
                      ? filteredFAQs.map(renderAccordionItem)
                      : filteredFAQs.map(renderCardItem)
                    }
                  </>
                )}
              </>
            )}
            
            {/* Trending Tab */}
            {activeTab === 1 && (
              <>
                <Typography variant="h6" gutterBottom>
                  Trending Questions
                </Typography>
                {trendingFAQs.map(renderAccordionItem)}
              </>
            )}
            
            {/* Recent Tab */}
            {activeTab === 2 && (
              <>
                <Typography variant="h6" gutterBottom>
                  Recently Updated
                </Typography>
                {recentFAQs.map(renderAccordionItem)}
              </>
            )}
            
            {/* Bookmarked Tab */}
            {activeTab === 3 && (
              <>
                {bookmarkedItems.size === 0 ? (
                  <Alert severity="info">
                    You haven't bookmarked any FAQs yet. Click the bookmark icon on FAQs you want to save.
                  </Alert>
                ) : (
                  faqs
                    .filter(faq => bookmarkedItems.has(faq.id))
                    .map(renderAccordionItem)
                )}
              </>
            )}
          </>
        )}
      </Box>
      
      {/* Add Question FAB */}
      {!embedded && (
        <Tooltip title="Submit a new question">
          <IconButton
            sx={{
              position: 'fixed',
              bottom: 24,
              right: 24,
              bgcolor: theme.palette.primary.main,
              color: 'white',
              '&:hover': {
                bgcolor: theme.palette.primary.dark,
              },
            }}
          >
            <AddIcon />
          </IconButton>
        </Tooltip>
      )}
    </Box>
  );
};

export default SmartFAQ;