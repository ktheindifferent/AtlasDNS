import React, { useEffect, useState } from 'react';
import {
  Drawer,
  Box,
  Typography,
  IconButton,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Button,
  Card,
  CardContent,
  CardActions,
  TextField,
  InputAdornment,
  Alert,
  Skeleton,
  useTheme,
  alpha,
  Divider,
  Paper,
  Rating,
  LinearProgress,
} from '@mui/material';
import {
  Close as CloseIcon,
  ExpandMore as ExpandMoreIcon,
  Search as SearchIcon,
  Lightbulb as TipIcon,
  PlayCircle as VideoIcon,
  QuestionAnswer as FAQIcon,
  Article as DocsIcon,
  Build as WizardIcon,
  TipsAndUpdates as SuggestionIcon,
  History as HistoryIcon,
  School as TutorialIcon,
  AutoAwesome as AIIcon,
  Bookmark as BookmarkIcon,
  Share as ShareIcon,
  Print as PrintIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import {
  toggleHelpPanel,
  loadContextualHelp,
  incrementFAQView,
  markFAQHelpful,
} from '../../store/slices/helpSlice';
import { FAQItem, VideoSnippet, TroubleshootingWizard, HelpSuggestion } from './types';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index, ...other }) => {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`help-tabpanel-${index}`}
      aria-labelledby={`help-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 2 }}>{children}</Box>}
    </div>
  );
};

const ContextHelpPanel: React.FC = () => {
  const theme = useTheme();
  const dispatch = useDispatch();
  
  const {
    helpPanelOpen,
    currentContext,
    faqs,
    videos,
    suggestions,
    troubleshootingWizards,
    loading,
  } = useSelector((state: RootState) => state.help);
  
  const [activeTab, setActiveTab] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedFAQ, setExpandedFAQ] = useState<string | false>(false);
  const [bookmarkedItems, setBookmarkedItems] = useState<Set<string>>(new Set());
  
  // Load contextual help when panel opens or context changes
  useEffect(() => {
    if (helpPanelOpen) {
      dispatch(loadContextualHelp(currentContext));
    }
  }, [helpPanelOpen, currentContext, dispatch]);
  
  // Filter content based on search
  const filteredFAQs = faqs.filter(faq =>
    faq.question.toLowerCase().includes(searchQuery.toLowerCase()) ||
    faq.answer.toLowerCase().includes(searchQuery.toLowerCase())
  );
  
  const filteredVideos = videos.filter(video =>
    video.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    video.description.toLowerCase().includes(searchQuery.toLowerCase())
  );
  
  const handleFAQClick = (faq: FAQItem) => {
    dispatch(incrementFAQView(faq.id));
    setExpandedFAQ(expandedFAQ === faq.id ? false : faq.id);
  };
  
  const handleFAQFeedback = (faqId: string, helpful: boolean) => {
    dispatch(markFAQHelpful({ id: faqId, helpful }));
  };
  
  const handleBookmark = (itemId: string) => {
    setBookmarkedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(itemId)) {
        newSet.delete(itemId);
      } else {
        newSet.add(itemId);
      }
      return newSet;
    });
  };
  
  const renderSuggestions = () => (
    <Box>
      {suggestions.length === 0 ? (
        <Alert severity="info">
          No suggestions available for this context. Try performing an action to get contextual help.
        </Alert>
      ) : (
        suggestions.map((suggestion: HelpSuggestion) => (
          <Card key={suggestion.id} sx={{ mb: 2 }}>
            <CardContent>
              <Box display="flex" alignItems="flex-start" justifyContent="space-between">
                <Box flex={1}>
                  <Box display="flex" alignItems="center" gap={1} mb={1}>
                    <SuggestionIcon color={
                      suggestion.type === 'warning' ? 'warning' :
                      suggestion.type === 'tip' ? 'success' :
                      'info'
                    } />
                    <Typography variant="subtitle1" fontWeight="bold">
                      {suggestion.title}
                    </Typography>
                    <Chip
                      label={suggestion.type}
                      size="small"
                      color={
                        suggestion.type === 'warning' ? 'warning' :
                        suggestion.type === 'tip' ? 'success' :
                        'info'
                      }
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {suggestion.description}
                  </Typography>
                </Box>
                <IconButton
                  size="small"
                  onClick={() => handleBookmark(suggestion.id)}
                >
                  <BookmarkIcon color={bookmarkedItems.has(suggestion.id) ? 'primary' : 'action'} />
                </IconButton>
              </Box>
            </CardContent>
            {suggestion.action && (
              <CardActions>
                <Button
                  size="small"
                  variant="contained"
                  onClick={suggestion.action.handler}
                >
                  {suggestion.action.label}
                </Button>
              </CardActions>
            )}
          </Card>
        ))
      )}
    </Box>
  );
  
  const renderFAQs = () => (
    <Box>
      {loading ? (
        <>
          <Skeleton variant="rectangular" height={60} sx={{ mb: 1 }} />
          <Skeleton variant="rectangular" height={60} sx={{ mb: 1 }} />
          <Skeleton variant="rectangular" height={60} />
        </>
      ) : filteredFAQs.length === 0 ? (
        <Alert severity="info">
          No FAQs found. Try adjusting your search or browse other help sections.
        </Alert>
      ) : (
        filteredFAQs.map((faq) => (
          <Accordion
            key={faq.id}
            expanded={expandedFAQ === faq.id}
            onChange={() => handleFAQClick(faq)}
            sx={{ mb: 1 }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box display="flex" alignItems="center" gap={1} width="100%">
                <FAQIcon color="primary" />
                <Typography flex={1}>{faq.question}</Typography>
                <Box display="flex" gap={0.5}>
                  <Chip
                    label={`${faq.viewCount} views`}
                    size="small"
                    variant="outlined"
                  />
                  {faq.helpfulCount > 0 && (
                    <Chip
                      label={`${Math.round((faq.helpfulCount / (faq.helpfulCount + faq.notHelpfulCount)) * 100)}% helpful`}
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
              
              {faq.tags.length > 0 && (
                <Box display="flex" gap={0.5} mb={2}>
                  {faq.tags.map(tag => (
                    <Chip key={tag} label={tag} size="small" />
                  ))}
                </Box>
              )}
              
              <Divider sx={{ my: 2 }} />
              
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box display="flex" alignItems="center" gap={1}>
                  <Typography variant="body2">Was this helpful?</Typography>
                  <Button
                    size="small"
                    onClick={() => handleFAQFeedback(faq.id, true)}
                  >
                    Yes
                  </Button>
                  <Button
                    size="small"
                    onClick={() => handleFAQFeedback(faq.id, false)}
                  >
                    No
                  </Button>
                </Box>
                
                <Box display="flex" gap={1}>
                  {faq.videoUrl && (
                    <Button
                      size="small"
                      startIcon={<VideoIcon />}
                      href={faq.videoUrl}
                      target="_blank"
                    >
                      Watch Video
                    </Button>
                  )}
                  {faq.docsUrl && (
                    <Button
                      size="small"
                      startIcon={<DocsIcon />}
                      href={faq.docsUrl}
                      target="_blank"
                    >
                      View Docs
                    </Button>
                  )}
                </Box>
              </Box>
            </AccordionDetails>
          </Accordion>
        ))
      )}
    </Box>
  );
  
  const renderVideos = () => (
    <Box>
      {filteredVideos.length === 0 ? (
        <Alert severity="info">
          No video tutorials available for this context.
        </Alert>
      ) : (
        <Box display="grid" gap={2}>
          {filteredVideos.map((video) => (
            <Card key={video.id}>
              <CardContent>
                <Box display="flex" alignItems="flex-start" gap={2}>
                  <VideoIcon sx={{ fontSize: 40, color: theme.palette.primary.main }} />
                  <Box flex={1}>
                    <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                      {video.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      {video.description}
                    </Typography>
                    <Box display="flex" alignItems="center" gap={1}>
                      <Chip
                        label={`${Math.floor(video.duration / 60)} min`}
                        size="small"
                        icon={<VideoIcon />}
                      />
                      {video.tags.map(tag => (
                        <Chip key={tag} label={tag} size="small" variant="outlined" />
                      ))}
                    </Box>
                    
                    {video.timestamps && video.timestamps.length > 0 && (
                      <Box mt={2}>
                        <Typography variant="caption" color="text.secondary">
                          Chapters:
                        </Typography>
                        <List dense>
                          {video.timestamps.map((timestamp, index) => (
                            <ListItem key={index} disablePadding>
                              <ListItemText
                                primary={
                                  <Typography variant="caption">
                                    {Math.floor(timestamp.time / 60)}:{(timestamp.time % 60).toString().padStart(2, '0')} - {timestamp.label}
                                  </Typography>
                                }
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                  </Box>
                </Box>
              </CardContent>
              <CardActions>
                <Button
                  variant="contained"
                  startIcon={<VideoIcon />}
                  href={video.url}
                  target="_blank"
                  fullWidth
                >
                  Watch Video
                </Button>
              </CardActions>
            </Card>
          ))}
        </Box>
      )}
    </Box>
  );
  
  const renderWizards = () => (
    <Box>
      {troubleshootingWizards.length === 0 ? (
        <Alert severity="info">
          No troubleshooting wizards available for this context.
        </Alert>
      ) : (
        troubleshootingWizards.map((wizard) => (
          <Card key={wizard.id} sx={{ mb: 2 }}>
            <CardContent>
              <Box display="flex" alignItems="center" gap={1} mb={1}>
                <WizardIcon color="primary" />
                <Typography variant="h6">{wizard.title}</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary" paragraph>
                {wizard.description}
              </Typography>
              
              <Box display="flex" gap={1} mb={2}>
                <Chip
                  label={`${wizard.steps.length} steps`}
                  size="small"
                  variant="outlined"
                />
                <Chip
                  label={`~${wizard.estimatedTime} min`}
                  size="small"
                  variant="outlined"
                />
                <Chip
                  label={wizard.category}
                  size="small"
                  color="primary"
                  variant="outlined"
                />
              </Box>
              
              {wizard.commonIssues.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    Common Issues Covered:
                  </Typography>
                  <List dense>
                    {wizard.commonIssues.map((issue, index) => (
                      <ListItem key={index} disablePadding>
                        <ListItemIcon>
                          <Chip label={index + 1} size="small" />
                        </ListItemIcon>
                        <ListItemText primary={issue} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}
            </CardContent>
            <CardActions>
              <Button
                variant="contained"
                startIcon={<WizardIcon />}
                fullWidth
              >
                Start Troubleshooting
              </Button>
            </CardActions>
          </Card>
        ))
      )}
    </Box>
  );
  
  return (
    <Drawer
      anchor="right"
      open={helpPanelOpen}
      onClose={() => dispatch(toggleHelpPanel())}
      sx={{
        '& .MuiDrawer-paper': {
          width: { xs: '100%', sm: 400 },
          maxWidth: '100%',
        },
      }}
    >
      <Box
        sx={{
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        {/* Header */}
        <Box
          sx={{
            p: 2,
            borderBottom: 1,
            borderColor: 'divider',
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)}, ${alpha(theme.palette.secondary.main, 0.1)})`,
          }}
        >
          <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <AIIcon color="primary" />
              <Typography variant="h6">Context Help</Typography>
            </Box>
            <Box>
              <IconButton size="small">
                <PrintIcon />
              </IconButton>
              <IconButton size="small">
                <ShareIcon />
              </IconButton>
              <IconButton
                size="small"
                onClick={() => dispatch(toggleHelpPanel())}
              >
                <CloseIcon />
              </IconButton>
            </Box>
          </Box>
          
          <Paper elevation={0} sx={{ bgcolor: 'background.paper', p: 1 }}>
            <Typography variant="body2">
              <strong>Current Context:</strong> {currentContext.page}
              {currentContext.component && ` > ${currentContext.component}`}
              {currentContext.action && ` > ${currentContext.action}`}
            </Typography>
          </Paper>
          
          <TextField
            fullWidth
            size="small"
            placeholder="Search help content..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{ mt: 2 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
            }}
          />
        </Box>
        
        {/* Tabs */}
        <Tabs
          value={activeTab}
          onChange={(e, newValue) => setActiveTab(newValue)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab label="Suggestions" icon={<TipIcon />} iconPosition="start" />
          <Tab label="FAQs" icon={<FAQIcon />} iconPosition="start" />
          <Tab label="Videos" icon={<VideoIcon />} iconPosition="start" />
          <Tab label="Wizards" icon={<WizardIcon />} iconPosition="start" />
        </Tabs>
        
        {/* Content */}
        <Box sx={{ flex: 1, overflow: 'auto' }}>
          <TabPanel value={activeTab} index={0}>
            {renderSuggestions()}
          </TabPanel>
          <TabPanel value={activeTab} index={1}>
            {renderFAQs()}
          </TabPanel>
          <TabPanel value={activeTab} index={2}>
            {renderVideos()}
          </TabPanel>
          <TabPanel value={activeTab} index={3}>
            {renderWizards()}
          </TabPanel>
        </Box>
        
        {/* Footer */}
        <Box
          sx={{
            p: 2,
            borderTop: 1,
            borderColor: 'divider',
            bgcolor: 'background.paper',
          }}
        >
          <Button
            fullWidth
            variant="outlined"
            startIcon={<AIIcon />}
            onClick={() => dispatch(toggleHelpPanel())}
          >
            Open AI Assistant
          </Button>
        </Box>
      </Box>
    </Drawer>
  );
};

export default ContextHelpPanel;