import React, { useEffect, useState, useRef } from 'react';
import {
  Snackbar,
  Alert,
  AlertTitle,
  Box,
  Typography,
  Button,
  IconButton,
  Slide,
  Fade,
  Paper,
  Chip,
  LinearProgress,
  Avatar,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Collapse,
  useTheme,
  alpha,
} from '@mui/material';
import {
  AutoAwesome as AutoAwesomeIcon,
  Close as CloseIcon,
  Lightbulb as TipIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  School as LearnIcon,
  PlayCircle as VideoIcon,
  QuestionAnswer as QuestionIcon,
  ThumbUp as ThumbUpIcon,
  ThumbDown as ThumbDownIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  Check as CheckIcon,
  Psychology as AIIcon,
  TipsAndUpdates as SuggestionIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import {
  addSuggestion,
  dismissSuggestion,
  setActiveSuggestion,
  trackUserBehavior,
  recordInteraction,
  toggleChat,
  toggleHelpPanel,
} from '../../store/slices/helpSlice';
import { HelpSuggestion, HelpContext } from './types';

interface ProactiveHelpEngineProps {
  enabled?: boolean;
}

interface BehaviorPattern {
  type: 'confusion' | 'frustration' | 'exploration' | 'success' | 'idle';
  confidence: number;
  indicators: string[];
}

const ProactiveHelpEngine: React.FC<ProactiveHelpEngineProps> = ({
  enabled = true,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch();
  const behaviorAnalysisRef = useRef<NodeJS.Timeout>();
  const idleTimerRef = useRef<NodeJS.Timeout>();
  const mouseTrailRef = useRef<Array<{ x: number; y: number; time: number }>>([]);
  
  const {
    currentContext,
    suggestions,
    activeSuggestion,
    proactiveHelpEnabled,
    userBehaviorTracking,
    sessionId,
  } = useSelector((state: RootState) => state.help);
  
  const [currentPattern, setCurrentPattern] = useState<BehaviorPattern | null>(null);
  const [showSuggestion, setShowSuggestion] = useState(false);
  const [suggestionExpanded, setSuggestionExpanded] = useState(false);
  const [suggestionFeedback, setSuggestionFeedback] = useState<'helpful' | 'not-helpful' | null>(null);
  const [dismissedSuggestions, setDismissedSuggestions] = useState<Set<string>>(new Set());
  const [lastSuggestionTime, setLastSuggestionTime] = useState(0);
  const [userEngagement, setUserEngagement] = useState({
    timeOnPage: 0,
    interactions: 0,
    scrollDepth: 0,
  });
  
  // Minimum time between suggestions (in ms)
  const SUGGESTION_COOLDOWN = 30000; // 30 seconds
  
  // Monitor user behavior
  useEffect(() => {
    if (!enabled || !proactiveHelpEnabled) return;
    
    // Track mouse movements
    const handleMouseMove = (e: MouseEvent) => {
      const now = Date.now();
      mouseTrailRef.current.push({ x: e.clientX, y: e.clientY, time: now });
      
      // Keep only last 50 movements
      if (mouseTrailRef.current.length > 50) {
        mouseTrailRef.current.shift();
      }
      
      dispatch(trackUserBehavior({
        type: 'mouse',
        data: { x: e.clientX, y: e.clientY },
      }));
      
      // Reset idle timer
      if (idleTimerRef.current) {
        clearTimeout(idleTimerRef.current);
      }
      idleTimerRef.current = setTimeout(() => {
        detectIdleUser();
      }, 10000); // 10 seconds of inactivity
    };
    
    // Track clicks
    const handleClick = (e: MouseEvent) => {
      const element = (e.target as HTMLElement).tagName;
      dispatch(trackUserBehavior({
        type: 'click',
        data: { element },
      }));
      
      setUserEngagement(prev => ({
        ...prev,
        interactions: prev.interactions + 1,
      }));
    };
    
    // Track scroll
    const handleScroll = () => {
      const scrollPercentage = (window.scrollY / 
        (document.documentElement.scrollHeight - window.innerHeight)) * 100;
      
      setUserEngagement(prev => ({
        ...prev,
        scrollDepth: Math.max(prev.scrollDepth, scrollPercentage),
      }));
    };
    
    // Add event listeners
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('click', handleClick);
    window.addEventListener('scroll', handleScroll);
    
    // Start behavior analysis
    behaviorAnalysisRef.current = setInterval(() => {
      analyzeBehavior();
    }, 5000); // Analyze every 5 seconds
    
    // Track time on page
    const startTime = Date.now();
    const timeTracker = setInterval(() => {
      setUserEngagement(prev => ({
        ...prev,
        timeOnPage: Date.now() - startTime,
      }));
    }, 1000);
    
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('click', handleClick);
      window.removeEventListener('scroll', handleScroll);
      
      if (behaviorAnalysisRef.current) {
        clearInterval(behaviorAnalysisRef.current);
      }
      if (idleTimerRef.current) {
        clearTimeout(idleTimerRef.current);
      }
      clearInterval(timeTracker);
    };
  }, [enabled, proactiveHelpEnabled, currentContext]);
  
  // Analyze user behavior patterns
  const analyzeBehavior = () => {
    const patterns: BehaviorPattern[] = [];
    
    // Check for confusion (rapid mouse movements, back-and-forth)
    if (detectConfusion()) {
      patterns.push({
        type: 'confusion',
        confidence: 0.7,
        indicators: ['Rapid mouse movements', 'Hovering over elements'],
      });
    }
    
    // Check for frustration (repeated clicks, rage clicks)
    if (detectFrustration()) {
      patterns.push({
        type: 'frustration',
        confidence: 0.8,
        indicators: ['Multiple rapid clicks', 'Repeated actions'],
      });
    }
    
    // Check for exploration (systematic navigation)
    if (detectExploration()) {
      patterns.push({
        type: 'exploration',
        confidence: 0.6,
        indicators: ['Systematic navigation', 'Exploring features'],
      });
    }
    
    // Select highest confidence pattern
    const topPattern = patterns.sort((a, b) => b.confidence - a.confidence)[0];
    
    if (topPattern && topPattern.confidence > 0.5) {
      setCurrentPattern(topPattern);
      generateContextualSuggestion(topPattern);
    }
  };
  
  // Detect confusion pattern
  const detectConfusion = (): boolean => {
    if (mouseTrailRef.current.length < 10) return false;
    
    // Calculate mouse velocity and direction changes
    let directionChanges = 0;
    let totalVelocity = 0;
    
    for (let i = 1; i < mouseTrailRef.current.length; i++) {
      const prev = mouseTrailRef.current[i - 1];
      const curr = mouseTrailRef.current[i];
      
      const dx = curr.x - prev.x;
      const dy = curr.y - prev.y;
      const dt = curr.time - prev.time;
      
      const velocity = Math.sqrt(dx * dx + dy * dy) / dt;
      totalVelocity += velocity;
      
      if (i > 1) {
        const prevPrev = mouseTrailRef.current[i - 2];
        const prevDx = prev.x - prevPrev.x;
        const prevDy = prev.y - prevPrev.y;
        
        // Check for direction change
        if ((dx * prevDx < 0) || (dy * prevDy < 0)) {
          directionChanges++;
        }
      }
    }
    
    const avgVelocity = totalVelocity / mouseTrailRef.current.length;
    
    // High velocity with many direction changes indicates confusion
    return avgVelocity > 2 && directionChanges > 5;
  };
  
  // Detect frustration pattern
  const detectFrustration = (): boolean => {
    const recentClicks = userBehaviorTracking.clicks.filter(
      click => Date.now() - click.timestamp < 3000
    );
    
    // Rage clicking detection
    if (recentClicks.length > 5) {
      dispatch(trackUserBehavior({
        type: 'frustration',
        data: { type: 'rage-click' },
      }));
      return true;
    }
    
    // Check for repeated failed actions
    const frustrationEvents = userBehaviorTracking.frustrationEvents.filter(
      event => Date.now() - event.timestamp < 10000
    );
    
    return frustrationEvents.length > 2;
  };
  
  // Detect exploration pattern
  const detectExploration = (): boolean => {
    // User is systematically exploring features
    return userEngagement.interactions > 10 && 
           userEngagement.scrollDepth > 50 &&
           userEngagement.timeOnPage > 30000;
  };
  
  // Detect idle user
  const detectIdleUser = () => {
    if (userEngagement.timeOnPage > 60000 && userEngagement.interactions < 3) {
      generateIdleSuggestion();
    }
  };
  
  // Generate contextual suggestion based on behavior
  const generateContextualSuggestion = (pattern: BehaviorPattern) => {
    // Don't show suggestions too frequently
    if (Date.now() - lastSuggestionTime < SUGGESTION_COOLDOWN) return;
    
    let suggestion: HelpSuggestion | null = null;
    
    switch (pattern.type) {
      case 'confusion':
        suggestion = generateConfusionSuggestion();
        break;
      case 'frustration':
        suggestion = generateFrustrationSuggestion();
        break;
      case 'exploration':
        suggestion = generateExplorationSuggestion();
        break;
    }
    
    if (suggestion && !dismissedSuggestions.has(suggestion.id)) {
      dispatch(addSuggestion(suggestion));
      dispatch(setActiveSuggestion(suggestion));
      setShowSuggestion(true);
      setLastSuggestionTime(Date.now());
      
      // Record interaction
      dispatch(recordInteraction({
        type: 'suggestion',
        context: currentContext,
        query: `Proactive: ${pattern.type}`,
        sessionId,
      }));
    }
  };
  
  // Generate suggestion for confused user
  const generateConfusionSuggestion = (): HelpSuggestion => {
    const contextMessages = {
      records: 'Need help managing DNS records?',
      zones: 'Looking for zone configuration options?',
      dnssec: 'DNSSEC can be complex. Need guidance?',
      analytics: 'Want to understand your analytics better?',
    };
    
    const message = contextMessages[currentContext.page as keyof typeof contextMessages] || 
                   'Looks like you might need some help';
    
    return {
      id: `confusion-${Date.now()}`,
      title: message,
      description: 'I noticed you might be looking for something. Would you like me to help?',
      type: 'info',
      priority: 2,
      context: currentContext,
      action: {
        label: 'Get Help',
        handler: () => dispatch(toggleChat()),
      },
      dismissible: true,
      shown: false,
    };
  };
  
  // Generate suggestion for frustrated user
  const generateFrustrationSuggestion = (): HelpSuggestion => {
    return {
      id: `frustration-${Date.now()}`,
      title: 'Having trouble?',
      description: 'It looks like something isn\'t working as expected. Let me help you troubleshoot.',
      type: 'warning',
      priority: 1,
      context: currentContext,
      action: {
        label: 'Start Troubleshooting',
        handler: () => {
          // Open troubleshooting wizard
          console.log('Opening troubleshooting wizard');
        },
      },
      dismissible: true,
      shown: false,
    };
  };
  
  // Generate suggestion for exploring user
  const generateExplorationSuggestion = (): HelpSuggestion => {
    const tips = {
      records: 'Did you know you can bulk import DNS records?',
      zones: 'Pro tip: Use zone templates for faster setup',
      dnssec: 'Learn about DNSSEC key rotation best practices',
      analytics: 'Export your analytics data for deeper analysis',
    };
    
    const tip = tips[currentContext.page as keyof typeof tips] || 
                'Discover advanced features';
    
    return {
      id: `exploration-${Date.now()}`,
      title: tip,
      description: 'Since you\'re exploring, here\'s something you might find useful.',
      type: 'tip',
      priority: 3,
      context: currentContext,
      action: {
        label: 'Learn More',
        handler: () => dispatch(toggleHelpPanel()),
      },
      dismissible: true,
      shown: false,
    };
  };
  
  // Generate suggestion for idle user
  const generateIdleSuggestion = () => {
    const suggestion: HelpSuggestion = {
      id: `idle-${Date.now()}`,
      title: 'Need assistance?',
      description: 'You\'ve been on this page for a while. Would you like help or a tutorial?',
      type: 'info',
      priority: 3,
      context: currentContext,
      action: {
        label: 'Watch Tutorial',
        handler: () => {
          // Open video tutorial
          console.log('Opening tutorial');
        },
      },
      dismissible: true,
      shown: false,
    };
    
    if (!dismissedSuggestions.has(suggestion.id)) {
      dispatch(addSuggestion(suggestion));
      dispatch(setActiveSuggestion(suggestion));
      setShowSuggestion(true);
      setLastSuggestionTime(Date.now());
    }
  };
  
  // Handle suggestion dismissal
  const handleDismiss = () => {
    if (activeSuggestion) {
      dispatch(dismissSuggestion(activeSuggestion.id));
      setDismissedSuggestions(prev => new Set(prev).add(activeSuggestion.id));
    }
    setShowSuggestion(false);
    setSuggestionExpanded(false);
    setSuggestionFeedback(null);
  };
  
  // Handle suggestion feedback
  const handleFeedback = (helpful: boolean) => {
    setSuggestionFeedback(helpful ? 'helpful' : 'not-helpful');
    
    // Record feedback
    dispatch(recordInteraction({
      type: 'suggestion',
      context: currentContext,
      query: `Feedback: ${helpful ? 'helpful' : 'not helpful'}`,
      sessionId,
      helpful,
    }));
    
    // Dismiss after feedback
    setTimeout(() => {
      handleDismiss();
    }, 2000);
  };
  
  // Get icon for suggestion type
  const getSuggestionIcon = (type: string) => {
    switch (type) {
      case 'tip':
        return <TipIcon />;
      case 'warning':
        return <WarningIcon />;
      case 'info':
        return <InfoIcon />;
      case 'tutorial':
        return <LearnIcon />;
      default:
        return <SuggestionIcon />;
    }
  };
  
  // Get color for suggestion type
  const getSuggestionColor = (type: string) => {
    switch (type) {
      case 'tip':
        return 'success';
      case 'warning':
        return 'warning';
      case 'info':
        return 'info';
      case 'tutorial':
        return 'primary';
      default:
        return 'default';
    }
  };
  
  if (!enabled || !proactiveHelpEnabled || !activeSuggestion) {
    return null;
  }
  
  return (
    <Snackbar
      open={showSuggestion}
      autoHideDuration={suggestionExpanded ? null : 10000}
      onClose={handleDismiss}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      TransitionComponent={Slide}
      sx={{ mb: 8 }}
    >
      <Paper
        elevation={8}
        sx={{
          minWidth: 350,
          maxWidth: 450,
          borderRadius: 2,
          overflow: 'hidden',
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        }}
      >
        <Alert
          severity={getSuggestionColor(activeSuggestion.type) as any}
          icon={
            <Avatar
              sx={{
                bgcolor: alpha(theme.palette[getSuggestionColor(activeSuggestion.type) as 'success' | 'warning' | 'info' | 'error'].main, 0.1),
                color: theme.palette[getSuggestionColor(activeSuggestion.type) as 'success' | 'warning' | 'info' | 'error'].main,
              }}
            >
              {getSuggestionIcon(activeSuggestion.type)}
            </Avatar>
          }
          action={
            <IconButton size="small" onClick={handleDismiss}>
              <CloseIcon />
            </IconButton>
          }
          sx={{
            '& .MuiAlert-icon': {
              alignItems: 'center',
            },
          }}
        >
          <AlertTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {activeSuggestion.title}
            <Chip
              icon={<AutoAwesomeIcon />}
              label="AI Suggestion"
              size="small"
              variant="outlined"
            />
          </AlertTitle>
          
          <Typography variant="body2" sx={{ mb: 2 }}>
            {activeSuggestion.description}
          </Typography>
          
          {/* Pattern indicators */}
          {currentPattern && suggestionExpanded && (
            <Box sx={{ mb: 2 }}>
              <Typography variant="caption" color="text.secondary">
                Detected: {currentPattern.type} (confidence: {Math.round(currentPattern.confidence * 100)}%)
              </Typography>
              <List dense>
                {currentPattern.indicators.map((indicator, index) => (
                  <ListItem key={index} disablePadding>
                    <ListItemIcon sx={{ minWidth: 24 }}>
                      <CheckIcon fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={<Typography variant="caption">{indicator}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
          
          {/* Action buttons */}
          <Box display="flex" gap={1} alignItems="center">
            {activeSuggestion.action && (
              <Button
                size="small"
                variant="contained"
                onClick={() => {
                  activeSuggestion.action?.handler();
                  handleDismiss();
                }}
                startIcon={<AIIcon />}
              >
                {activeSuggestion.action.label}
              </Button>
            )}
            
            <Button
              size="small"
              onClick={() => setSuggestionExpanded(!suggestionExpanded)}
              endIcon={suggestionExpanded ? <CollapseIcon /> : <ExpandIcon />}
            >
              {suggestionExpanded ? 'Less' : 'More'}
            </Button>
            
            {!suggestionFeedback && (
              <>
                <IconButton
                  size="small"
                  onClick={() => handleFeedback(true)}
                  color="success"
                >
                  <ThumbUpIcon fontSize="small" />
                </IconButton>
                <IconButton
                  size="small"
                  onClick={() => handleFeedback(false)}
                  color="error"
                >
                  <ThumbDownIcon fontSize="small" />
                </IconButton>
              </>
            )}
          </Box>
          
          {suggestionFeedback && (
            <Box mt={1}>
              <Typography variant="caption" color="success.main">
                Thank you for your feedback!
              </Typography>
            </Box>
          )}
        </Alert>
        
        {/* User engagement metrics (debug) */}
        {process.env.NODE_ENV === 'development' && suggestionExpanded && (
          <Box sx={{ p: 2, bgcolor: 'background.default' }}>
            <Typography variant="caption" color="text.secondary">
              Debug Info:
            </Typography>
            <Typography variant="caption" display="block">
              Time on page: {Math.round(userEngagement.timeOnPage / 1000)}s
            </Typography>
            <Typography variant="caption" display="block">
              Interactions: {userEngagement.interactions}
            </Typography>
            <Typography variant="caption" display="block">
              Scroll depth: {Math.round(userEngagement.scrollDepth)}%
            </Typography>
          </Box>
        )}
      </Paper>
    </Snackbar>
  );
};

export default ProactiveHelpEngine;