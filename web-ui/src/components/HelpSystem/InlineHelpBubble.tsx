import React, { useState, useEffect, useRef } from 'react';
import {
  Popper,
  Paper,
  Box,
  Typography,
  IconButton,
  Button,
  Fade,
  ClickAwayListener,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  useTheme,
  alpha,
  Zoom,
  Tooltip,
} from '@mui/material';
import {
  Help as HelpIcon,
  Close as CloseIcon,
  PlayCircle as VideoIcon,
  Article as DocsIcon,
  Lightbulb as TipIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  CheckCircle as CheckIcon,
  RadioButtonUnchecked as UncheckedIcon,
  AutoAwesome as AIIcon,
  School as LearnIcon,
  ContentCopy as CopyIcon,
  OpenInNew as OpenIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import { recordInteraction } from '../../store/slices/helpSlice';
import { HelpContext } from './types';

interface InlineHelpContent {
  title: string;
  description: string;
  tips?: string[];
  warnings?: string[];
  examples?: Array<{ label: string; value: string; copyable?: boolean }>;
  checklist?: Array<{ label: string; checked?: boolean }>;
  videoUrl?: string;
  docsUrl?: string;
  learnMoreUrl?: string;
  relatedTopics?: string[];
  difficulty?: 'beginner' | 'intermediate' | 'advanced';
  estimatedTime?: number;
}

interface InlineHelpBubbleProps {
  content: InlineHelpContent;
  children: React.ReactElement;
  context?: HelpContext;
  position?: 'top' | 'bottom' | 'left' | 'right';
  trigger?: 'hover' | 'click' | 'focus';
  delay?: number;
  interactive?: boolean;
  pulseAnimation?: boolean;
  showProgress?: boolean;
}

const InlineHelpBubble: React.FC<InlineHelpBubbleProps> = ({
  content,
  children,
  context,
  position = 'top',
  trigger = 'hover',
  delay = 200,
  interactive = true,
  pulseAnimation = false,
  showProgress = false,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch();
  const childRef = useRef<HTMLElement>(null);
  const timeoutRef = useRef<NodeJS.Timeout>();
  
  const { sessionId } = useSelector((state: RootState) => state.help);
  
  const [open, setOpen] = useState(false);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [checkedItems, setCheckedItems] = useState<Set<number>>(new Set());
  const [hasInteracted, setHasInteracted] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  
  useEffect(() => {
    return () => {
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, []);
  
  const handleOpen = (event: React.MouseEvent<HTMLElement> | React.FocusEvent<HTMLElement>) => {
    const target = event.currentTarget;
    
    if (trigger === 'click') {
      setAnchorEl(target);
      setOpen(true);
      recordHelpInteraction();
    } else {
      timeoutRef.current = setTimeout(() => {
        setAnchorEl(target);
        setOpen(true);
        recordHelpInteraction();
      }, delay);
    }
  };
  
  const handleClose = () => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
    }
    setOpen(false);
    setAnchorEl(null);
  };
  
  const recordHelpInteraction = () => {
    if (!hasInteracted) {
      setHasInteracted(true);
      dispatch(recordInteraction({
        type: 'tooltip',
        context: context || { page: 'unknown' },
        sessionId,
        query: content.title,
      }));
    }
  };
  
  const handleChecklistToggle = (index: number) => {
    setCheckedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(index)) {
        newSet.delete(index);
      } else {
        newSet.add(index);
      }
      return newSet;
    });
  };
  
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };
  
  const getDifficultyColor = (difficulty?: string) => {
    switch (difficulty) {
      case 'beginner':
        return theme.palette.success.main;
      case 'intermediate':
        return theme.palette.warning.main;
      case 'advanced':
        return theme.palette.error.main;
      default:
        return theme.palette.info.main;
    }
  };
  
  const childElement = React.cloneElement(children, {
    ref: childRef,
    onMouseEnter: trigger === 'hover' ? handleOpen : undefined,
    onMouseLeave: trigger === 'hover' ? handleClose : undefined,
    onClick: trigger === 'click' ? handleOpen : undefined,
    onFocus: trigger === 'focus' ? handleOpen : undefined,
    onBlur: trigger === 'focus' ? handleClose : undefined,
    style: {
      ...children.props.style,
      position: 'relative',
    },
  });
  
  return (
    <>
      {pulseAnimation && !hasInteracted ? (
        <Box sx={{ position: 'relative', display: 'inline-block' }}>
          {childElement}
          <Box
            sx={{
              position: 'absolute',
              top: -8,
              right: -8,
              zIndex: 1,
            }}
          >
            <Box
              sx={{
                position: 'relative',
                display: 'inline-block',
              }}
            >
              <HelpIcon
                sx={{
                  fontSize: 16,
                  color: theme.palette.primary.main,
                  cursor: 'pointer',
                }}
              />
              <Box
                sx={{
                  position: 'absolute',
                  top: '50%',
                  left: '50%',
                  transform: 'translate(-50%, -50%)',
                  width: 24,
                  height: 24,
                  borderRadius: '50%',
                  border: `2px solid ${theme.palette.primary.main}`,
                  animation: 'pulse 2s infinite',
                  '@keyframes pulse': {
                    '0%': {
                      transform: 'translate(-50%, -50%) scale(1)',
                      opacity: 1,
                    },
                    '100%': {
                      transform: 'translate(-50%, -50%) scale(1.5)',
                      opacity: 0,
                    },
                  },
                }}
              />
            </Box>
          </Box>
        </Box>
      ) : (
        childElement
      )}
      
      <Popper
        open={open}
        anchorEl={anchorEl}
        placement={position}
        transition
        sx={{ zIndex: theme.zIndex.tooltip + 1 }}
      >
        {({ TransitionProps }) => (
          <Fade {...TransitionProps} timeout={350}>
            <Paper
              elevation={8}
              sx={{
                p: 2,
                maxWidth: 400,
                borderRadius: 2,
                border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                background: `linear-gradient(135deg, ${theme.palette.background.paper}, ${alpha(theme.palette.primary.main, 0.02)})`,
              }}
            >
              {interactive ? (
                <ClickAwayListener onClickAway={handleClose}>
                  <Box>
                    {/* Header */}
                    <Box display="flex" alignItems="flex-start" justifyContent="space-between" mb={2}>
                      <Box flex={1}>
                        <Box display="flex" alignItems="center" gap={1} mb={1}>
                          <InfoIcon color="primary" />
                          <Typography variant="subtitle1" fontWeight="bold">
                            {content.title}
                          </Typography>
                        </Box>
                        
                        {(content.difficulty || content.estimatedTime) && (
                          <Box display="flex" gap={1}>
                            {content.difficulty && (
                              <Chip
                                label={content.difficulty}
                                size="small"
                                sx={{
                                  bgcolor: alpha(getDifficultyColor(content.difficulty), 0.1),
                                  color: getDifficultyColor(content.difficulty),
                                }}
                              />
                            )}
                            {content.estimatedTime && (
                              <Chip
                                label={`~${content.estimatedTime} min`}
                                size="small"
                                variant="outlined"
                              />
                            )}
                          </Box>
                        )}
                      </Box>
                      <IconButton size="small" onClick={handleClose}>
                        <CloseIcon />
                      </IconButton>
                    </Box>
                    
                    {/* Description */}
                    <Typography variant="body2" color="text.secondary" paragraph>
                      {content.description}
                    </Typography>
                    
                    {/* Progress indicator */}
                    {showProgress && content.checklist && (
                      <Box mb={2}>
                        <Box display="flex" justifyContent="space-between" mb={1}>
                          <Typography variant="caption" color="text.secondary">
                            Progress
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {checkedItems.size} / {content.checklist.length}
                          </Typography>
                        </Box>
                        <LinearProgress
                          variant="determinate"
                          value={(checkedItems.size / content.checklist.length) * 100}
                          sx={{ height: 6, borderRadius: 3 }}
                        />
                      </Box>
                    )}
                    
                    {/* Tips */}
                    {content.tips && content.tips.length > 0 && (
                      <Box mb={2}>
                        <Box display="flex" alignItems="center" gap={0.5} mb={1}>
                          <TipIcon sx={{ fontSize: 18, color: theme.palette.success.main }} />
                          <Typography variant="subtitle2">Tips</Typography>
                        </Box>
                        <List dense disablePadding>
                          {content.tips.map((tip, index) => (
                            <ListItem key={index} disableGutters>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <CheckIcon sx={{ fontSize: 16, color: theme.palette.success.main }} />
                              </ListItemIcon>
                              <ListItemText
                                primary={<Typography variant="caption">{tip}</Typography>}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                    
                    {/* Warnings */}
                    {content.warnings && content.warnings.length > 0 && (
                      <Box mb={2}>
                        <Box display="flex" alignItems="center" gap={0.5} mb={1}>
                          <WarningIcon sx={{ fontSize: 18, color: theme.palette.warning.main }} />
                          <Typography variant="subtitle2">Important</Typography>
                        </Box>
                        <List dense disablePadding>
                          {content.warnings.map((warning, index) => (
                            <ListItem key={index} disableGutters>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <WarningIcon sx={{ fontSize: 16, color: theme.palette.warning.main }} />
                              </ListItemIcon>
                              <ListItemText
                                primary={<Typography variant="caption">{warning}</Typography>}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                    
                    {/* Examples */}
                    {content.examples && content.examples.length > 0 && (
                      <Box mb={2}>
                        <Typography variant="subtitle2" gutterBottom>
                          Examples
                        </Typography>
                        {content.examples.map((example, index) => (
                          <Box
                            key={index}
                            sx={{
                              mb: 1,
                              p: 1,
                              bgcolor: alpha(theme.palette.grey[900], 0.04),
                              borderRadius: 1,
                            }}
                          >
                            <Typography variant="caption" color="text.secondary">
                              {example.label}:
                            </Typography>
                            <Box display="flex" alignItems="center" gap={1}>
                              <Typography
                                variant="body2"
                                sx={{
                                  fontFamily: 'monospace',
                                  flex: 1,
                                }}
                              >
                                {example.value}
                              </Typography>
                              {example.copyable && (
                                <Tooltip title={copied === `ex-${index}` ? 'Copied!' : 'Copy'}>
                                  <IconButton
                                    size="small"
                                    onClick={() => handleCopy(example.value, `ex-${index}`)}
                                  >
                                    <CopyIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                              )}
                            </Box>
                          </Box>
                        ))}
                      </Box>
                    )}
                    
                    {/* Checklist */}
                    {content.checklist && content.checklist.length > 0 && (
                      <Box mb={2}>
                        <Typography variant="subtitle2" gutterBottom>
                          Checklist
                        </Typography>
                        <List dense disablePadding>
                          {content.checklist.map((item, index) => (
                            <ListItem
                              key={index}
                              disableGutters
                              onClick={() => handleChecklistToggle(index)}
                              sx={{ cursor: 'pointer' }}
                            >
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                {checkedItems.has(index) || item.checked ? (
                                  <CheckIcon sx={{ fontSize: 18, color: theme.palette.success.main }} />
                                ) : (
                                  <UncheckedIcon sx={{ fontSize: 18 }} />
                                )}
                              </ListItemIcon>
                              <ListItemText
                                primary={
                                  <Typography
                                    variant="caption"
                                    sx={{
                                      textDecoration: checkedItems.has(index) || item.checked ? 'line-through' : 'none',
                                    }}
                                  >
                                    {item.label}
                                  </Typography>
                                }
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                    
                    {/* Related Topics */}
                    {content.relatedTopics && content.relatedTopics.length > 0 && (
                      <Box mb={2}>
                        <Typography variant="subtitle2" gutterBottom>
                          Related Topics
                        </Typography>
                        <Box display="flex" gap={0.5} flexWrap="wrap">
                          {content.relatedTopics.map((topic, index) => (
                            <Chip
                              key={index}
                              label={topic}
                              size="small"
                              variant="outlined"
                              onClick={() => console.log('Navigate to:', topic)}
                            />
                          ))}
                        </Box>
                      </Box>
                    )}
                    
                    {/* Action buttons */}
                    {(content.videoUrl || content.docsUrl || content.learnMoreUrl) && (
                      <>
                        <Divider sx={{ my: 2 }} />
                        <Box display="flex" gap={1} flexWrap="wrap">
                          {content.videoUrl && (
                            <Button
                              size="small"
                              startIcon={<VideoIcon />}
                              href={content.videoUrl}
                              target="_blank"
                              variant="outlined"
                            >
                              Video
                            </Button>
                          )}
                          {content.docsUrl && (
                            <Button
                              size="small"
                              startIcon={<DocsIcon />}
                              href={content.docsUrl}
                              target="_blank"
                              variant="outlined"
                            >
                              Docs
                            </Button>
                          )}
                          {content.learnMoreUrl && (
                            <Button
                              size="small"
                              startIcon={<LearnIcon />}
                              href={content.learnMoreUrl}
                              target="_blank"
                              variant="outlined"
                            >
                              Learn More
                            </Button>
                          )}
                          <Button
                            size="small"
                            startIcon={<AIIcon />}
                            variant="contained"
                            onClick={() => {
                              handleClose();
                              // Open AI chat with context
                              console.log('Open AI chat with context:', content.title);
                            }}
                          >
                            Ask AI
                          </Button>
                        </Box>
                      </>
                    )}
                  </Box>
                </ClickAwayListener>
              ) : (
                <Box>
                  <Typography variant="subtitle2" gutterBottom>
                    {content.title}
                  </Typography>
                  <Typography variant="body2">
                    {content.description}
                  </Typography>
                </Box>
              )}
            </Paper>
          </Fade>
        )}
      </Popper>
    </>
  );
};

export default InlineHelpBubble;