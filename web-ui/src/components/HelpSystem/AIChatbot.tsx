import React, { useState, useEffect, useRef } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  IconButton,
  Avatar,
  Chip,
  Button,
  Fab,
  Badge,
  Zoom,
  Slide,
  CircularProgress,
  Divider,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  InputAdornment,
  Menu,
  MenuItem,
  Tooltip,
  Rating,
  Alert,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Chat as ChatIcon,
  Send as SendIcon,
  Close as CloseIcon,
  SmartToy as BotIcon,
  Person as PersonIcon,
  AttachFile as AttachIcon,
  Mic as MicIcon,
  MicOff as MicOffIcon,
  MoreVert as MoreIcon,
  ThumbUp as ThumbUpIcon,
  ThumbDown as ThumbDownIcon,
  ContentCopy as CopyIcon,
  Refresh as RefreshIcon,
  Download as DownloadIcon,
  Psychology as PsychologyIcon,
  AutoAwesome as AutoAwesomeIcon,
  QuestionAnswer as QuestionAnswerIcon,
  School as SchoolIcon,
  Build as BuildIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import {
  toggleChat,
  addChatMessage,
  clearChat,
  sendChatMessage,
  provideFeedback,
  recordInteraction,
} from '../../store/slices/helpSlice';
import { ChatMessage } from './types';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

const AIChatbot: React.FC = () => {
  const theme = useTheme();
  const dispatch = useDispatch();
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const {
    chatOpen,
    chatMessages,
    currentContext,
    loading,
    sessionId,
  } = useSelector((state: RootState) => state.help);
  
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedMessage, setSelectedMessage] = useState<ChatMessage | null>(null);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const [attachments, setAttachments] = useState<File[]>([]);
  
  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages]);
  
  // Focus input when chat opens
  useEffect(() => {
    if (chatOpen) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [chatOpen]);
  
  // Handle sending message
  const handleSend = async () => {
    if (!input.trim() && attachments.length === 0) return;
    
    // Add user message
    const userMessage: ChatMessage = {
      id: `msg-${Date.now()}`,
      type: 'user',
      content: input,
      timestamp: new Date(),
      context: currentContext,
      attachments: attachments.map(file => ({
        type: 'file',
        url: URL.createObjectURL(file),
        name: file.name,
      })),
    };
    
    dispatch(addChatMessage(userMessage));
    setInput('');
    setAttachments([]);
    setIsTyping(true);
    
    // Record interaction
    dispatch(recordInteraction({
      type: 'chat',
      context: currentContext,
      query: input,
      sessionId,
    }));
    
    // Send to LLM and get response
    try {
      await dispatch(sendChatMessage({
        message: input,
        context: currentContext,
      })).unwrap();
    } catch (error) {
      console.error('Failed to send message:', error);
      dispatch(addChatMessage({
        id: `msg-error-${Date.now()}`,
        type: 'system',
        content: 'Sorry, I encountered an error. Please try again.',
        timestamp: new Date(),
      }));
    } finally {
      setIsTyping(false);
    }
  };
  
  // Handle voice input
  const handleVoiceInput = () => {
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
          setInput(transcript);
          setIsListening(false);
        };
        
        recognition.onerror = () => {
          setIsListening(false);
        };
        
        recognition.onend = () => {
          setIsListening(false);
        };
      }
    } else {
      alert('Speech recognition is not supported in your browser.');
    }
  };
  
  // Handle file attachment
  const handleFileAttach = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files || []);
    setAttachments(prev => [...prev, ...files]);
  };
  
  // Handle message actions
  const handleMessageAction = (action: string, data?: any) => {
    switch (action) {
      case 'openAddRecord':
        // Navigate to add record with type
        console.log('Opening add record dialog with type:', data.type);
        break;
      case 'playVideo':
        // Open video player
        console.log('Playing video:', data.id);
        break;
      case 'openDocs':
        // Open documentation
        console.log('Opening docs for:', data.topic);
        break;
      case 'startWizard':
        // Start troubleshooting wizard
        console.log('Starting wizard:', data.wizard);
        break;
      case 'search':
        // Perform search
        console.log('Searching for:', data.query);
        break;
      default:
        console.log('Unknown action:', action, data);
    }
  };
  
  // Copy message to clipboard
  const copyToClipboard = (content: string) => {
    navigator.clipboard.writeText(content);
  };
  
  // Download chat history
  const downloadChatHistory = () => {
    const history = chatMessages.map(msg => 
      `[${msg.timestamp}] ${msg.type.toUpperCase()}: ${msg.content}`
    ).join('\n\n');
    
    const blob = new Blob([history], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `chat-history-${sessionId}.txt`;
    a.click();
  };
  
  // Suggested prompts based on context
  const getSuggestedPrompts = () => {
    const prompts = {
      records: [
        'How do I add an A record?',
        'What is the difference between A and CNAME?',
        'How to set up email records?',
      ],
      zones: [
        'How to create a new zone?',
        'Import zone from another provider',
        'What are zone transfers?',
      ],
      dnssec: [
        'How to enable DNSSEC?',
        'What are DS records?',
        'DNSSEC key rotation',
      ],
      analytics: [
        'How to view query statistics?',
        'Export analytics data',
        'Set up performance alerts',
      ],
    };
    
    return prompts[currentContext.page as keyof typeof prompts] || [
      'How can I get started?',
      'What features are available?',
      'Show me a tutorial',
    ];
  };
  
  return (
    <>
      {/* Chat toggle button */}
      <Zoom in={!chatOpen}>
        <Fab
          color="primary"
          size="large"
          onClick={() => dispatch(toggleChat())}
          sx={{
            position: 'fixed',
            bottom: 24,
            right: 24,
            zIndex: 1200,
            background: `linear-gradient(45deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            '&:hover': {
              transform: 'scale(1.1)',
            },
          }}
        >
          <Badge badgeContent={chatMessages.length} color="error">
            <ChatIcon />
          </Badge>
        </Fab>
      </Zoom>
      
      {/* Chat window */}
      <Slide direction="up" in={chatOpen} mountOnEnter unmountOnExit>
        <Paper
          elevation={8}
          sx={{
            position: 'fixed',
            bottom: 24,
            right: 24,
            width: { xs: '90%', sm: 400 },
            height: { xs: '80vh', sm: 600 },
            maxHeight: '80vh',
            zIndex: 1300,
            display: 'flex',
            flexDirection: 'column',
            borderRadius: 2,
            overflow: 'hidden',
          }}
        >
          {/* Header */}
          <Box
            sx={{
              p: 2,
              background: `linear-gradient(45deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              color: 'white',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <Box display="flex" alignItems="center" gap={1}>
              <Avatar sx={{ bgcolor: alpha(theme.palette.common.white, 0.2) }}>
                <AutoAwesomeIcon />
              </Avatar>
              <Box>
                <Typography variant="h6">AI Assistant</Typography>
                <Typography variant="caption" sx={{ opacity: 0.9 }}>
                  {currentContext.page ? `Helping with ${currentContext.page}` : 'Ready to help'}
                </Typography>
              </Box>
            </Box>
            <Box>
              <IconButton
                size="small"
                onClick={(e) => setMenuAnchor(e.currentTarget)}
                sx={{ color: 'white' }}
              >
                <MoreIcon />
              </IconButton>
              <IconButton
                size="small"
                onClick={() => dispatch(toggleChat())}
                sx={{ color: 'white' }}
              >
                <CloseIcon />
              </IconButton>
            </Box>
          </Box>
          
          {/* Menu */}
          <Menu
            anchorEl={menuAnchor}
            open={Boolean(menuAnchor)}
            onClose={() => setMenuAnchor(null)}
          >
            <MenuItem onClick={() => {
              dispatch(clearChat());
              setMenuAnchor(null);
            }}>
              <RefreshIcon fontSize="small" sx={{ mr: 1 }} />
              Clear Chat
            </MenuItem>
            <MenuItem onClick={() => {
              downloadChatHistory();
              setMenuAnchor(null);
            }}>
              <DownloadIcon fontSize="small" sx={{ mr: 1 }} />
              Download History
            </MenuItem>
          </Menu>
          
          {/* Messages */}
          <Box
            sx={{
              flex: 1,
              overflowY: 'auto',
              p: 2,
              bgcolor: theme.palette.grey[50],
            }}
          >
            {chatMessages.length === 0 && showSuggestions && (
              <Box sx={{ textAlign: 'center', py: 4 }}>
                <PsychologyIcon sx={{ fontSize: 48, color: theme.palette.grey[400], mb: 2 }} />
                <Typography variant="h6" gutterBottom>
                  How can I help you today?
                </Typography>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  I'm here to assist with {currentContext.page || 'anything you need'}
                </Typography>
                <Box sx={{ mt: 3 }}>
                  <Typography variant="caption" color="text.secondary" gutterBottom>
                    Try asking:
                  </Typography>
                  <Box sx={{ mt: 1, display: 'flex', flexDirection: 'column', gap: 1 }}>
                    {getSuggestedPrompts().map((prompt, index) => (
                      <Chip
                        key={index}
                        label={prompt}
                        onClick={() => setInput(prompt)}
                        variant="outlined"
                        size="small"
                        sx={{ cursor: 'pointer' }}
                      />
                    ))}
                  </Box>
                </Box>
              </Box>
            )}
            
            <List sx={{ p: 0 }}>
              {chatMessages.map((message) => (
                <ListItem
                  key={message.id}
                  sx={{
                    flexDirection: 'column',
                    alignItems: message.type === 'user' ? 'flex-end' : 'flex-start',
                    p: 0,
                    mb: 2,
                  }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      gap: 1,
                      maxWidth: '85%',
                      flexDirection: message.type === 'user' ? 'row-reverse' : 'row',
                    }}
                  >
                    <Avatar
                      sx={{
                        width: 32,
                        height: 32,
                        bgcolor: message.type === 'user' 
                          ? theme.palette.primary.main 
                          : theme.palette.secondary.main,
                      }}
                    >
                      {message.type === 'user' ? <PersonIcon /> : <BotIcon />}
                    </Avatar>
                    <Paper
                      elevation={1}
                      sx={{
                        p: 1.5,
                        bgcolor: message.type === 'user'
                          ? theme.palette.primary.main
                          : theme.palette.background.paper,
                        color: message.type === 'user'
                          ? 'white'
                          : 'text.primary',
                        borderRadius: 2,
                        borderTopLeftRadius: message.type === 'user' ? 16 : 4,
                        borderTopRightRadius: message.type === 'user' ? 4 : 16,
                      }}
                    >
                      {message.type === 'assistant' ? (
                        <ReactMarkdown
                          components={{
                            code({ node, inline, className, children, ...props }) {
                              const match = /language-(\w+)/.exec(className || '');
                              return !inline && match ? (
                                <SyntaxHighlighter
                                  style={vscDarkPlus}
                                  language={match[1]}
                                  PreTag="div"
                                  {...props}
                                >
                                  {String(children).replace(/\n$/, '')}
                                </SyntaxHighlighter>
                              ) : (
                                <code className={className} {...props}>
                                  {children}
                                </code>
                              );
                            },
                          }}
                        >
                          {message.content}
                        </ReactMarkdown>
                      ) : (
                        <Typography variant="body2">
                          {message.content}
                        </Typography>
                      )}
                      
                      {/* Message actions */}
                      {message.actions && message.actions.length > 0 && (
                        <Box sx={{ mt: 1.5, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                          {message.actions.map((action, index) => (
                            <Button
                              key={index}
                              size="small"
                              variant={message.type === 'user' ? 'outlined' : 'contained'}
                              onClick={() => handleMessageAction(action.action, action.data)}
                              sx={{
                                color: message.type === 'user' ? 'white' : undefined,
                                borderColor: message.type === 'user' ? 'white' : undefined,
                              }}
                            >
                              {action.label}
                            </Button>
                          ))}
                        </Box>
                      )}
                      
                      {/* Attachments */}
                      {message.attachments && message.attachments.length > 0 && (
                        <Box sx={{ mt: 1 }}>
                          {message.attachments.map((attachment, index) => (
                            <Chip
                              key={index}
                              label={attachment.name}
                              size="small"
                              icon={<AttachIcon />}
                              onClick={() => window.open(attachment.url, '_blank')}
                              sx={{ mr: 0.5, mb: 0.5 }}
                            />
                          ))}
                        </Box>
                      )}
                    </Paper>
                  </Box>
                  
                  {/* Feedback for assistant messages */}
                  {message.type === 'assistant' && (
                    <Box
                      sx={{
                        display: 'flex',
                        gap: 0.5,
                        mt: 0.5,
                        ml: 5,
                      }}
                    >
                      <Tooltip title="Helpful">
                        <IconButton
                          size="small"
                          onClick={() => dispatch(provideFeedback({
                            messageId: message.id,
                            helpful: true,
                          }))}
                          sx={{
                            color: message.feedback?.helpful === true
                              ? theme.palette.success.main
                              : theme.palette.grey[400],
                          }}
                        >
                          <ThumbUpIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Not helpful">
                        <IconButton
                          size="small"
                          onClick={() => dispatch(provideFeedback({
                            messageId: message.id,
                            helpful: false,
                          }))}
                          sx={{
                            color: message.feedback?.helpful === false
                              ? theme.palette.error.main
                              : theme.palette.grey[400],
                          }}
                        >
                          <ThumbDownIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Copy">
                        <IconButton
                          size="small"
                          onClick={() => copyToClipboard(message.content)}
                        >
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  )}
                </ListItem>
              ))}
            </List>
            
            {/* Typing indicator */}
            {isTyping && (
              <Box display="flex" alignItems="center" gap={1} ml={5}>
                <Avatar sx={{ width: 32, height: 32, bgcolor: theme.palette.secondary.main }}>
                  <BotIcon />
                </Avatar>
                <Paper sx={{ p: 1, borderRadius: 2 }}>
                  <Box display="flex" gap={0.5}>
                    <CircularProgress size={8} />
                    <CircularProgress size={8} sx={{ animationDelay: '0.2s' }} />
                    <CircularProgress size={8} sx={{ animationDelay: '0.4s' }} />
                  </Box>
                </Paper>
              </Box>
            )}
            
            <div ref={messagesEndRef} />
          </Box>
          
          {/* Input area */}
          <Box sx={{ p: 2, borderTop: 1, borderColor: 'divider' }}>
            {/* Attached files */}
            {attachments.length > 0 && (
              <Box sx={{ mb: 1, display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                {attachments.map((file, index) => (
                  <Chip
                    key={index}
                    label={file.name}
                    size="small"
                    onDelete={() => setAttachments(prev => prev.filter((_, i) => i !== index))}
                  />
                ))}
              </Box>
            )}
            
            <TextField
              ref={inputRef}
              fullWidth
              placeholder="Type your question..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyPress={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault();
                  handleSend();
                }
              }}
              multiline
              maxRows={3}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <input
                      ref={fileInputRef}
                      type="file"
                      hidden
                      multiple
                      onChange={handleFileAttach}
                    />
                    <IconButton
                      size="small"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      <AttachIcon />
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={handleVoiceInput}
                      color={isListening ? 'error' : 'default'}
                    >
                      {isListening ? <MicOffIcon /> : <MicIcon />}
                    </IconButton>
                    <IconButton
                      size="small"
                      color="primary"
                      onClick={handleSend}
                      disabled={loading || (!input.trim() && attachments.length === 0)}
                    >
                      <SendIcon />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{
                '& .MuiOutlinedInput-root': {
                  borderRadius: 3,
                },
              }}
            />
          </Box>
        </Paper>
      </Slide>
    </>
  );
};

export default AIChatbot;