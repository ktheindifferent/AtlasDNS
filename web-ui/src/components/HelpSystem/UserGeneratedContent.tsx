import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Card,
  CardContent,
  CardActions,
  Avatar,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tab,
  Tabs,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondaryAction,
  Rating,
  Divider,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  ToggleButton,
  ToggleButtonGroup,
  Badge,
  Tooltip,
  Menu,
  LinearProgress,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ThumbUp as ThumbUpIcon,
  ThumbDown as ThumbDownIcon,
  Share as ShareIcon,
  Flag as FlagIcon,
  CheckCircle as VerifiedIcon,
  Person as PersonIcon,
  Lightbulb as TipIcon,
  Build as SolutionIcon,
  School as GuideIcon,
  Code as CodeIcon,
  TrendingUp as TrendingIcon,
  NewReleases as NewIcon,
  Star as StarIcon,
  Comment as CommentIcon,
  Bookmark as BookmarkIcon,
  MoreVert as MoreIcon,
  ContentCopy as CopyIcon,
  Search as SearchIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import { submitUserContent, voteUserContent } from '../../store/slices/helpSlice';
import { UserHelpContent, HelpContext } from './types';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface UserGeneratedContentProps {
  context?: HelpContext;
  embedded?: boolean;
}

interface ContentFormData {
  type: 'tip' | 'solution' | 'workaround' | 'guide';
  title: string;
  content: string;
  tags: string[];
  context?: HelpContext;
}

const UserGeneratedContent: React.FC<UserGeneratedContentProps> = ({
  context,
  embedded = false,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch();
  
  const { userContent, currentContext } = useSelector((state: RootState) => state.help);
  
  const [activeTab, setActiveTab] = useState(0);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [editingContent, setEditingContent] = useState<UserHelpContent | null>(null);
  const [formData, setFormData] = useState<ContentFormData>({
    type: 'tip',
    title: '',
    content: '',
    tags: [],
    context: context || currentContext,
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'recent' | 'popular' | 'helpful'>('recent');
  const [bookmarkedItems, setBookmarkedItems] = useState<Set<string>>(new Set());
  const [reportedItems, setReportedItems] = useState<Set<string>>(new Set());
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedContent, setSelectedContent] = useState<UserHelpContent | null>(null);
  const [tagInput, setTagInput] = useState('');
  
  // Filter and sort content
  const filteredContent = userContent
    .filter(item => {
      if (searchQuery && !item.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
          !item.content.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false;
      }
      if (filterType !== 'all' && item.type !== filterType) {
        return false;
      }
      if (context && item.context.page !== context.page) {
        return false;
      }
      return true;
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'popular':
          return (b.votes.helpful + b.votes.notHelpful) - (a.votes.helpful + a.votes.notHelpful);
        case 'helpful':
          const aRatio = a.votes.helpful / (a.votes.helpful + a.votes.notHelpful || 1);
          const bRatio = b.votes.helpful / (b.votes.helpful + b.votes.notHelpful || 1);
          return bRatio - aRatio;
        case 'recent':
        default:
          return new Date(b.created).getTime() - new Date(a.created).getTime();
      }
    });
  
  // Get trending content
  const trendingContent = [...userContent]
    .sort((a, b) => (b.votes.helpful + b.votes.notHelpful) - (a.votes.helpful + a.votes.notHelpful))
    .slice(0, 5);
  
  // Get verified content
  const verifiedContent = userContent.filter(item => item.verified);
  
  // Handle content submission
  const handleSubmit = async () => {
    if (!formData.title || !formData.content) return;
    
    await dispatch(submitUserContent({
      ...formData,
      context: formData.context || currentContext,
    })).unwrap();
    
    setCreateDialogOpen(false);
    setFormData({
      type: 'tip',
      title: '',
      content: '',
      tags: [],
      context: context || currentContext,
    });
    setTagInput('');
  };
  
  // Handle voting
  const handleVote = (contentId: string, helpful: boolean) => {
    dispatch(voteUserContent({ id: contentId, helpful }));
  };
  
  // Handle bookmark
  const handleBookmark = (contentId: string) => {
    setBookmarkedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(contentId)) {
        newSet.delete(contentId);
      } else {
        newSet.add(contentId);
      }
      return newSet;
    });
  };
  
  // Handle report
  const handleReport = (contentId: string) => {
    setReportedItems(prev => {
      const newSet = new Set(prev);
      newSet.add(contentId);
      return newSet;
    });
    // Send report to backend
    console.log('Reporting content:', contentId);
  };
  
  // Handle expand/collapse
  const handleToggleExpand = (contentId: string) => {
    setExpandedItems(prev => {
      const newSet = new Set(prev);
      if (newSet.has(contentId)) {
        newSet.delete(contentId);
      } else {
        newSet.add(contentId);
      }
      return newSet;
    });
  };
  
  // Add tag to form
  const handleAddTag = () => {
    if (tagInput && !formData.tags.includes(tagInput)) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, tagInput],
      }));
      setTagInput('');
    }
  };
  
  // Remove tag from form
  const handleRemoveTag = (tag: string) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(t => t !== tag),
    }));
  };
  
  // Copy content to clipboard
  const handleCopy = (content: string) => {
    navigator.clipboard.writeText(content);
  };
  
  // Get icon for content type
  const getContentIcon = (type: string) => {
    switch (type) {
      case 'tip':
        return <TipIcon />;
      case 'solution':
        return <SolutionIcon />;
      case 'workaround':
        return <CodeIcon />;
      case 'guide':
        return <GuideIcon />;
      default:
        return <TipIcon />;
    }
  };
  
  // Get color for content type
  const getContentColor = (type: string) => {
    switch (type) {
      case 'tip':
        return theme.palette.info.main;
      case 'solution':
        return theme.palette.success.main;
      case 'workaround':
        return theme.palette.warning.main;
      case 'guide':
        return theme.palette.primary.main;
      default:
        return theme.palette.grey[500];
    }
  };
  
  // Render content card
  const renderContentCard = (item: UserHelpContent) => {
    const isExpanded = expandedItems.has(item.id);
    const helpfulRatio = item.votes.helpful / (item.votes.helpful + item.votes.notHelpful || 1);
    
    return (
      <Card key={item.id} sx={{ mb: 2 }}>
        <CardContent>
          <Box display="flex" alignItems="flex-start" justifyContent="space-between" mb={2}>
            <Box display="flex" alignItems="center" gap={1}>
              <Avatar
                sx={{
                  bgcolor: alpha(getContentColor(item.type), 0.1),
                  color: getContentColor(item.type),
                }}
              >
                {getContentIcon(item.type)}
              </Avatar>
              <Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <Typography variant="h6">{item.title}</Typography>
                  {item.verified && (
                    <Tooltip title="Verified by moderators">
                      <VerifiedIcon color="primary" fontSize="small" />
                    </Tooltip>
                  )}
                </Box>
                <Box display="flex" alignItems="center" gap={1}>
                  <Typography variant="caption" color="text.secondary">
                    by {item.userName}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    • {new Date(item.created).toLocaleDateString()}
                  </Typography>
                  <Chip
                    label={item.type}
                    size="small"
                    sx={{
                      bgcolor: alpha(getContentColor(item.type), 0.1),
                      color: getContentColor(item.type),
                    }}
                  />
                </Box>
              </Box>
            </Box>
            
            <IconButton
              size="small"
              onClick={(e) => {
                setMenuAnchor(e.currentTarget);
                setSelectedContent(item);
              }}
            >
              <MoreIcon />
            </IconButton>
          </Box>
          
          <Box sx={{ mb: 2 }}>
            {isExpanded ? (
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
                {item.content}
              </ReactMarkdown>
            ) : (
              <Typography variant="body2" color="text.secondary">
                {item.content.substring(0, 200)}...
              </Typography>
            )}
          </Box>
          
          {item.tags.length > 0 && (
            <Box display="flex" gap={0.5} flexWrap="wrap" mb={2}>
              {item.tags.map(tag => (
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
          
          <Box display="flex" alignItems="center" justifyContent="space-between">
            <Box display="flex" alignItems="center" gap={2}>
              <Box display="flex" alignItems="center">
                <IconButton
                  size="small"
                  onClick={() => handleVote(item.id, true)}
                  color="success"
                >
                  <ThumbUpIcon fontSize="small" />
                </IconButton>
                <Typography variant="caption">{item.votes.helpful}</Typography>
              </Box>
              
              <Box display="flex" alignItems="center">
                <IconButton
                  size="small"
                  onClick={() => handleVote(item.id, false)}
                  color="error"
                >
                  <ThumbDownIcon fontSize="small" />
                </IconButton>
                <Typography variant="caption">{item.votes.notHelpful}</Typography>
              </Box>
              
              <Chip
                label={`${Math.round(helpfulRatio * 100)}% helpful`}
                size="small"
                color={helpfulRatio > 0.8 ? 'success' : helpfulRatio > 0.5 ? 'warning' : 'default'}
                variant="outlined"
              />
            </Box>
            
            <Box display="flex" gap={1}>
              <Button
                size="small"
                onClick={() => handleToggleExpand(item.id)}
              >
                {isExpanded ? 'Show Less' : 'Read More'}
              </Button>
              <IconButton
                size="small"
                onClick={() => handleBookmark(item.id)}
                color={bookmarkedItems.has(item.id) ? 'primary' : 'default'}
              >
                <BookmarkIcon fontSize="small" />
              </IconButton>
              <IconButton
                size="small"
                onClick={() => handleCopy(item.content)}
              >
                <CopyIcon fontSize="small" />
              </IconButton>
              <IconButton
                size="small"
                onClick={() => window.open(`/share/${item.id}`, '_blank')}
              >
                <ShareIcon fontSize="small" />
              </IconButton>
            </Box>
          </Box>
        </CardContent>
      </Card>
    );
  };
  
  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      {!embedded && (
        <Paper sx={{ p: 2, mb: 2 }}>
          <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
            <Box display="flex" alignItems="center" gap={2}>
              <PersonIcon color="primary" />
              <Typography variant="h5">Community Help</Typography>
              <Chip
                label={`${userContent.length} contributions`}
                color="primary"
                variant="outlined"
              />
            </Box>
            
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setCreateDialogOpen(true)}
            >
              Share Knowledge
            </Button>
          </Box>
          
          <Typography variant="body2" color="text.secondary">
            Learn from the community's collective knowledge. Share your tips, solutions, and guides to help others.
          </Typography>
        </Paper>
      )}
      
      {/* Search and Filters */}
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box display="flex" gap={2} alignItems="center" mb={2}>
          <TextField
            fullWidth
            size="small"
            placeholder="Search community content..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: <SearchIcon sx={{ mr: 1, color: 'text.secondary' }} />,
            }}
          />
          
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Type</InputLabel>
            <Select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              label="Type"
            >
              <MenuItem value="all">All Types</MenuItem>
              <MenuItem value="tip">Tips</MenuItem>
              <MenuItem value="solution">Solutions</MenuItem>
              <MenuItem value="workaround">Workarounds</MenuItem>
              <MenuItem value="guide">Guides</MenuItem>
            </Select>
          </FormControl>
          
          <ToggleButtonGroup
            value={sortBy}
            exclusive
            onChange={(e, value) => value && setSortBy(value)}
            size="small"
          >
            <ToggleButton value="recent">
              <Tooltip title="Most Recent">
                <NewIcon />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="popular">
              <Tooltip title="Most Popular">
                <TrendingIcon />
              </Tooltip>
            </ToggleButton>
            <ToggleButton value="helpful">
              <Tooltip title="Most Helpful">
                <StarIcon />
              </Tooltip>
            </ToggleButton>
          </ToggleButtonGroup>
        </Box>
      </Paper>
      
      {/* Tabs */}
      <Paper sx={{ mb: 2 }}>
        <Tabs
          value={activeTab}
          onChange={(e, value) => setActiveTab(value)}
          variant="fullWidth"
        >
          <Tab
            label="All Content"
            icon={<Badge badgeContent={filteredContent.length} color="primary" />}
          />
          <Tab
            label="Trending"
            icon={<TrendingIcon />}
          />
          <Tab
            label="Verified"
            icon={<VerifiedIcon />}
          />
          <Tab
            label="Bookmarked"
            icon={<Badge badgeContent={bookmarkedItems.size} color="primary">
              <BookmarkIcon />
            </Badge>}
          />
        </Tabs>
      </Paper>
      
      {/* Content */}
      <Box sx={{ flex: 1, overflow: 'auto' }}>
        {activeTab === 0 && (
          <>
            {filteredContent.length === 0 ? (
              <Alert severity="info">
                No community content found. Be the first to share your knowledge!
              </Alert>
            ) : (
              filteredContent.map(renderContentCard)
            )}
          </>
        )}
        
        {activeTab === 1 && (
          <>
            <Typography variant="h6" gutterBottom>
              Trending Content
            </Typography>
            {trendingContent.map(renderContentCard)}
          </>
        )}
        
        {activeTab === 2 && (
          <>
            {verifiedContent.length === 0 ? (
              <Alert severity="info">
                No verified content yet. Quality contributions get verified by moderators.
              </Alert>
            ) : (
              verifiedContent.map(renderContentCard)
            )}
          </>
        )}
        
        {activeTab === 3 && (
          <>
            {bookmarkedItems.size === 0 ? (
              <Alert severity="info">
                You haven't bookmarked any content yet.
              </Alert>
            ) : (
              userContent
                .filter(item => bookmarkedItems.has(item.id))
                .map(renderContentCard)
            )}
          </>
        )}
      </Box>
      
      {/* Content Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={() => setMenuAnchor(null)}
      >
        <MenuItem onClick={() => {
          if (selectedContent) {
            handleReport(selectedContent.id);
          }
          setMenuAnchor(null);
        }}>
          <FlagIcon fontSize="small" sx={{ mr: 1 }} />
          Report
        </MenuItem>
        <MenuItem onClick={() => {
          setEditingContent(selectedContent);
          setMenuAnchor(null);
        }}>
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Edit
        </MenuItem>
      </Menu>
      
      {/* Create/Edit Dialog */}
      <Dialog
        open={createDialogOpen || Boolean(editingContent)}
        onClose={() => {
          setCreateDialogOpen(false);
          setEditingContent(null);
        }}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {editingContent ? 'Edit Content' : 'Share Your Knowledge'}
        </DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2 }}>
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel>Content Type</InputLabel>
              <Select
                value={formData.type}
                onChange={(e) => setFormData(prev => ({ ...prev, type: e.target.value as any }))}
                label="Content Type"
              >
                <MenuItem value="tip">
                  <Box display="flex" alignItems="center" gap={1}>
                    <TipIcon />
                    Tip - Quick advice or best practice
                  </Box>
                </MenuItem>
                <MenuItem value="solution">
                  <Box display="flex" alignItems="center" gap={1}>
                    <SolutionIcon />
                    Solution - Fix for a specific problem
                  </Box>
                </MenuItem>
                <MenuItem value="workaround">
                  <Box display="flex" alignItems="center" gap={1}>
                    <CodeIcon />
                    Workaround - Alternative approach
                  </Box>
                </MenuItem>
                <MenuItem value="guide">
                  <Box display="flex" alignItems="center" gap={1}>
                    <GuideIcon />
                    Guide - Step-by-step tutorial
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>
            
            <TextField
              fullWidth
              label="Title"
              value={formData.title}
              onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
              sx={{ mb: 2 }}
            />
            
            <TextField
              fullWidth
              label="Content"
              value={formData.content}
              onChange={(e) => setFormData(prev => ({ ...prev, content: e.target.value }))}
              multiline
              rows={8}
              sx={{ mb: 2 }}
              helperText="Supports Markdown formatting"
            />
            
            <Box sx={{ mb: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Tags
              </Typography>
              <Box display="flex" gap={1} alignItems="center" mb={1}>
                <TextField
                  size="small"
                  placeholder="Add tag..."
                  value={tagInput}
                  onChange={(e) => setTagInput(e.target.value)}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleAddTag();
                    }
                  }}
                />
                <Button size="small" onClick={handleAddTag}>
                  Add
                </Button>
              </Box>
              <Box display="flex" gap={0.5} flexWrap="wrap">
                {formData.tags.map(tag => (
                  <Chip
                    key={tag}
                    label={tag}
                    onDelete={() => handleRemoveTag(tag)}
                  />
                ))}
              </Box>
            </Box>
            
            {context && (
              <Alert severity="info">
                This content will be associated with the {context.page} section
              </Alert>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setCreateDialogOpen(false);
            setEditingContent(null);
          }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSubmit}
            disabled={!formData.title || !formData.content}
          >
            {editingContent ? 'Update' : 'Share'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UserGeneratedContent;