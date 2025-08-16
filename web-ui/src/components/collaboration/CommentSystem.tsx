import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  TextField,
  Button,
  Avatar,
  Typography,
  IconButton,
  Menu,
  MenuItem,
  Chip,
  Divider,
  Badge,
  Collapse,
} from '@mui/material';
import { MentionsInput, Mention } from 'react-mentions';
import { format } from 'date-fns';
import SendIcon from '@mui/icons-material/Send';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import ReplyIcon from '@mui/icons-material/Reply';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CommentIcon from '@mui/icons-material/Comment';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { useSelector } from 'react-redux';
import { RootState } from '../../store';
import { useCollaboration } from '../../contexts/CollaborationContext';
import { Comment } from '../../store/slices/collaborationSlice';

interface CommentSystemProps {
  entityType: 'zone' | 'record';
  entityId: string;
  compact?: boolean;
}

const CommentSystem: React.FC<CommentSystemProps> = ({ entityType, entityId, compact = false }) => {
  const { sendComment, mentionUser, sendTyping } = useCollaboration();
  const { comments: allComments, activeUsers, typing } = useSelector(
    (state: RootState) => state.collaboration
  );
  const { user: currentUser } = useSelector((state: RootState) => state.auth);
  const [newComment, setNewComment] = useState('');
  const [editingComment, setEditingComment] = useState<string | null>(null);
  const [editContent, setEditContent] = useState('');
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedComment, setSelectedComment] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(!compact);
  const [isTyping, setIsTyping] = useState(false);

  const comments = allComments.filter(
    (c) => c.entityType === entityType && c.entityId === entityId
  );

  const unresolvedCount = comments.filter(c => !c.resolved).length;

  useEffect(() => {
    let typingTimeout: NodeJS.Timeout;
    if (isTyping) {
      sendTyping(`${entityType}:${entityId}`, true);
      typingTimeout = setTimeout(() => {
        sendTyping(`${entityType}:${entityId}`, false);
        setIsTyping(false);
      }, 3000);
    }
    return () => clearTimeout(typingTimeout);
  }, [isTyping, entityType, entityId, sendTyping]);

  const handleCommentSubmit = () => {
    if (!newComment.trim() || !currentUser) return;

    const mentions = extractMentions(newComment);
    
    sendComment({
      userId: currentUser.id || '',
      user: {
        id: currentUser.id || '',
        name: currentUser.name || currentUser.email || '',
        email: currentUser.email || '',
        color: '#2196F3',
        avatar: currentUser.avatar,
      },
      content: newComment,
      entityType,
      entityId,
      parentId: replyingTo || undefined,
      mentions,
    });

    mentions.forEach(userId => {
      mentionUser(userId, `${entityType}:${entityId}`);
    });

    setNewComment('');
    setReplyingTo(null);
    setIsTyping(false);
    sendTyping(`${entityType}:${entityId}`, false);
  };

  const handleEdit = (comment: Comment) => {
    setEditingComment(comment.id);
    setEditContent(comment.content);
    setAnchorEl(null);
  };

  const handleDelete = (commentId: string) => {
    // Send delete event
    setAnchorEl(null);
  };

  const handleResolve = (commentId: string) => {
    // Send resolve event
    setAnchorEl(null);
  };

  const extractMentions = (text: string): string[] => {
    const mentionRegex = /@\[([^\]]+)\]\(([^)]+)\)/g;
    const mentions: string[] = [];
    let match;
    while ((match = mentionRegex.exec(text)) !== null) {
      mentions.push(match[2]);
    }
    return mentions;
  };

  const mentionStyle = {
    control: {
      fontSize: 14,
      fontFamily: 'inherit',
    },
    highlighter: {
      overflow: 'hidden',
    },
    input: {
      margin: 0,
      padding: '8px 12px',
      border: '1px solid #e0e0e0',
      borderRadius: '4px',
      outline: 'none',
      '&:focus': {
        borderColor: '#1976d2',
      },
    },
    suggestions: {
      list: {
        backgroundColor: 'white',
        border: '1px solid #e0e0e0',
        borderRadius: '4px',
        fontSize: 14,
        overflow: 'auto',
        position: 'absolute',
        bottom: 14,
        maxHeight: 200,
        boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
      },
      item: {
        padding: '8px 12px',
        borderBottom: '1px solid #f0f0f0',
        cursor: 'pointer',
        '&focused': {
          backgroundColor: '#f5f5f5',
        },
      },
    },
  };

  const currentlyTyping = Object.values(typing)
    .filter(t => t.location === `${entityType}:${entityId}` && t.userId !== currentUser?.id)
    .map(t => activeUsers.find(u => u.id === t.userId)?.name)
    .filter(Boolean);

  if (compact && !expanded) {
    return (
      <Box sx={{ position: 'relative' }}>
        <Badge badgeContent={unresolvedCount} color="primary">
          <IconButton onClick={() => setExpanded(true)} size="small">
            <CommentIcon />
          </IconButton>
        </Badge>
      </Box>
    );
  }

  return (
    <Paper sx={{ p: 2, maxHeight: compact ? 400 : 600, overflowY: 'auto' }}>
      {compact && (
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="subtitle2">
            Comments ({comments.length})
          </Typography>
          <IconButton onClick={() => setExpanded(false)} size="small">
            <ExpandLessIcon />
          </IconButton>
        </Box>
      )}

      <Box sx={{ mb: 2 }}>
        {comments.length === 0 ? (
          <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 3 }}>
            No comments yet. Be the first to comment!
          </Typography>
        ) : (
          comments.map((comment) => (
            <Box key={comment.id} sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', gap: 1.5 }}>
                <Avatar
                  src={comment.user.avatar}
                  sx={{ width: 32, height: 32, bgcolor: comment.user.color }}
                >
                  {!comment.user.avatar && comment.user.name[0].toUpperCase()}
                </Avatar>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                    <Typography variant="subtitle2">{comment.user.name}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {format(new Date(comment.createdAt), 'MMM d, h:mm a')}
                    </Typography>
                    {comment.resolved && (
                      <Chip
                        label="Resolved"
                        size="small"
                        icon={<CheckCircleIcon />}
                        color="success"
                        variant="outlined"
                      />
                    )}
                    {comment.userId === currentUser?.id && (
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          setAnchorEl(e.currentTarget);
                          setSelectedComment(comment.id);
                        }}
                      >
                        <MoreVertIcon fontSize="small" />
                      </IconButton>
                    )}
                  </Box>
                  {editingComment === comment.id ? (
                    <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-end' }}>
                      <TextField
                        fullWidth
                        size="small"
                        value={editContent}
                        onChange={(e) => setEditContent(e.target.value)}
                        onKeyPress={(e) => {
                          if (e.key === 'Enter' && !e.shiftKey) {
                            // Handle edit save
                            setEditingComment(null);
                          }
                        }}
                      />
                      <Button size="small" onClick={() => setEditingComment(null)}>
                        Cancel
                      </Button>
                      <Button
                        size="small"
                        variant="contained"
                        onClick={() => {
                          // Handle edit save
                          setEditingComment(null);
                        }}
                      >
                        Save
                      </Button>
                    </Box>
                  ) : (
                    <>
                      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                        {comment.content}
                      </Typography>
                      {comment.mentions.length > 0 && (
                        <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5 }}>
                          {comment.mentions.map((userId) => {
                            const user = activeUsers.find(u => u.id === userId);
                            return user ? (
                              <Chip
                                key={userId}
                                label={`@${user.name}`}
                                size="small"
                                variant="outlined"
                                sx={{ height: 20, fontSize: 11 }}
                              />
                            ) : null;
                          })}
                        </Box>
                      )}
                      <Button
                        size="small"
                        startIcon={<ReplyIcon />}
                        onClick={() => setReplyingTo(comment.id)}
                        sx={{ mt: 0.5 }}
                      >
                        Reply
                      </Button>
                    </>
                  )}
                </Box>
              </Box>
              {comment.parentId && (
                <Box sx={{ ml: 6, mt: 1, pl: 2, borderLeft: '2px solid #e0e0e0' }}>
                  <Typography variant="caption" color="text.secondary">
                    Replying to thread
                  </Typography>
                </Box>
              )}
            </Box>
          ))
        )}
      </Box>

      <Divider sx={{ my: 2 }} />

      {currentlyTyping.length > 0 && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 1 }}>
          {currentlyTyping.join(', ')} {currentlyTyping.length === 1 ? 'is' : 'are'} typing...
        </Typography>
      )}

      {replyingTo && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <ReplyIcon fontSize="small" color="action" />
          <Typography variant="caption" color="text.secondary">
            Replying to comment
          </Typography>
          <IconButton size="small" onClick={() => setReplyingTo(null)}>
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Box>
      )}

      <Box sx={{ display: 'flex', gap: 1 }}>
        <MentionsInput
          value={newComment}
          onChange={(e) => {
            setNewComment(e.target.value);
            if (!isTyping && e.target.value) {
              setIsTyping(true);
            }
          }}
          style={mentionStyle}
          placeholder="Add a comment... Use @ to mention team members"
          onKeyPress={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              handleCommentSubmit();
            }
          }}
        >
          <Mention
            trigger="@"
            data={activeUsers.map(user => ({
              id: user.id,
              display: user.name,
            }))}
            style={{
              backgroundColor: '#e3f2fd',
              borderRadius: '3px',
              padding: '0 2px',
            }}
          />
        </MentionsInput>
        <IconButton
          color="primary"
          onClick={handleCommentSubmit}
          disabled={!newComment.trim()}
        >
          <SendIcon />
        </IconButton>
      </Box>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
      >
        <MenuItem onClick={() => handleEdit(comments.find(c => c.id === selectedComment)!)}>
          <EditIcon fontSize="small" sx={{ mr: 1 }} />
          Edit
        </MenuItem>
        <MenuItem onClick={() => handleResolve(selectedComment!)}>
          <CheckCircleIcon fontSize="small" sx={{ mr: 1 }} />
          Mark as Resolved
        </MenuItem>
        <MenuItem onClick={() => handleDelete(selectedComment!)}>
          <DeleteIcon fontSize="small" sx={{ mr: 1 }} />
          Delete
        </MenuItem>
      </Menu>
    </Paper>
  );
};

export default CommentSystem;