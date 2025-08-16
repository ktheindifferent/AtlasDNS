import React, { useState, useEffect } from 'react';
import { Box, TextField, Typography } from '@mui/material';
import { WidgetConfig } from '../types';

interface TextWidgetProps {
  config: WidgetConfig;
  onUpdate?: (updates: Partial<WidgetConfig>) => void;
}

const TextWidget: React.FC<TextWidgetProps> = ({ config, onUpdate }) => {
  const [text, setText] = useState(config.data?.text || '');
  const [isEditing, setIsEditing] = useState(false);

  useEffect(() => {
    if (config.data?.text !== undefined) {
      setText(config.data.text);
    }
  }, [config.data]);

  const handleSave = () => {
    onUpdate?.({ data: { text } });
    setIsEditing(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      setText(config.data?.text || '');
      setIsEditing(false);
    }
  };

  return (
    <Box sx={{ p: 2, height: '100%' }}>
      {isEditing && onUpdate ? (
        <TextField
          multiline
          fullWidth
          value={text}
          onChange={(e) => setText(e.target.value)}
          onBlur={handleSave}
          onKeyDown={handleKeyDown}
          variant="outlined"
          autoFocus
          placeholder="Enter your notes here..."
          sx={{ height: '100%' }}
          InputProps={{
            sx: { height: '100%', alignItems: 'flex-start' }
          }}
        />
      ) : (
        <Box 
          onClick={() => onUpdate && setIsEditing(true)}
          sx={{ 
            height: '100%',
            cursor: onUpdate ? 'text' : 'default',
            '&:hover': onUpdate ? {
              backgroundColor: 'action.hover',
              borderRadius: 1
            } : {}
          }}
        >
          {text ? (
            <Typography 
              variant="body1" 
              sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
            >
              {text}
            </Typography>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {onUpdate ? 'Click to add notes...' : 'No content'}
            </Typography>
          )}
        </Box>
      )}
    </Box>
  );
};

export default TextWidget;