import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  Typography,
  Alert,
  Stack,
  Chip,
  Paper,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Tooltip,
  Button,
} from '@mui/material';
import {
  Code,
  Check,
  Close,
  ContentCopy,
  HelpOutline,
} from '@mui/icons-material';

interface RegexFilterProps {
  value: string;
  onChange: (value: string) => void;
  testData?: string[];
}

const RegexFilter: React.FC<RegexFilterProps> = ({
  value,
  onChange,
  testData = [],
}) => {
  const [localValue, setLocalValue] = useState(value);
  const [isValid, setIsValid] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');
  const [matches, setMatches] = useState<string[]>([]);
  const [showHelp, setShowHelp] = useState(false);

  const commonPatterns = [
    { label: 'Email', pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$' },
    { label: 'IPv4', pattern: '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$' },
    { label: 'IPv6', pattern: '^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$' },
    { label: 'Domain', pattern: '^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$' },
    { label: 'Subdomain', pattern: '^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$' },
    { label: 'URL', pattern: '^https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&\\/\\/=]*)$' },
    { label: 'SPF Record', pattern: '^v=spf1\\s+.*' },
    { label: 'DKIM Record', pattern: '^v=DKIM1;.*' },
    { label: 'DMARC Record', pattern: '^v=DMARC1;.*' },
  ];

  useEffect(() => {
    validateRegex(localValue);
  }, [localValue, testData]);

  const validateRegex = (pattern: string) => {
    if (!pattern) {
      setIsValid(true);
      setErrorMessage('');
      setMatches([]);
      return;
    }

    try {
      const regex = new RegExp(pattern, 'gi');
      setIsValid(true);
      setErrorMessage('');
      
      // Test against sample data
      if (testData.length > 0) {
        const matchedData = testData.filter(item => regex.test(item));
        setMatches(matchedData);
      }
    } catch (error: any) {
      setIsValid(false);
      setErrorMessage(error.message);
      setMatches([]);
    }
  };

  const handleApply = () => {
    if (isValid) {
      onChange(localValue);
    }
  };

  const handlePatternSelect = (pattern: string) => {
    setLocalValue(pattern);
    validateRegex(pattern);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(localValue);
  };

  return (
    <Box>
      <Stack spacing={2}>
        <Box>
          <Typography variant="h6" gutterBottom display="flex" alignItems="center" gap={1}>
            <Code />
            Regular Expression Filter
          </Typography>
          
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Enter regular expression pattern..."
            value={localValue}
            onChange={(e) => setLocalValue(e.target.value)}
            error={!isValid}
            helperText={errorMessage}
            InputProps={{
              endAdornment: (
                <Box display="flex" alignItems="center">
                  {localValue && (
                    <>
                      {isValid ? (
                        <Check color="success" />
                      ) : (
                        <Close color="error" />
                      )}
                      <Tooltip title="Copy pattern">
                        <IconButton size="small" onClick={copyToClipboard}>
                          <ContentCopy />
                        </IconButton>
                      </Tooltip>
                    </>
                  )}
                  <Tooltip title="Help">
                    <IconButton size="small" onClick={() => setShowHelp(!showHelp)}>
                      <HelpOutline />
                    </IconButton>
                  </Tooltip>
                  <Button
                    variant="contained"
                    size="small"
                    onClick={handleApply}
                    disabled={!isValid || !localValue}
                    sx={{ ml: 1 }}
                  >
                    Apply
                  </Button>
                </Box>
              ),
            }}
          />
        </Box>

        {showHelp && (
          <Alert severity="info" onClose={() => setShowHelp(false)}>
            <Typography variant="subtitle2" gutterBottom>
              Regex Pattern Help
            </Typography>
            <Typography variant="caption" component="div">
              • <code>^</code> - Start of string<br />
              • <code>$</code> - End of string<br />
              • <code>.</code> - Any character<br />
              • <code>*</code> - Zero or more<br />
              • <code>+</code> - One or more<br />
              • <code>?</code> - Zero or one<br />
              • <code>[abc]</code> - Character class<br />
              • <code>(abc)</code> - Capturing group<br />
              • <code>\d</code> - Digit<br />
              • <code>\w</code> - Word character<br />
              • <code>\s</code> - Whitespace<br />
            </Typography>
          </Alert>
        )}

        <Box>
          <Typography variant="subtitle2" gutterBottom>
            Common Patterns
          </Typography>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {commonPatterns.map((pattern) => (
              <Chip
                key={pattern.label}
                label={pattern.label}
                onClick={() => handlePatternSelect(pattern.pattern)}
                variant="outlined"
                size="small"
                sx={{ 
                  mb: 1,
                  cursor: 'pointer',
                  '&:hover': {
                    backgroundColor: 'primary.main',
                    color: 'white',
                    borderColor: 'primary.main',
                  }
                }}
              />
            ))}
          </Stack>
        </Box>

        {localValue && isValid && testData.length > 0 && (
          <Paper elevation={1} sx={{ p: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              Test Results ({matches.length} matches)
            </Typography>
            {matches.length > 0 ? (
              <List dense sx={{ maxHeight: 200, overflow: 'auto' }}>
                {matches.slice(0, 10).map((match, index) => (
                  <ListItem key={index}>
                    <ListItemText 
                      primary={match}
                      primaryTypographyProps={{ variant: 'body2' }}
                    />
                  </ListItem>
                ))}
                {matches.length > 10 && (
                  <ListItem>
                    <ListItemText 
                      primary={`... and ${matches.length - 10} more`}
                      primaryTypographyProps={{ 
                        variant: 'caption',
                        color: 'textSecondary'
                      }}
                    />
                  </ListItem>
                )}
              </List>
            ) : (
              <Typography variant="body2" color="textSecondary">
                No matches found in test data
              </Typography>
            )}
          </Paper>
        )}
      </Stack>
    </Box>
  );
};

export default RegexFilter;