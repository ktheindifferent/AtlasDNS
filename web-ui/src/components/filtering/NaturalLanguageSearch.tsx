import React, { useState, useCallback, useEffect } from 'react';
import {
  Box,
  TextField,
  Button,
  Typography,
  Chip,
  Stack,
  Paper,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Tooltip,
  Alert,
} from '@mui/material';
import {
  Search,
  AutoAwesome,
  History,
  Clear,
  HelpOutline,
} from '@mui/icons-material';
import { parseDate } from 'chrono-node';
import Fuse from 'fuse.js';
import { RuleGroupType } from 'react-querybuilder';

interface NaturalLanguageSearchProps {
  value: string;
  onChange: (value: string) => void;
  onQueryParse?: (query: RuleGroupType) => void;
  suggestions?: string[];
}

const NaturalLanguageSearch: React.FC<NaturalLanguageSearchProps> = ({
  value,
  onChange,
  onQueryParse,
  suggestions = [],
}) => {
  const [localValue, setLocalValue] = useState(value);
  const [parsedQuery, setParsedQuery] = useState<RuleGroupType | null>(null);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [filteredSuggestions, setFilteredSuggestions] = useState<string[]>([]);
  const [showHelp, setShowHelp] = useState(false);

  const exampleQueries = [
    'show all A records from last week',
    'find CNAME records created in the last 24 hours',
    'get MX records with priority less than 10',
    'display TXT records containing SPF',
    'show records modified today with TTL greater than 3600',
    'find all records for domain example.com',
    'show NS records excluding cloudflare',
    'get records created between January 1 and March 31',
  ];

  useEffect(() => {
    if (localValue && suggestions.length > 0) {
      const fuse = new Fuse(suggestions, {
        threshold: 0.3,
        includeScore: true,
      });
      const results = fuse.search(localValue);
      setFilteredSuggestions(results.slice(0, 5).map(r => r.item));
    } else {
      setFilteredSuggestions([]);
    }
  }, [localValue, suggestions]);

  const parseNaturalLanguage = useCallback((text: string) => {
    const query: RuleGroupType = {
      combinator: 'and',
      rules: [],
    };

    // Parse record types
    const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR', 'SRV', 'CAA'];
    recordTypes.forEach(type => {
      const regex = new RegExp(`\\b${type}\\s+records?\\b`, 'i');
      if (regex.test(text)) {
        query.rules.push({
          field: 'type',
          operator: '=',
          value: type,
        });
      }
    });

    // Parse time ranges
    const timePatterns = [
      { pattern: /last\s+(\d+)\s+hours?/i, unit: 'hours' },
      { pattern: /last\s+(\d+)\s+days?/i, unit: 'days' },
      { pattern: /last\s+week/i, unit: 'week', value: 7 },
      { pattern: /last\s+month/i, unit: 'month', value: 30 },
      { pattern: /today/i, unit: 'today', value: 0 },
      { pattern: /yesterday/i, unit: 'yesterday', value: 1 },
    ];

    timePatterns.forEach(({ pattern, unit, value: fixedValue }) => {
      const match = text.match(pattern);
      if (match) {
        const amount = fixedValue || parseInt(match[1]);
        const date = new Date();
        
        if (unit === 'hours') {
          date.setHours(date.getHours() - amount);
        } else if (unit === 'days' || unit === 'yesterday') {
          date.setDate(date.getDate() - amount);
        } else if (unit === 'week') {
          date.setDate(date.getDate() - 7);
        } else if (unit === 'month') {
          date.setDate(date.getDate() - 30);
        } else if (unit === 'today') {
          date.setHours(0, 0, 0, 0);
        }

        query.rules.push({
          field: 'createdAt',
          operator: '>=',
          value: date.toISOString(),
        });
      }
    });

    // Parse date ranges using chrono-node
    const parsedDates = parseDate(text);
    if (parsedDates) {
      query.rules.push({
        field: 'createdAt',
        operator: '>=',
        value: parsedDates.toISOString(),
      });
    }

    // Parse TTL conditions
    const ttlMatch = text.match(/TTL\s*(>|<|>=|<=|=)?\s*(\d+)/i);
    if (ttlMatch) {
      query.rules.push({
        field: 'ttl',
        operator: ttlMatch[1] || '=',
        value: parseInt(ttlMatch[2]),
      });
    }

    // Parse priority conditions (for MX records)
    const priorityMatch = text.match(/priority\s*(>|<|>=|<=|=)?\s*(\d+)/i);
    if (priorityMatch) {
      query.rules.push({
        field: 'priority',
        operator: priorityMatch[1] || '=',
        value: parseInt(priorityMatch[2]),
      });
    }

    // Parse domain/name conditions
    const domainMatch = text.match(/(?:domain|name|for)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/i);
    if (domainMatch) {
      query.rules.push({
        field: 'name',
        operator: 'contains',
        value: domainMatch[1],
      });
    }

    // Parse containing/excluding conditions
    const containingMatch = text.match(/containing\s+"?([^"]+)"?/i);
    if (containingMatch) {
      query.rules.push({
        field: 'value',
        operator: 'contains',
        value: containingMatch[1].replace(/"/g, ''),
      });
    }

    const excludingMatch = text.match(/excluding\s+"?([^"]+)"?/i);
    if (excludingMatch) {
      query.rules.push({
        field: 'value',
        operator: 'doesNotContain',
        value: excludingMatch[1].replace(/"/g, ''),
      });
    }

    // Parse status conditions
    if (/\bactive\b/i.test(text)) {
      query.rules.push({
        field: 'enabled',
        operator: '=',
        value: true,
      });
    }
    if (/\binactive\b/i.test(text)) {
      query.rules.push({
        field: 'enabled',
        operator: '=',
        value: false,
      });
    }

    // Parse logical operators
    if (/\b(and|&&)\b/i.test(text)) {
      query.combinator = 'and';
    } else if (/\b(or|\|\|)\b/i.test(text)) {
      query.combinator = 'or';
    }

    return query;
  }, []);

  const handleSearch = () => {
    const parsed = parseNaturalLanguage(localValue);
    setParsedQuery(parsed);
    if (onQueryParse) {
      onQueryParse(parsed);
    }
    onChange(localValue);
    setShowSuggestions(false);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  const handleSuggestionClick = (suggestion: string) => {
    setLocalValue(suggestion);
    setShowSuggestions(false);
    const parsed = parseNaturalLanguage(suggestion);
    setParsedQuery(parsed);
    if (onQueryParse) {
      onQueryParse(parsed);
    }
    onChange(suggestion);
  };

  return (
    <Box>
      <Stack spacing={2}>
        <Box position="relative">
          <TextField
            fullWidth
            variant="outlined"
            placeholder="e.g., 'show all A records from last week' or 'find MX records with priority less than 10'"
            value={localValue}
            onChange={(e) => {
              setLocalValue(e.target.value);
              setShowSuggestions(true);
            }}
            onKeyPress={handleKeyPress}
            onFocus={() => setShowSuggestions(true)}
            InputProps={{
              startAdornment: <AutoAwesome sx={{ mr: 1, color: 'primary.main' }} />,
              endAdornment: (
                <Box display="flex" alignItems="center">
                  {localValue && (
                    <IconButton size="small" onClick={() => setLocalValue('')}>
                      <Clear />
                    </IconButton>
                  )}
                  <Tooltip title="Help">
                    <IconButton size="small" onClick={() => setShowHelp(!showHelp)}>
                      <HelpOutline />
                    </IconButton>
                  </Tooltip>
                  <Button
                    variant="contained"
                    size="small"
                    onClick={handleSearch}
                    startIcon={<Search />}
                    sx={{ ml: 1 }}
                  >
                    Search
                  </Button>
                </Box>
              ),
            }}
          />
          
          {showSuggestions && filteredSuggestions.length > 0 && (
            <Paper
              elevation={3}
              sx={{
                position: 'absolute',
                top: '100%',
                left: 0,
                right: 0,
                zIndex: 1000,
                mt: 0.5,
                maxHeight: 200,
                overflow: 'auto',
              }}
            >
              <List dense>
                {filteredSuggestions.map((suggestion, index) => (
                  <ListItem
                    key={index}
                    button
                    onClick={() => handleSuggestionClick(suggestion)}
                  >
                    <History sx={{ mr: 1, fontSize: 18 }} />
                    <ListItemText primary={suggestion} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </Box>

        {showHelp && (
          <Alert severity="info" onClose={() => setShowHelp(false)}>
            <Typography variant="subtitle2" gutterBottom>
              Natural Language Search Examples:
            </Typography>
            <Stack spacing={0.5}>
              {exampleQueries.map((example, index) => (
                <Typography
                  key={index}
                  variant="caption"
                  sx={{ cursor: 'pointer', '&:hover': { color: 'primary.main' } }}
                  onClick={() => setLocalValue(example)}
                >
                  • {example}
                </Typography>
              ))}
            </Stack>
          </Alert>
        )}

        {parsedQuery && parsedQuery.rules.length > 0 && (
          <Box>
            <Typography variant="caption" color="textSecondary" gutterBottom>
              Parsed Query:
            </Typography>
            <Stack direction="row" spacing={1} flexWrap="wrap">
              {parsedQuery.rules.map((rule: any, index) => (
                <Chip
                  key={index}
                  label={`${rule.field} ${rule.operator} ${rule.value}`}
                  size="small"
                  color="primary"
                  variant="outlined"
                />
              ))}
            </Stack>
          </Box>
        )}
      </Stack>
    </Box>
  );
};

export default NaturalLanguageSearch;