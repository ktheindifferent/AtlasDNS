import React, { useState } from 'react';
import {
  Tooltip,
  IconButton,
  Popover,
  Box,
  Typography,
  Link,
  Button,
  Divider,
} from '@mui/material';
import {
  Help as HelpIcon,
  PlayCircleOutline as VideoIcon,
  MenuBook as DocsIcon,
  Lightbulb as TipIcon,
} from '@mui/icons-material';

interface HelpContent {
  title: string;
  description: string;
  tips?: string[];
  videoUrl?: string;
  docsUrl?: string;
  examples?: { label: string; value: string }[];
}

interface HelpTooltipProps {
  content: HelpContent;
  size?: 'small' | 'medium' | 'large';
  placement?: 'top' | 'bottom' | 'left' | 'right';
  interactive?: boolean;
}

const HelpTooltip: React.FC<HelpTooltipProps> = ({
  content,
  size = 'small',
  placement = 'right',
  interactive = false,
}) => {
  const [anchorEl, setAnchorEl] = useState<HTMLButtonElement | null>(null);

  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    if (interactive) {
      setAnchorEl(event.currentTarget);
    }
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const open = Boolean(anchorEl);

  const tooltipContent = (
    <Box sx={{ maxWidth: 300 }}>
      <Typography variant="subtitle2" sx={{ fontWeight: 'bold', mb: 1 }}>
        {content.title}
      </Typography>
      <Typography variant="body2">
        {content.description}
      </Typography>
      {content.tips && content.tips.length > 0 && (
        <Box sx={{ mt: 1 }}>
          <Typography variant="caption" sx={{ fontWeight: 'bold' }}>
            Quick Tips:
          </Typography>
          <ul style={{ margin: 0, paddingLeft: 20 }}>
            {content.tips.map((tip, index) => (
              <li key={index}>
                <Typography variant="caption">{tip}</Typography>
              </li>
            ))}
          </ul>
        </Box>
      )}
    </Box>
  );

  const popoverContent = (
    <Box sx={{ p: 2, maxWidth: 400 }}>
      <Typography variant="h6" sx={{ mb: 1 }}>
        {content.title}
      </Typography>
      
      <Typography variant="body2" sx={{ mb: 2 }}>
        {content.description}
      </Typography>

      {content.tips && content.tips.length > 0 && (
        <>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
            <TipIcon fontSize="small" sx={{ mr: 1, color: 'warning.main' }} />
            <Typography variant="subtitle2">Tips & Best Practices</Typography>
          </Box>
          <Box sx={{ pl: 3, mb: 2 }}>
            {content.tips.map((tip, index) => (
              <Typography key={index} variant="body2" sx={{ mb: 0.5 }}>
                • {tip}
              </Typography>
            ))}
          </Box>
        </>
      )}

      {content.examples && content.examples.length > 0 && (
        <>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Examples:
          </Typography>
          <Box sx={{ pl: 2, mb: 2 }}>
            {content.examples.map((example, index) => (
              <Box key={index} sx={{ mb: 1 }}>
                <Typography variant="caption" color="text.secondary">
                  {example.label}:
                </Typography>
                <Typography
                  variant="body2"
                  sx={{
                    fontFamily: 'monospace',
                    backgroundColor: 'grey.100',
                    p: 0.5,
                    borderRadius: 1,
                  }}
                >
                  {example.value}
                </Typography>
              </Box>
            ))}
          </Box>
        </>
      )}

      {(content.videoUrl || content.docsUrl) && (
        <>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: 'flex', gap: 1 }}>
            {content.videoUrl && (
              <Button
                size="small"
                startIcon={<VideoIcon />}
                href={content.videoUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                Watch Video
              </Button>
            )}
            {content.docsUrl && (
              <Button
                size="small"
                startIcon={<DocsIcon />}
                href={content.docsUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                View Docs
              </Button>
            )}
          </Box>
        </>
      )}
    </Box>
  );

  return (
    <>
      {interactive ? (
        <>
          <IconButton size={size} onClick={handleClick}>
            <HelpIcon fontSize={size} />
          </IconButton>
          <Popover
            open={open}
            anchorEl={anchorEl}
            onClose={handleClose}
            anchorOrigin={{
              vertical: 'bottom',
              horizontal: 'left',
            }}
            transformOrigin={{
              vertical: 'top',
              horizontal: 'left',
            }}
          >
            {popoverContent}
          </Popover>
        </>
      ) : (
        <Tooltip title={tooltipContent} placement={placement} arrow>
          <IconButton size={size}>
            <HelpIcon fontSize={size} />
          </IconButton>
        </Tooltip>
      )}
    </>
  );
};

export default HelpTooltip;

// Pre-configured help content for common DNS concepts
export const helpContent = {
  aRecord: {
    title: 'A Record',
    description: 'Maps a domain name to an IPv4 address (e.g., 192.0.2.1)',
    tips: [
      'Use for pointing domains to web servers',
      'Can have multiple A records for load balancing',
      'TTL affects how long the record is cached',
    ],
    examples: [
      { label: 'Website', value: 'www.example.com → 192.0.2.1' },
      { label: 'Subdomain', value: 'api.example.com → 192.0.2.2' },
    ],
  },
  aaaaRecord: {
    title: 'AAAA Record',
    description: 'Maps a domain name to an IPv6 address',
    tips: [
      'IPv6 equivalent of A record',
      'Required for IPv6 connectivity',
      'Can coexist with A records',
    ],
    examples: [
      { label: 'IPv6', value: 'www.example.com → 2001:db8::1' },
    ],
  },
  cnameRecord: {
    title: 'CNAME Record',
    description: 'Creates an alias from one domain name to another',
    tips: [
      'Cannot be used at the zone apex',
      'Cannot coexist with other records of the same name',
      'Useful for pointing multiple subdomains to the same location',
    ],
    examples: [
      { label: 'Alias', value: 'blog.example.com → www.example.com' },
    ],
  },
  mxRecord: {
    title: 'MX Record',
    description: 'Specifies mail servers for a domain',
    tips: [
      'Priority value determines server preference (lower = higher priority)',
      'Multiple MX records provide redundancy',
      'Points to A or AAAA records, not IP addresses',
    ],
    examples: [
      { label: 'Primary', value: '10 mail.example.com' },
      { label: 'Backup', value: '20 mail2.example.com' },
    ],
  },
  txtRecord: {
    title: 'TXT Record',
    description: 'Stores text information for various purposes',
    tips: [
      'Used for SPF, DKIM, domain verification',
      'Can contain multiple strings',
      'Maximum 255 characters per string',
    ],
    examples: [
      { label: 'SPF', value: 'v=spf1 include:_spf.google.com ~all' },
      { label: 'Verification', value: 'google-site-verification=...' },
    ],
  },
  nsRecord: {
    title: 'NS Record',
    description: 'Delegates a subdomain to a set of name servers',
    tips: [
      'Required for zone delegation',
      'At least 2 NS records recommended',
      'Points to hostnames, not IP addresses',
    ],
    examples: [
      { label: 'Delegation', value: 'sub.example.com → ns1.provider.com' },
    ],
  },
  ttl: {
    title: 'TTL (Time To Live)',
    description: 'How long DNS resolvers should cache the record (in seconds)',
    tips: [
      'Lower TTL = faster propagation but more DNS queries',
      'Higher TTL = better performance but slower updates',
      'Common values: 300 (5 min), 3600 (1 hour), 86400 (1 day)',
    ],
  },
  dnssec: {
    title: 'DNSSEC',
    description: 'Adds cryptographic signatures to DNS records for security',
    tips: [
      'Prevents DNS spoofing and cache poisoning',
      'Requires DS records at parent zone',
      'Increases DNS response size slightly',
    ],
  },
  geodns: {
    title: 'GeoDNS',
    description: 'Returns different DNS responses based on geographic location',
    tips: [
      'Improves performance by routing to nearest server',
      'Enables region-specific content delivery',
      'Requires geographic IP database',
    ],
  },
  caa: {
    title: 'CAA Record',
    description: 'Specifies which Certificate Authorities can issue SSL certificates',
    tips: [
      'Improves security by limiting certificate issuance',
      'Required by some compliance standards',
      'Can specify different CAs for wildcards',
    ],
    examples: [
      { label: 'Allow', value: '0 issue "letsencrypt.org"' },
      { label: 'Wildcard', value: '0 issuewild "digicert.com"' },
    ],
  },
  ptr: {
    title: 'PTR Record',
    description: 'Maps IP addresses to domain names (reverse DNS)',
    tips: [
      'Important for email deliverability',
      'Must match forward DNS (A/AAAA record)',
      'Usually managed by IP address owner',
    ],
  },
  srv: {
    title: 'SRV Record',
    description: 'Specifies location of services',
    tips: [
      'Used for service discovery',
      'Includes port and priority information',
      'Common for VoIP, XMPP, etc.',
    ],
    examples: [
      { label: 'Format', value: '_service._proto.name TTL class SRV priority weight port target' },
    ],
  },
};