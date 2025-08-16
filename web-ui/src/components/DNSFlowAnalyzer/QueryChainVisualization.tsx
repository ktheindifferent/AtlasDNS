import React, { useRef, useEffect, useState } from 'react';
import { Box, Paper, Typography, Card, CardContent, Chip, List, ListItem, ListItemText, Divider } from '@mui/material';
import * as d3 from 'd3';
import { DNSQuery, DNSNode } from './types';
import { AccessTime, Speed, CheckCircle, Error, Cached, Block } from '@mui/icons-material';

interface QueryChainVisualizationProps {
  queries: DNSQuery[];
  selectedQuery: DNSQuery | null;
}

const QueryChainVisualization: React.FC<QueryChainVisualizationProps> = ({ queries, selectedQuery }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height: 400 });

  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height: 400,
        });
      }
    };

    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    if (!svgRef.current || !selectedQuery || dimensions.width === 0) return;

    const margin = { top: 40, right: 40, bottom: 40, left: 40 };
    const innerWidth = dimensions.width - margin.left - margin.right;
    const innerHeight = dimensions.height - margin.top - margin.bottom;

    // Clear previous content
    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', dimensions.width)
      .attr('height', dimensions.height);

    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Build the chain from the selected query
    const chain: (DNSNode & { isSource?: boolean; isDestination?: boolean })[] = [];
    
    // Add source
    chain.push({
      id: selectedQuery.source,
      name: selectedQuery.source,
      type: 'client',
      ip: selectedQuery.source,
      latency: 0,
      timestamp: selectedQuery.timestamp,
      isSource: true,
    });

    // Add path nodes
    if (selectedQuery.path) {
      chain.push(...selectedQuery.path);
    }

    // Add destination
    chain.push({
      id: selectedQuery.destination,
      name: selectedQuery.destination,
      type: 'authoritative',
      ip: selectedQuery.destination,
      latency: selectedQuery.latency,
      timestamp: selectedQuery.timestamp,
      isDestination: true,
    });

    // Calculate positions
    const nodeWidth = 120;
    const nodeHeight = 60;
    const nodeSpacing = (innerWidth - nodeWidth) / Math.max(1, chain.length - 1);

    // Create arrow marker
    svg.append('defs').append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 10)
      .attr('refY', 0)
      .attr('markerWidth', 5)
      .attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#666');

    // Draw connections
    for (let i = 0; i < chain.length - 1; i++) {
      const x1 = i * nodeSpacing + nodeWidth / 2;
      const x2 = (i + 1) * nodeSpacing + nodeWidth / 2;
      const y = innerHeight / 2;

      // Draw connection line
      g.append('line')
        .attr('x1', x1 + nodeWidth / 2)
        .attr('y1', y)
        .attr('x2', x2 - nodeWidth / 2 - 10)
        .attr('y2', y)
        .attr('stroke', '#666')
        .attr('stroke-width', 2)
        .attr('marker-end', 'url(#arrowhead)');

      // Add latency label
      const latency = chain[i + 1].latency - chain[i].latency;
      g.append('text')
        .attr('x', (x1 + x2) / 2)
        .attr('y', y - 10)
        .attr('text-anchor', 'middle')
        .attr('font-size', '11px')
        .attr('fill', latency > 100 ? '#f44336' : '#4caf50')
        .text(`${latency.toFixed(1)}ms`);
    }

    // Draw nodes
    const nodes = g.selectAll('.node')
      .data(chain)
      .enter().append('g')
      .attr('class', 'node')
      .attr('transform', (d, i) => `translate(${i * nodeSpacing},${innerHeight / 2 - nodeHeight / 2})`);

    // Node rectangles
    nodes.append('rect')
      .attr('width', nodeWidth)
      .attr('height', nodeHeight)
      .attr('rx', 5)
      .attr('fill', d => {
        switch (d.type) {
          case 'client': return '#4fc3f7';
          case 'resolver': return '#ffa726';
          case 'authoritative': return '#66bb6a';
          case 'cache': return '#ab47bc';
          case 'forwarder': return '#ef5350';
          default: return '#757575';
        }
      })
      .attr('stroke', '#333')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .on('mouseover', function(event, d) {
        d3.select(this)
          .attr('stroke-width', 3)
          .attr('stroke', '#000');
        setHoveredNode(d.id);
      })
      .on('mouseout', function() {
        d3.select(this)
          .attr('stroke-width', 2)
          .attr('stroke', '#333');
        setHoveredNode(null);
      });

    // Node icons
    nodes.append('text')
      .attr('x', nodeWidth / 2)
      .attr('y', 20)
      .attr('text-anchor', 'middle')
      .attr('font-size', '16px')
      .attr('fill', 'white')
      .text(d => {
        switch (d.type) {
          case 'client': return '💻';
          case 'resolver': return '🔄';
          case 'authoritative': return '🏛️';
          case 'cache': return '💾';
          case 'forwarder': return '➡️';
          default: return '📡';
        }
      });

    // Node labels
    nodes.append('text')
      .attr('x', nodeWidth / 2)
      .attr('y', 40)
      .attr('text-anchor', 'middle')
      .attr('font-size', '11px')
      .attr('fill', 'white')
      .text(d => d.name.substring(0, 15));

    // Node type labels
    nodes.append('text')
      .attr('x', nodeWidth / 2)
      .attr('y', nodeHeight + 15)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px')
      .attr('fill', '#666')
      .text(d => d.type.toUpperCase());

    // Add total latency indicator
    svg.append('text')
      .attr('x', dimensions.width / 2)
      .attr('y', 20)
      .attr('text-anchor', 'middle')
      .attr('font-size', '14px')
      .attr('font-weight', 'bold')
      .text(`Total Query Time: ${selectedQuery.latency}ms`);

    // Draw timeline at the bottom
    const timeScale = d3.scaleLinear()
      .domain([0, selectedQuery.latency])
      .range([margin.left, innerWidth + margin.left]);

    const timeAxis = d3.axisBottom(timeScale)
      .tickFormat(d => `${d}ms`);

    svg.append('g')
      .attr('transform', `translate(0,${dimensions.height - 20})`)
      .call(timeAxis);

    // Add cumulative latency markers
    let cumulativeLatency = 0;
    chain.forEach((node, i) => {
      if (i > 0) {
        cumulativeLatency += node.latency - chain[i - 1].latency;
        svg.append('line')
          .attr('x1', timeScale(cumulativeLatency))
          .attr('y1', dimensions.height - 20)
          .attr('x2', timeScale(cumulativeLatency))
          .attr('y2', dimensions.height - 30)
          .attr('stroke', '#999')
          .attr('stroke-width', 1)
          .attr('stroke-dasharray', '2,2');
      }
    });

  }, [selectedQuery, dimensions]);

  const getStatusIcon = (query: DNSQuery) => {
    if (query.blocked) return <Block color="error" />;
    if (query.cached) return <Cached color="info" />;
    if (query.responseCode === 'NOERROR') return <CheckCircle color="success" />;
    return <Error color="error" />;
  };

  const getLatencyColor = (latency: number) => {
    if (latency < 50) return 'success.main';
    if (latency < 150) return 'warning.main';
    return 'error.main';
  };

  return (
    <Box sx={{ width: '100%', height: '100%', display: 'flex', gap: 2 }}>
      <Paper sx={{ flex: 2, p: 2, overflow: 'auto' }}>
        <Typography variant="h6" gutterBottom>
          DNS Query Chain
        </Typography>
        {selectedQuery ? (
          <>
            <Box sx={{ mb: 2, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
              <Chip
                icon={getStatusIcon(selectedQuery)}
                label={selectedQuery.responseCode}
                size="small"
                color={selectedQuery.responseCode === 'NOERROR' ? 'success' : 'error'}
              />
              <Chip
                icon={<AccessTime />}
                label={`${selectedQuery.latency}ms`}
                size="small"
                sx={{ color: getLatencyColor(selectedQuery.latency) }}
              />
              <Chip
                label={selectedQuery.queryType}
                size="small"
                variant="outlined"
              />
              {selectedQuery.cached && (
                <Chip label="Cached" size="small" color="info" variant="outlined" />
              )}
              {selectedQuery.anomaly && (
                <Chip label="Anomaly" size="small" color="error" />
              )}
            </Box>
            <Box ref={containerRef} sx={{ width: '100%', height: dimensions.height }}>
              <svg ref={svgRef} />
            </Box>
          </>
        ) : (
          <Typography color="textSecondary">
            Select a query to visualize its resolution chain
          </Typography>
        )}
      </Paper>

      <Paper sx={{ flex: 1, p: 2, overflow: 'auto' }}>
        <Typography variant="h6" gutterBottom>
          Recent Queries
        </Typography>
        <List dense>
          {queries.slice(-10).reverse().map((query, index) => (
            <React.Fragment key={query.id}>
              <ListItem
                button
                selected={selectedQuery?.id === query.id}
                onClick={() => {/* Handle selection */}}
                sx={{
                  borderLeft: 3,
                  borderColor: query.anomaly ? 'error.main' : 'transparent',
                }}
              >
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      {getStatusIcon(query)}
                      <Typography variant="body2" noWrap>
                        {query.queryName}
                      </Typography>
                    </Box>
                  }
                  secondary={
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="caption" color="textSecondary">
                        {query.queryType}
                      </Typography>
                      <Typography 
                        variant="caption" 
                        sx={{ color: getLatencyColor(query.latency) }}
                      >
                        {query.latency}ms
                      </Typography>
                    </Box>
                  }
                />
              </ListItem>
              {index < queries.length - 1 && <Divider />}
            </React.Fragment>
          ))}
        </List>
      </Paper>
    </Box>
  );
};

export default QueryChainVisualization;