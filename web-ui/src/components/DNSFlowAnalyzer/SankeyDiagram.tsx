import React, { useRef, useEffect } from 'react';
import { Box, Paper, Typography, Tooltip } from '@mui/material';
import * as d3 from 'd3';
import { sankey, sankeyLinkHorizontal, SankeyNode as D3SankeyNode, SankeyLink as D3SankeyLink } from 'd3-sankey';
import { DNSQuery, SankeyNode, SankeyLink } from './types';

interface SankeyDiagramProps {
  queries: DNSQuery[];
  height?: number;
}

interface ProcessedNode extends D3SankeyNode<SankeyNode, SankeyLink> {
  id: string;
  name: string;
  group: number;
  value: number;
}

interface ProcessedLink extends D3SankeyLink<ProcessedNode, SankeyLink> {
  queries: number;
}

const SankeyDiagram: React.FC<SankeyDiagramProps> = ({ queries, height = 600 }) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current || queries.length === 0) return;

    const width = containerRef.current.clientWidth;
    const margin = { top: 10, right: 150, bottom: 10, left: 150 };
    const innerWidth = width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    // Clear previous content
    d3.select(svgRef.current).selectAll('*').remove();

    // Process data for Sankey diagram
    const nodeMap = new Map<string, ProcessedNode>();
    const linkMap = new Map<string, ProcessedLink>();

    // Create nodes from queries
    queries.forEach(query => {
      // Source node
      if (!nodeMap.has(query.source)) {
        nodeMap.set(query.source, {
          id: query.source,
          name: query.source,
          group: 0,
          value: 0,
        } as ProcessedNode);
      }

      // Query type as intermediate node
      const queryTypeNode = `type_${query.queryType}`;
      if (!nodeMap.has(queryTypeNode)) {
        nodeMap.set(queryTypeNode, {
          id: queryTypeNode,
          name: query.queryType,
          group: 1,
          value: 0,
        } as ProcessedNode);
      }

      // Response code as intermediate node
      const responseNode = `response_${query.responseCode}`;
      if (!nodeMap.has(responseNode)) {
        nodeMap.set(responseNode, {
          id: responseNode,
          name: query.responseCode,
          group: 2,
          value: 0,
        } as ProcessedNode);
      }

      // Destination node
      if (!nodeMap.has(query.destination)) {
        nodeMap.set(query.destination, {
          id: query.destination,
          name: query.destination,
          group: 3,
          value: 0,
        } as ProcessedNode);
      }

      // Create links
      const link1Key = `${query.source}-${queryTypeNode}`;
      if (!linkMap.has(link1Key)) {
        linkMap.set(link1Key, {
          source: query.source,
          target: queryTypeNode,
          value: 0,
          queries: 0,
        } as ProcessedLink);
      }
      const link1 = linkMap.get(link1Key)!;
      link1.value += 1;
      link1.queries += 1;

      const link2Key = `${queryTypeNode}-${responseNode}`;
      if (!linkMap.has(link2Key)) {
        linkMap.set(link2Key, {
          source: queryTypeNode,
          target: responseNode,
          value: 0,
          queries: 0,
        } as ProcessedLink);
      }
      const link2 = linkMap.get(link2Key)!;
      link2.value += 1;
      link2.queries += 1;

      const link3Key = `${responseNode}-${query.destination}`;
      if (!linkMap.has(link3Key)) {
        linkMap.set(link3Key, {
          source: responseNode,
          target: query.destination,
          value: 0,
          queries: 0,
        } as ProcessedLink);
      }
      const link3 = linkMap.get(link3Key)!;
      link3.value += 1;
      link3.queries += 1;

      // Update node values
      nodeMap.get(query.source)!.value += 1;
      nodeMap.get(queryTypeNode)!.value += 1;
      nodeMap.get(responseNode)!.value += 1;
      nodeMap.get(query.destination)!.value += 1;
    });

    const nodes = Array.from(nodeMap.values());
    const links = Array.from(linkMap.values());

    // Create Sankey generator
    const sankeyGenerator = sankey<ProcessedNode, ProcessedLink>()
      .nodeId(d => d.id)
      .nodeAlign(d3.sankeyJustify)
      .nodeWidth(15)
      .nodePadding(10)
      .extent([[0, 0], [innerWidth, innerHeight]]);

    // Generate Sankey data
    const sankeyData = sankeyGenerator({
      nodes: nodes.map(d => ({ ...d })),
      links: links.map(d => ({ ...d })),
    });

    // Create SVG
    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height);

    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Color scales
    const colorScale = d3.scaleOrdinal<string>()
      .domain(['0', '1', '2', '3'])
      .range(['#4fc3f7', '#ffa726', '#66bb6a', '#ab47bc']);

    const responseColorScale = d3.scaleOrdinal<string>()
      .domain(['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED', 'TIMEOUT'])
      .range(['#4caf50', '#ff9800', '#f44336', '#e91e63', '#9c27b0']);

    // Add links
    const link = g.append('g')
      .selectAll('.link')
      .data(sankeyData.links)
      .enter().append('path')
      .attr('class', 'link')
      .attr('d', sankeyLinkHorizontal())
      .attr('fill', 'none')
      .attr('stroke', d => {
        const targetNode = d.target as ProcessedNode;
        if (targetNode.id.startsWith('response_')) {
          const responseCode = targetNode.name;
          return responseColorScale(responseCode);
        }
        return '#888';
      })
      .attr('stroke-opacity', 0.5)
      .attr('stroke-width', d => Math.max(1, d.width || 0))
      .on('mouseover', function(event, d) {
        d3.select(this)
          .attr('stroke-opacity', 0.8);
        
        // Show tooltip
        const tooltip = d3.select('body').append('div')
          .attr('class', 'sankey-tooltip')
          .style('position', 'absolute')
          .style('padding', '10px')
          .style('background', 'rgba(0, 0, 0, 0.8)')
          .style('color', 'white')
          .style('border-radius', '5px')
          .style('pointer-events', 'none')
          .style('font-size', '12px');

        tooltip.html(`
          <strong>${(d.source as ProcessedNode).name} → ${(d.target as ProcessedNode).name}</strong><br/>
          Queries: ${d.queries}<br/>
          Value: ${d.value}
        `)
          .style('left', (event.pageX + 10) + 'px')
          .style('top', (event.pageY - 10) + 'px');
      })
      .on('mouseout', function() {
        d3.select(this)
          .attr('stroke-opacity', 0.5);
        d3.selectAll('.sankey-tooltip').remove();
      });

    // Add nodes
    const node = g.append('g')
      .selectAll('.node')
      .data(sankeyData.nodes)
      .enter().append('g')
      .attr('class', 'node')
      .attr('transform', d => `translate(${d.x0},${d.y0})`);

    // Add node rectangles
    node.append('rect')
      .attr('height', d => (d.y1 || 0) - (d.y0 || 0))
      .attr('width', sankeyGenerator.nodeWidth())
      .attr('fill', d => {
        const nodeData = d as ProcessedNode;
        if (nodeData.id.startsWith('response_')) {
          return responseColorScale(nodeData.name);
        }
        return colorScale(nodeData.group.toString());
      })
      .attr('stroke', '#000')
      .attr('stroke-width', 0.5)
      .on('mouseover', function(event, d) {
        // Highlight connected links
        g.selectAll('.link')
          .attr('stroke-opacity', (l: any) => {
            return l.source === d || l.target === d ? 0.8 : 0.2;
          });
      })
      .on('mouseout', function() {
        g.selectAll('.link')
          .attr('stroke-opacity', 0.5);
      });

    // Add node labels
    node.append('text')
      .attr('x', d => {
        const nodeData = d as ProcessedNode;
        return nodeData.group < 2 ? -6 : sankeyGenerator.nodeWidth() + 6;
      })
      .attr('y', d => ((d.y1 || 0) - (d.y0 || 0)) / 2)
      .attr('dy', '0.35em')
      .attr('text-anchor', d => {
        const nodeData = d as ProcessedNode;
        return nodeData.group < 2 ? 'end' : 'start';
      })
      .attr('font-size', '11px')
      .text(d => {
        const nodeData = d as ProcessedNode;
        return `${nodeData.name} (${nodeData.value})`;
      });

    // Add group labels
    const groupLabels = [
      { x: -margin.left / 2, text: 'Sources' },
      { x: innerWidth * 0.33, text: 'Query Types' },
      { x: innerWidth * 0.66, text: 'Response Codes' },
      { x: innerWidth + margin.right / 2, text: 'Destinations' },
    ];

    svg.append('g')
      .selectAll('.group-label')
      .data(groupLabels)
      .enter().append('text')
      .attr('class', 'group-label')
      .attr('x', d => d.x + margin.left)
      .attr('y', margin.top - 5)
      .attr('text-anchor', 'middle')
      .attr('font-weight', 'bold')
      .attr('font-size', '12px')
      .text(d => d.text);

    // Add gradient definitions for links
    const defs = svg.append('defs');

    links.forEach((link, i) => {
      const gradient = defs.append('linearGradient')
        .attr('id', `gradient-${i}`)
        .attr('gradientUnits', 'userSpaceOnUse')
        .attr('x1', '0%')
        .attr('x2', '100%');

      const sourceNode = nodes.find(n => n.id === link.source) as ProcessedNode;
      const targetNode = nodes.find(n => n.id === link.target) as ProcessedNode;

      gradient.append('stop')
        .attr('offset', '0%')
        .attr('stop-color', colorScale(sourceNode.group.toString()))
        .attr('stop-opacity', 0.5);

      gradient.append('stop')
        .attr('offset', '100%')
        .attr('stop-color', colorScale(targetNode.group.toString()))
        .attr('stop-opacity', 0.5);
    });

  }, [queries, height]);

  return (
    <Box sx={{ width: '100%', height: '100%' }}>
      <Paper sx={{ p: 2, height: '100%' }}>
        <Typography variant="h6" gutterBottom>
          Query Distribution Flow
        </Typography>
        <Typography variant="body2" color="textSecondary" gutterBottom>
          Visualizing the flow of DNS queries through different stages
        </Typography>
        <Box ref={containerRef} sx={{ width: '100%', height: height }}>
          <svg ref={svgRef} style={{ width: '100%', height: '100%' }} />
        </Box>
      </Paper>
    </Box>
  );
};

export default SankeyDiagram;