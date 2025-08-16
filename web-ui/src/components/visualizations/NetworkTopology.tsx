import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, Typography, Box, Button, ButtonGroup, Chip, IconButton } from '@mui/material';
import { ZoomIn, ZoomOut, ZoomOutMap, CenterFocusStrong } from '@mui/icons-material';
import * as d3 from 'd3';
import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide } from 'd3-force';

interface NetworkNode {
  id: string;
  name: string;
  type: 'client' | 'resolver' | 'authoritative' | 'root' | 'cache';
  status: 'healthy' | 'degraded' | 'down';
  queries?: number;
  responseTime?: number;
  location?: string;
}

interface NetworkLink {
  source: string;
  target: string;
  value: number;
  latency: number;
  packetLoss?: number;
}

interface NetworkTopologyProps {
  nodes?: NetworkNode[];
  links?: NetworkLink[];
  height?: number;
  title?: string;
  onNodeClick?: (node: NetworkNode) => void;
  onLinkClick?: (link: NetworkLink) => void;
}

const NetworkTopology: React.FC<NetworkTopologyProps> = ({
  nodes = [],
  links = [],
  height = 600,
  title = 'DNS Infrastructure Topology',
  onNodeClick,
  onLinkClick,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height });
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [viewMode, setViewMode] = useState<'topology' | 'hierarchy' | 'radial'>('topology');
  const simulationRef = useRef<d3.Simulation<NetworkNode, NetworkLink> | null>(null);

  useEffect(() => {
    const handleResize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.clientWidth,
          height,
        });
      }
    };

    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [height]);

  useEffect(() => {
    if (!svgRef.current || dimensions.width === 0 || nodes.length === 0) return;

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', dimensions.width)
      .attr('height', height);

    const g = svg.append('g');

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    const nodesCopy = nodes.map(d => ({ ...d }));
    const linksCopy = links.map(d => ({ ...d }));

    const simulation = forceSimulation<NetworkNode>(nodesCopy)
      .force('link', forceLink<NetworkNode, NetworkLink>(linksCopy)
        .id((d: any) => d.id)
        .distance(d => 100 - d.latency))
      .force('charge', forceManyBody().strength(-300))
      .force('center', forceCenter(dimensions.width / 2, height / 2))
      .force('collide', forceCollide().radius(30));

    simulationRef.current = simulation;

    const linkWidthScale = d3.scaleLinear()
      .domain([0, d3.max(links, d => d.value) || 1])
      .range([1, 8]);

    const linkColorScale = d3.scaleSequential(d3.interpolateRdYlGn)
      .domain([100, 0]);

    const link = g.append('g')
      .selectAll('line')
      .data(linksCopy)
      .enter()
      .append('line')
      .attr('stroke', d => linkColorScale(d.latency))
      .attr('stroke-width', d => linkWidthScale(d.value))
      .attr('stroke-opacity', 0.6)
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        onLinkClick?.(d as NetworkLink);
      })
      .on('mouseover', function(event, d) {
        d3.select(this)
          .attr('stroke-opacity', 1)
          .attr('stroke-width', (d: any) => linkWidthScale(d.value) * 1.5);
        
        showLinkTooltip(event, d as NetworkLink);
      })
      .on('mouseout', function(event, d) {
        d3.select(this)
          .attr('stroke-opacity', 0.6)
          .attr('stroke-width', (d: any) => linkWidthScale(d.value));
        
        hideTooltip();
      });

    const node = g.append('g')
      .selectAll('g')
      .data(nodesCopy)
      .enter()
      .append('g')
      .style('cursor', 'pointer')
      .call(drag(simulation));

    const nodeColorMap = {
      client: '#2196F3',
      resolver: '#4CAF50',
      authoritative: '#FF9800',
      root: '#9C27B0',
      cache: '#00BCD4',
    };

    const statusOpacityMap = {
      healthy: 1,
      degraded: 0.7,
      down: 0.3,
    };

    node.append('circle')
      .attr('r', d => getNodeSize(d))
      .attr('fill', d => nodeColorMap[d.type])
      .attr('opacity', d => statusOpacityMap[d.status])
      .attr('stroke', '#fff')
      .attr('stroke-width', 2);

    node.append('text')
      .text(d => d.name)
      .attr('x', 0)
      .attr('y', 0)
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'middle')
      .style('font-size', '10px')
      .style('fill', '#fff')
      .style('pointer-events', 'none');

    node.filter(d => d.status !== 'healthy')
      .append('circle')
      .attr('r', 5)
      .attr('cx', d => getNodeSize(d) - 5)
      .attr('cy', d => -getNodeSize(d) + 5)
      .attr('fill', d => d.status === 'down' ? '#F44336' : '#FF9800')
      .attr('stroke', '#fff')
      .attr('stroke-width', 1);

    node.on('click', (event, d) => {
      event.stopPropagation();
      setSelectedNode(d as NetworkNode);
      onNodeClick?.(d as NetworkNode);
    })
    .on('mouseover', function(event, d) {
      d3.select(this).select('circle')
        .attr('stroke-width', 4);
      
      showNodeTooltip(event, d as NetworkNode);
    })
    .on('mouseout', function() {
      d3.select(this).select('circle')
        .attr('stroke-width', 2);
      
      hideTooltip();
    });

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    });

    if (viewMode === 'hierarchy') {
      applyHierarchicalLayout(nodesCopy, simulation, dimensions.width, height);
    } else if (viewMode === 'radial') {
      applyRadialLayout(nodesCopy, simulation, dimensions.width, height);
    }

    return () => {
      simulation.stop();
    };
  }, [nodes, links, dimensions, height, viewMode, onNodeClick, onLinkClick]);

  const getNodeSize = (node: NetworkNode) => {
    const baseSize = 20;
    if (node.queries) {
      const scale = d3.scaleLinear()
        .domain([0, Math.max(...nodes.map(n => n.queries || 0))])
        .range([baseSize, baseSize * 2]);
      return scale(node.queries);
    }
    return baseSize;
  };

  const drag = (simulation: d3.Simulation<NetworkNode, NetworkLink>) => {
    function dragstarted(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }

    function dragged(event: any, d: any) {
      d.fx = event.x;
      d.fy = event.y;
    }

    function dragended(event: any, d: any) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }

    return d3.drag<any, any>()
      .on('start', dragstarted)
      .on('drag', dragged)
      .on('end', dragended);
  };

  const applyHierarchicalLayout = (
    nodes: NetworkNode[],
    simulation: d3.Simulation<NetworkNode, NetworkLink>,
    width: number,
    height: number
  ) => {
    const levels: { [key: string]: number } = {
      root: 0,
      authoritative: 1,
      resolver: 2,
      cache: 3,
      client: 4,
    };

    const nodesByLevel: { [key: number]: NetworkNode[] } = {};
    nodes.forEach(node => {
      const level = levels[node.type];
      if (!nodesByLevel[level]) nodesByLevel[level] = [];
      nodesByLevel[level].push(node);
    });

    Object.keys(nodesByLevel).forEach(level => {
      const levelNodes = nodesByLevel[parseInt(level)];
      const y = (parseInt(level) + 1) * (height / (Object.keys(levels).length + 1));
      levelNodes.forEach((node: any, i) => {
        const x = (i + 1) * (width / (levelNodes.length + 1));
        node.fx = x;
        node.fy = y;
      });
    });

    simulation.alpha(0.3).restart();
  };

  const applyRadialLayout = (
    nodes: NetworkNode[],
    simulation: d3.Simulation<NetworkNode, NetworkLink>,
    width: number,
    height: number
  ) => {
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) / 3;

    const angleStep = (2 * Math.PI) / nodes.length;
    nodes.forEach((node: any, i) => {
      const angle = i * angleStep;
      node.fx = centerX + radius * Math.cos(angle);
      node.fy = centerY + radius * Math.sin(angle);
    });

    simulation.alpha(0.3).restart();
  };

  const showNodeTooltip = (event: MouseEvent, node: NetworkNode) => {
    const tooltip = d3.select('body').append('div')
      .attr('class', 'network-tooltip')
      .style('position', 'absolute')
      .style('padding', '10px')
      .style('background', 'rgba(0, 0, 0, 0.8)')
      .style('color', 'white')
      .style('border-radius', '4px')
      .style('pointer-events', 'none')
      .style('font-size', '12px');

    tooltip.html(`
      <strong>${node.name}</strong><br/>
      Type: ${node.type}<br/>
      Status: ${node.status}<br/>
      ${node.queries ? `Queries: ${node.queries.toLocaleString()}<br/>` : ''}
      ${node.responseTime ? `Response Time: ${node.responseTime}ms<br/>` : ''}
      ${node.location ? `Location: ${node.location}` : ''}
    `);

    tooltip
      .style('left', `${event.pageX + 10}px`)
      .style('top', `${event.pageY - 10}px`);
  };

  const showLinkTooltip = (event: MouseEvent, link: NetworkLink) => {
    const tooltip = d3.select('body').append('div')
      .attr('class', 'network-tooltip')
      .style('position', 'absolute')
      .style('padding', '10px')
      .style('background', 'rgba(0, 0, 0, 0.8)')
      .style('color', 'white')
      .style('border-radius', '4px')
      .style('pointer-events', 'none')
      .style('font-size', '12px');

    tooltip.html(`
      <strong>Connection</strong><br/>
      Traffic: ${link.value.toLocaleString()} queries<br/>
      Latency: ${link.latency}ms<br/>
      ${link.packetLoss ? `Packet Loss: ${link.packetLoss}%` : ''}
    `);

    tooltip
      .style('left', `${event.pageX + 10}px`)
      .style('top', `${event.pageY - 10}px`);
  };

  const hideTooltip = () => {
    d3.selectAll('.network-tooltip').remove();
  };

  const handleZoomIn = () => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      svg.transition().call(
        d3.zoom<SVGSVGElement, unknown>().scaleTo as any, 1.5
      );
    }
  };

  const handleZoomOut = () => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      svg.transition().call(
        d3.zoom<SVGSVGElement, unknown>().scaleTo as any, 0.75
      );
    }
  };

  const handleResetZoom = () => {
    if (svgRef.current) {
      const svg = d3.select(svgRef.current);
      svg.transition().call(
        d3.zoom<SVGSVGElement, unknown>().transform as any, d3.zoomIdentity
      );
    }
  };

  const handleRestart = () => {
    if (simulationRef.current) {
      simulationRef.current.alpha(1).restart();
    }
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">{title}</Typography>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <ButtonGroup size="small" variant="outlined">
              <Button
                variant={viewMode === 'topology' ? 'contained' : 'outlined'}
                onClick={() => setViewMode('topology')}
              >
                Force
              </Button>
              <Button
                variant={viewMode === 'hierarchy' ? 'contained' : 'outlined'}
                onClick={() => setViewMode('hierarchy')}
              >
                Hierarchy
              </Button>
              <Button
                variant={viewMode === 'radial' ? 'contained' : 'outlined'}
                onClick={() => setViewMode('radial')}
              >
                Radial
              </Button>
            </ButtonGroup>
            <ButtonGroup size="small" variant="outlined">
              <IconButton onClick={handleZoomIn} size="small">
                <ZoomIn />
              </IconButton>
              <IconButton onClick={handleZoomOut} size="small">
                <ZoomOut />
              </IconButton>
              <IconButton onClick={handleResetZoom} size="small">
                <ZoomOutMap />
              </IconButton>
              <IconButton onClick={handleRestart} size="small">
                <CenterFocusStrong />
              </IconButton>
            </ButtonGroup>
          </Box>
        </Box>

        {selectedNode && (
          <Box sx={{ mb: 2, p: 1, bgcolor: 'background.default', borderRadius: 1 }}>
            <Typography variant="subtitle2">
              Selected: <strong>{selectedNode.name}</strong> ({selectedNode.type})
            </Typography>
          </Box>
        )}

        <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
          <Chip icon={<Box sx={{ width: 12, height: 12, bgcolor: '#2196F3', borderRadius: '50%' }} />} label="Client" size="small" />
          <Chip icon={<Box sx={{ width: 12, height: 12, bgcolor: '#4CAF50', borderRadius: '50%' }} />} label="Resolver" size="small" />
          <Chip icon={<Box sx={{ width: 12, height: 12, bgcolor: '#FF9800', borderRadius: '50%' }} />} label="Authoritative" size="small" />
          <Chip icon={<Box sx={{ width: 12, height: 12, bgcolor: '#9C27B0', borderRadius: '50%' }} />} label="Root" size="small" />
          <Chip icon={<Box sx={{ width: 12, height: 12, bgcolor: '#00BCD4', borderRadius: '50%' }} />} label="Cache" size="small" />
        </Box>

        <Box ref={containerRef} sx={{ width: '100%', height }}>
          <svg ref={svgRef} />
        </Box>
      </CardContent>
    </Card>
  );
};

export default NetworkTopology;