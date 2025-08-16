import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, Typography, Box, Button, ButtonGroup, Tooltip } from '@mui/material';
import * as d3 from 'd3';
import { hierarchy, treemap, treemapSquarify } from 'd3-hierarchy';
import { scaleOrdinal, scaleSequential } from 'd3-scale';
import { schemeCategory10, interpolateBlues } from 'd3-scale-chromatic';

interface DomainData {
  name: string;
  queries: number;
  avgResponseTime: number;
  cacheHitRate: number;
  category?: string;
  subdomains?: DomainData[];
}

interface DomainsTreemapProps {
  data?: DomainData[];
  height?: number;
  title?: string;
  colorBy?: 'category' | 'queries' | 'responseTime' | 'cacheHitRate';
  onDomainClick?: (domain: DomainData) => void;
}

const DomainsTreemap: React.FC<DomainsTreemapProps> = ({
  data = [],
  height = 500,
  title = 'Top Queried Domains',
  colorBy = 'category',
  onDomainClick,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height });
  const [selectedColorBy, setSelectedColorBy] = useState(colorBy);
  const [zoomedDomain, setZoomedDomain] = useState<string | null>(null);
  const [hoveredDomain, setHoveredDomain] = useState<DomainData | null>(null);

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
    if (!svgRef.current || dimensions.width === 0 || data.length === 0) return;

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', dimensions.width)
      .attr('height', height);

    const hierarchyData = {
      name: 'root',
      children: data.map(d => ({
        ...d,
        value: d.queries,
      })),
    };

    const root = hierarchy(hierarchyData)
      .sum((d: any) => d.value || 0)
      .sort((a, b) => (b.value || 0) - (a.value || 0));

    const treemapLayout = treemap<any>()
      .size([dimensions.width, height])
      .padding(2)
      .round(true)
      .tile(treemapSquarify);

    treemapLayout(root);

    const colorScale = getColorScale(selectedColorBy, data);

    const g = svg.append('g');

    const nodes = g.selectAll('.node')
      .data(root.leaves())
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', (d: any) => `translate(${d.x0},${d.y0})`);

    nodes.append('rect')
      .attr('width', (d: any) => d.x1 - d.x0)
      .attr('height', (d: any) => d.y1 - d.y0)
      .attr('fill', (d: any) => {
        const domainData = d.data as DomainData;
        switch (selectedColorBy) {
          case 'category':
            return colorScale(domainData.category || 'Other');
          case 'queries':
            return colorScale(domainData.queries);
          case 'responseTime':
            return colorScale(domainData.avgResponseTime);
          case 'cacheHitRate':
            return colorScale(domainData.cacheHitRate);
          default:
            return '#2196F3';
        }
      })
      .attr('stroke', '#fff')
      .attr('stroke-width', 1)
      .style('cursor', 'pointer')
      .on('mouseover', function(event, d: any) {
        d3.select(this)
          .attr('stroke', '#000')
          .attr('stroke-width', 2);
        setHoveredDomain(d.data);
      })
      .on('mouseout', function() {
        d3.select(this)
          .attr('stroke', '#fff')
          .attr('stroke-width', 1);
        setHoveredDomain(null);
      })
      .on('click', (event, d: any) => {
        event.stopPropagation();
        const domainData = d.data as DomainData;
        if (domainData.subdomains && domainData.subdomains.length > 0) {
          setZoomedDomain(domainData.name);
        }
        onDomainClick?.(domainData);
      });

    nodes.append('clipPath')
      .attr('id', (d: any, i: number) => `clip-${i}`)
      .append('rect')
      .attr('width', (d: any) => d.x1 - d.x0)
      .attr('height', (d: any) => d.y1 - d.y0);

    const text = nodes.append('text')
      .attr('clip-path', (d: any, i: number) => `url(#clip-${i})`);

    text.append('tspan')
      .attr('x', 4)
      .attr('y', 18)
      .style('font-size', '12px')
      .style('font-weight', 'bold')
      .text((d: any) => {
        const domainData = d.data as DomainData;
        const width = d.x1 - d.x0;
        const maxChars = Math.floor(width / 7);
        return domainData.name.length > maxChars 
          ? domainData.name.substring(0, maxChars - 3) + '...'
          : domainData.name;
      });

    text.append('tspan')
      .attr('x', 4)
      .attr('y', 34)
      .style('font-size', '10px')
      .text((d: any) => {
        const domainData = d.data as DomainData;
        return formatNumber(domainData.queries) + ' queries';
      });

    text.append('tspan')
      .attr('x', 4)
      .attr('y', 48)
      .style('font-size', '10px')
      .style('fill', '#666')
      .text((d: any) => {
        const domainData = d.data as DomainData;
        const height = d.y1 - d.y0;
        if (height > 60) {
          return `${domainData.avgResponseTime}ms avg`;
        }
        return '';
      });

    if (zoomedDomain) {
      svg.on('click', () => {
        setZoomedDomain(null);
      });
    }

  }, [data, dimensions, height, selectedColorBy, zoomedDomain, onDomainClick]);

  const getColorScale = (colorBy: string, data: DomainData[]) => {
    switch (colorBy) {
      case 'category':
        const categories = Array.from(new Set(data.map(d => d.category || 'Other')));
        return scaleOrdinal(schemeCategory10).domain(categories);
      case 'queries':
        const maxQueries = Math.max(...data.map(d => d.queries));
        return scaleSequential(interpolateBlues).domain([0, maxQueries]);
      case 'responseTime':
        const maxResponseTime = Math.max(...data.map(d => d.avgResponseTime));
        return scaleSequential((t) => d3.interpolateRdYlGn(1 - t)).domain([0, maxResponseTime]);
      case 'cacheHitRate':
        return scaleSequential(d3.interpolateGreens).domain([0, 100]);
      default:
        return () => '#2196F3';
    }
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  const getLegendItems = () => {
    if (!data || data.length === 0) return [];

    switch (selectedColorBy) {
      case 'category':
        const categories = Array.from(new Set(data.map(d => d.category || 'Other')));
        return categories.slice(0, 5).map(cat => ({
          label: cat,
          color: scaleOrdinal(schemeCategory10)(cat),
        }));
      case 'queries':
        const maxQueries = Math.max(...data.map(d => d.queries));
        return [
          { label: '0', color: interpolateBlues(0) },
          { label: formatNumber(maxQueries / 2), color: interpolateBlues(0.5) },
          { label: formatNumber(maxQueries), color: interpolateBlues(1) },
        ];
      case 'responseTime':
        const maxResponseTime = Math.max(...data.map(d => d.avgResponseTime));
        return [
          { label: '0ms', color: d3.interpolateRdYlGn(1) },
          { label: `${Math.round(maxResponseTime / 2)}ms`, color: d3.interpolateRdYlGn(0.5) },
          { label: `${Math.round(maxResponseTime)}ms`, color: d3.interpolateRdYlGn(0) },
        ];
      case 'cacheHitRate':
        return [
          { label: '0%', color: d3.interpolateGreens(0) },
          { label: '50%', color: d3.interpolateGreens(0.5) },
          { label: '100%', color: d3.interpolateGreens(1) },
        ];
      default:
        return [];
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
                variant={selectedColorBy === 'category' ? 'contained' : 'outlined'}
                onClick={() => setSelectedColorBy('category')}
              >
                Category
              </Button>
              <Button
                variant={selectedColorBy === 'queries' ? 'contained' : 'outlined'}
                onClick={() => setSelectedColorBy('queries')}
              >
                Queries
              </Button>
              <Button
                variant={selectedColorBy === 'responseTime' ? 'contained' : 'outlined'}
                onClick={() => setSelectedColorBy('responseTime')}
              >
                Response Time
              </Button>
              <Button
                variant={selectedColorBy === 'cacheHitRate' ? 'contained' : 'outlined'}
                onClick={() => setSelectedColorBy('cacheHitRate')}
              >
                Cache Hit
              </Button>
            </ButtonGroup>
            {zoomedDomain && (
              <Button size="small" variant="outlined" onClick={() => setZoomedDomain(null)}>
                Reset Zoom
              </Button>
            )}
          </Box>
        </Box>

        {hoveredDomain && (
          <Box sx={{ mb: 1, p: 1, bgcolor: 'background.default', borderRadius: 1 }}>
            <Typography variant="subtitle2" fontWeight="bold">
              {hoveredDomain.name}
            </Typography>
            <Typography variant="body2">
              Queries: {hoveredDomain.queries.toLocaleString()} | 
              Avg Response: {hoveredDomain.avgResponseTime}ms | 
              Cache Hit: {hoveredDomain.cacheHitRate}%
              {hoveredDomain.category && ` | Category: ${hoveredDomain.category}`}
            </Typography>
          </Box>
        )}

        <Box ref={containerRef} sx={{ width: '100%', height, position: 'relative' }}>
          <svg ref={svgRef} />
        </Box>

        <Box sx={{ mt: 2, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          {getLegendItems().map((item, index) => (
            <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box
                sx={{
                  width: 16,
                  height: 16,
                  bgcolor: item.color,
                  borderRadius: 0.5,
                }}
              />
              <Typography variant="caption">{item.label}</Typography>
            </Box>
          ))}
        </Box>
      </CardContent>
    </Card>
  );
};

export default DomainsTreemap;