import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, Typography, Box, FormControlLabel, Switch, Select, MenuItem, Chip } from '@mui/material';
import * as d3 from 'd3';
import { scaleSequential } from 'd3-scale';
import { interpolateRdYlGn } from 'd3-scale-chromatic';

interface ResponseTimeData {
  bucket: number;
  count: number;
  percentage: number;
}

interface ResponseTimeHistogramProps {
  data?: ResponseTimeData[];
  height?: number;
  title?: string;
  showPercentiles?: boolean;
  binSize?: number;
}

const ResponseTimeHistogram: React.FC<ResponseTimeHistogramProps> = ({
  data = [],
  height = 350,
  title = 'DNS Response Time Distribution',
  showPercentiles = true,
  binSize = 10,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height });
  const [showCumulative, setShowCumulative] = useState(false);
  const [selectedBinSize, setSelectedBinSize] = useState(binSize);
  const [hoveredBar, setHoveredBar] = useState<ResponseTimeData | null>(null);

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

    const margin = { top: 20, right: 60, bottom: 60, left: 60 };
    const innerWidth = dimensions.width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', dimensions.width)
      .attr('height', height);

    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const processedData = processHistogramData(data, selectedBinSize);

    const xScale = d3.scaleBand()
      .domain(processedData.map(d => String(d.bucket)))
      .range([0, innerWidth])
      .padding(0.1);

    const yScale = d3.scaleLinear()
      .domain([0, d3.max(processedData, d => d.count) || 0])
      .nice()
      .range([innerHeight, 0]);

    const colorScale = scaleSequential(interpolateRdYlGn)
      .domain([200, 0]);

    const xAxis = d3.axisBottom(xScale)
      .tickValues(xScale.domain().filter((_, i) => i % Math.ceil(processedData.length / 10) === 0));

    const yAxis = d3.axisLeft(yScale);

    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis)
      .append('text')
      .attr('fill', '#000')
      .attr('x', innerWidth / 2)
      .attr('y', 45)
      .attr('text-anchor', 'middle')
      .text('Response Time (ms)');

    g.append('g')
      .call(yAxis)
      .append('text')
      .attr('fill', '#000')
      .attr('transform', 'rotate(-90)')
      .attr('y', -45)
      .attr('x', -innerHeight / 2)
      .attr('text-anchor', 'middle')
      .text('Number of Queries');

    const bars = g.selectAll('.bar')
      .data(processedData)
      .enter()
      .append('rect')
      .attr('class', 'bar')
      .attr('x', d => xScale(String(d.bucket)) || 0)
      .attr('y', d => yScale(d.count))
      .attr('width', xScale.bandwidth())
      .attr('height', d => innerHeight - yScale(d.count))
      .attr('fill', d => colorScale(d.bucket))
      .attr('opacity', 0.8)
      .on('mouseover', function(event, d) {
        d3.select(this).attr('opacity', 1);
        setHoveredBar(d);
      })
      .on('mouseout', function() {
        d3.select(this).attr('opacity', 0.8);
        setHoveredBar(null);
      });

    bars.transition()
      .duration(500)
      .attr('y', d => yScale(d.count))
      .attr('height', d => innerHeight - yScale(d.count));

    if (showCumulative) {
      const cumulativeData = calculateCumulative(processedData);
      
      const yScaleCumulative = d3.scaleLinear()
        .domain([0, 100])
        .range([innerHeight, 0]);

      const line = d3.line<any>()
        .x(d => (xScale(String(d.bucket)) || 0) + xScale.bandwidth() / 2)
        .y(d => yScaleCumulative(d.cumulative))
        .curve(d3.curveMonotoneX);

      g.append('g')
        .attr('transform', `translate(${innerWidth},0)`)
        .call(d3.axisRight(yScaleCumulative))
        .append('text')
        .attr('fill', '#000')
        .attr('transform', 'rotate(90)')
        .attr('y', -40)
        .attr('x', innerHeight / 2)
        .attr('text-anchor', 'middle')
        .text('Cumulative %');

      g.append('path')
        .datum(cumulativeData)
        .attr('fill', 'none')
        .attr('stroke', '#FF6B6B')
        .attr('stroke-width', 2)
        .attr('d', line);

      g.selectAll('.cumulative-dot')
        .data(cumulativeData)
        .enter()
        .append('circle')
        .attr('class', 'cumulative-dot')
        .attr('cx', d => (xScale(String(d.bucket)) || 0) + xScale.bandwidth() / 2)
        .attr('cy', d => yScaleCumulative(d.cumulative))
        .attr('r', 3)
        .attr('fill', '#FF6B6B');
    }

    if (showPercentiles) {
      const percentiles = calculatePercentiles(processedData);
      
      percentiles.forEach(p => {
        const xPos = xScale(String(p.value)) || 0;
        
        g.append('line')
          .attr('x1', xPos + xScale.bandwidth() / 2)
          .attr('x2', xPos + xScale.bandwidth() / 2)
          .attr('y1', 0)
          .attr('y2', innerHeight)
          .attr('stroke', p.percentile === 50 ? '#2196F3' : '#9E9E9E')
          .attr('stroke-width', p.percentile === 50 ? 2 : 1)
          .attr('stroke-dasharray', '5,5');

        g.append('text')
          .attr('x', xPos + xScale.bandwidth() / 2)
          .attr('y', -5)
          .attr('text-anchor', 'middle')
          .attr('font-size', '10px')
          .attr('fill', p.percentile === 50 ? '#2196F3' : '#9E9E9E')
          .text(`P${p.percentile}`);
      });
    }

  }, [data, dimensions, height, showCumulative, selectedBinSize, showPercentiles]);

  const processHistogramData = (data: ResponseTimeData[], binSize: number): ResponseTimeData[] => {
    const bins: { [key: number]: number } = {};
    
    data.forEach(d => {
      const bin = Math.floor(d.bucket / binSize) * binSize;
      bins[bin] = (bins[bin] || 0) + d.count;
    });

    const total = Object.values(bins).reduce((a, b) => a + b, 0);
    
    return Object.entries(bins).map(([bucket, count]) => ({
      bucket: Number(bucket),
      count,
      percentage: (count / total) * 100,
    })).sort((a, b) => a.bucket - b.bucket);
  };

  const calculateCumulative = (data: ResponseTimeData[]) => {
    let cumulative = 0;
    const total = data.reduce((sum, d) => sum + d.count, 0);
    
    return data.map(d => {
      cumulative += d.count;
      return {
        bucket: d.bucket,
        cumulative: (cumulative / total) * 100,
      };
    });
  };

  const calculatePercentiles = (data: ResponseTimeData[]) => {
    const total = data.reduce((sum, d) => sum + d.count, 0);
    const percentiles = [25, 50, 75, 90, 95, 99];
    const results: { percentile: number; value: number }[] = [];
    
    let cumulative = 0;
    for (const d of data) {
      cumulative += d.count;
      const percentage = (cumulative / total) * 100;
      
      percentiles.forEach(p => {
        if (percentage >= p && !results.find(r => r.percentile === p)) {
          results.push({ percentile: p, value: d.bucket });
        }
      });
    }
    
    return results;
  };

  const getStatistics = () => {
    if (data.length === 0) return null;
    
    const values: number[] = [];
    data.forEach(d => {
      for (let i = 0; i < d.count; i++) {
        values.push(d.bucket);
      }
    });
    
    values.sort((a, b) => a - b);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const median = values[Math.floor(values.length / 2)];
    const p95 = values[Math.floor(values.length * 0.95)];
    const p99 = values[Math.floor(values.length * 0.99)];
    
    return { mean, median, p95, p99 };
  };

  const stats = getStatistics();

  return (
    <Card>
      <CardContent>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">{title}</Typography>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <Select
              size="small"
              value={selectedBinSize}
              onChange={(e) => setSelectedBinSize(Number(e.target.value))}
            >
              <MenuItem value={5}>5ms bins</MenuItem>
              <MenuItem value={10}>10ms bins</MenuItem>
              <MenuItem value={20}>20ms bins</MenuItem>
              <MenuItem value={50}>50ms bins</MenuItem>
            </Select>
            <FormControlLabel
              control={
                <Switch
                  checked={showCumulative}
                  onChange={(e) => setShowCumulative(e.target.checked)}
                />
              }
              label="Show Cumulative"
            />
          </Box>
        </Box>

        {stats && (
          <Box sx={{ mb: 2, display: 'flex', gap: 2 }}>
            <Chip label={`Mean: ${stats.mean.toFixed(1)}ms`} size="small" />
            <Chip label={`Median: ${stats.median}ms`} size="small" />
            <Chip label={`P95: ${stats.p95}ms`} size="small" color="warning" />
            <Chip label={`P99: ${stats.p99}ms`} size="small" color="error" />
          </Box>
        )}

        {hoveredBar && (
          <Box sx={{ mb: 1 }}>
            <Typography variant="body2" color="text.secondary">
              {hoveredBar.bucket}-{hoveredBar.bucket + selectedBinSize}ms: {hoveredBar.count} queries ({hoveredBar.percentage.toFixed(1)}%)
            </Typography>
          </Box>
        )}

        <Box ref={containerRef} sx={{ width: '100%', height }}>
          <svg ref={svgRef} />
        </Box>
      </CardContent>
    </Card>
  );
};

export default ResponseTimeHistogram;