import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, Typography, Box, Button, ButtonGroup, Chip } from '@mui/material';
import * as d3 from 'd3';
import { ZoomIn, ZoomOut, ZoomOutMap, Pause, PlayArrow } from '@mui/icons-material';

interface QueryDataPoint {
  timestamp: Date;
  queries: number;
  cached: number;
  blocked: number;
  responseTime: number;
}

interface RealTimeQueryGraphProps {
  data?: QueryDataPoint[];
  height?: number;
  width?: number;
  title?: string;
  updateInterval?: number;
  showAnomalies?: boolean;
}

const RealTimeQueryGraph: React.FC<RealTimeQueryGraphProps> = ({
  data = [],
  height = 400,
  title = 'Real-time Query Rate',
  updateInterval = 1000,
  showAnomalies = true,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [isPaused, setIsPaused] = useState(false);
  const [selectedTimeRange, setSelectedTimeRange] = useState<'1m' | '5m' | '15m' | '1h'>('5m');
  const [currentData, setCurrentData] = useState<QueryDataPoint[]>(data);
  const [dimensions, setDimensions] = useState({ width: 0, height });

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
    if (!isPaused) {
      setCurrentData(data);
    }
  }, [data, isPaused]);

  useEffect(() => {
    if (!svgRef.current || dimensions.width === 0) return;

    const margin = { top: 20, right: 80, bottom: 50, left: 60 };
    const innerWidth = dimensions.width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', dimensions.width)
      .attr('height', height);

    const g = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const filteredData = filterDataByTimeRange(currentData, selectedTimeRange);

    const xScale = d3.scaleTime()
      .domain(d3.extent(filteredData, d => d.timestamp) as [Date, Date])
      .range([0, innerWidth]);

    const yScale = d3.scaleLinear()
      .domain([0, d3.max(filteredData, d => Math.max(d.queries, d.cached, d.blocked)) || 0])
      .nice()
      .range([innerHeight, 0]);

    const responseTimeScale = d3.scaleLinear()
      .domain([0, d3.max(filteredData, d => d.responseTime) || 0])
      .nice()
      .range([innerHeight, 0]);

    const xAxis = d3.axisBottom(xScale)
      .tickFormat(d3.timeFormat('%H:%M:%S') as any);

    const yAxis = d3.axisLeft(yScale);
    const yAxisRight = d3.axisRight(responseTimeScale);

    g.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis)
      .append('text')
      .attr('fill', '#000')
      .attr('x', innerWidth / 2)
      .attr('y', 40)
      .attr('text-anchor', 'middle')
      .text('Time');

    g.append('g')
      .call(yAxis)
      .append('text')
      .attr('fill', '#000')
      .attr('transform', 'rotate(-90)')
      .attr('y', -40)
      .attr('x', -innerHeight / 2)
      .attr('text-anchor', 'middle')
      .text('Queries per Second');

    g.append('g')
      .attr('transform', `translate(${innerWidth},0)`)
      .call(yAxisRight)
      .append('text')
      .attr('fill', '#000')
      .attr('transform', 'rotate(90)')
      .attr('y', -40)
      .attr('x', innerHeight / 2)
      .attr('text-anchor', 'middle')
      .text('Response Time (ms)');

    const lineQueries = d3.line<QueryDataPoint>()
      .x(d => xScale(d.timestamp))
      .y(d => yScale(d.queries))
      .curve(d3.curveMonotoneX);

    const lineCached = d3.line<QueryDataPoint>()
      .x(d => xScale(d.timestamp))
      .y(d => yScale(d.cached))
      .curve(d3.curveMonotoneX);

    const lineBlocked = d3.line<QueryDataPoint>()
      .x(d => xScale(d.timestamp))
      .y(d => yScale(d.blocked))
      .curve(d3.curveMonotoneX);

    const lineResponseTime = d3.line<QueryDataPoint>()
      .x(d => xScale(d.timestamp))
      .y(d => responseTimeScale(d.responseTime))
      .curve(d3.curveMonotoneX);

    const area = d3.area<QueryDataPoint>()
      .x(d => xScale(d.timestamp))
      .y0(innerHeight)
      .y1(d => yScale(d.queries))
      .curve(d3.curveMonotoneX);

    g.append('path')
      .datum(filteredData)
      .attr('fill', 'rgba(33, 150, 243, 0.1)')
      .attr('d', area);

    g.append('path')
      .datum(filteredData)
      .attr('fill', 'none')
      .attr('stroke', '#2196F3')
      .attr('stroke-width', 2)
      .attr('d', lineQueries);

    g.append('path')
      .datum(filteredData)
      .attr('fill', 'none')
      .attr('stroke', '#4CAF50')
      .attr('stroke-width', 2)
      .attr('d', lineCached);

    g.append('path')
      .datum(filteredData)
      .attr('fill', 'none')
      .attr('stroke', '#F44336')
      .attr('stroke-width', 2)
      .attr('d', lineBlocked);

    g.append('path')
      .datum(filteredData)
      .attr('fill', 'none')
      .attr('stroke', '#FF9800')
      .attr('stroke-width', 2)
      .attr('stroke-dasharray', '3,3')
      .attr('d', lineResponseTime);

    if (showAnomalies) {
      const anomalies = detectAnomalies(filteredData);
      g.selectAll('.anomaly')
        .data(anomalies)
        .enter()
        .append('circle')
        .attr('class', 'anomaly')
        .attr('cx', d => xScale(d.timestamp))
        .attr('cy', d => yScale(d.queries))
        .attr('r', 6)
        .attr('fill', '#FF5252')
        .attr('stroke', '#fff')
        .attr('stroke-width', 2);
    }

    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.5, 10])
      .translateExtent([[0, 0], [innerWidth, innerHeight]])
      .on('zoom', (event) => {
        const newXScale = event.transform.rescaleX(xScale);
        g.select('.x-axis').call(d3.axisBottom(newXScale).tickFormat(d3.timeFormat('%H:%M:%S') as any));
        
        g.selectAll('path')
          .attr('d', (d: any) => {
            if (Array.isArray(d)) {
              return lineQueries(d);
            }
            return null;
          });
      });

    svg.call(zoom);

    const legend = svg.append('g')
      .attr('transform', `translate(${margin.left + 10}, ${margin.top})`);

    const legendItems = [
      { label: 'Queries', color: '#2196F3' },
      { label: 'Cached', color: '#4CAF50' },
      { label: 'Blocked', color: '#F44336' },
      { label: 'Response Time', color: '#FF9800', dashed: true },
    ];

    legendItems.forEach((item, i) => {
      const legendRow = legend.append('g')
        .attr('transform', `translate(0, ${i * 20})`);

      legendRow.append('line')
        .attr('x1', 0)
        .attr('x2', 20)
        .attr('y1', 10)
        .attr('y2', 10)
        .attr('stroke', item.color)
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', item.dashed ? '3,3' : '0');

      legendRow.append('text')
        .attr('x', 25)
        .attr('y', 10)
        .attr('dy', '0.35em')
        .style('font-size', '12px')
        .text(item.label);
    });

  }, [currentData, dimensions, height, selectedTimeRange, showAnomalies]);

  const filterDataByTimeRange = (data: QueryDataPoint[], range: string): QueryDataPoint[] => {
    const now = new Date();
    const rangeMap: { [key: string]: number } = {
      '1m': 60 * 1000,
      '5m': 5 * 60 * 1000,
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
    };
    const cutoff = new Date(now.getTime() - rangeMap[range]);
    return data.filter(d => d.timestamp >= cutoff);
  };

  const detectAnomalies = (data: QueryDataPoint[]): QueryDataPoint[] => {
    if (data.length < 10) return [];
    
    const values = data.map(d => d.queries);
    const mean = values.reduce((a, b) => a + b, 0) / values.length;
    const stdDev = Math.sqrt(values.reduce((sq, n) => sq + Math.pow(n - mean, 2), 0) / values.length);
    const threshold = mean + (2 * stdDev);
    
    return data.filter(d => d.queries > threshold);
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

  return (
    <Card>
      <CardContent>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">{title}</Typography>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <ButtonGroup size="small" variant="outlined">
              {(['1m', '5m', '15m', '1h'] as const).map(range => (
                <Button
                  key={range}
                  variant={selectedTimeRange === range ? 'contained' : 'outlined'}
                  onClick={() => setSelectedTimeRange(range)}
                >
                  {range}
                </Button>
              ))}
            </ButtonGroup>
            <ButtonGroup size="small" variant="outlined">
              <Button onClick={handleZoomIn} title="Zoom In">
                <ZoomIn />
              </Button>
              <Button onClick={handleZoomOut} title="Zoom Out">
                <ZoomOut />
              </Button>
              <Button onClick={handleResetZoom} title="Reset Zoom">
                <ZoomOutMap />
              </Button>
            </ButtonGroup>
            <Button
              size="small"
              variant="outlined"
              startIcon={isPaused ? <PlayArrow /> : <Pause />}
              onClick={() => setIsPaused(!isPaused)}
            >
              {isPaused ? 'Resume' : 'Pause'}
            </Button>
          </Box>
        </Box>
        {showAnomalies && detectAnomalies(currentData).length > 0 && (
          <Chip
            label={`${detectAnomalies(currentData).length} anomalies detected`}
            color="error"
            size="small"
            sx={{ mb: 1 }}
          />
        )}
        <Box ref={containerRef} sx={{ width: '100%', height }}>
          <svg ref={svgRef} />
        </Box>
      </CardContent>
    </Card>
  );
};

export default RealTimeQueryGraph;