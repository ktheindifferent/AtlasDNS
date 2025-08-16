import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, Typography, Box, Button, ButtonGroup, FormControlLabel, Switch } from '@mui/material';
import * as d3 from 'd3';
import { arc, pie } from 'd3-shape';
import { scaleOrdinal } from 'd3-scale';
import { schemeSet3 } from 'd3-scale-chromatic';

interface QueryTypeData {
  type: string;
  count: number;
  percentage: number;
  avgResponseTime: number;
  trend?: number;
}

interface QueryTypeBreakdownProps {
  data?: QueryTypeData[];
  height?: number;
  title?: string;
  chartType?: 'pie' | 'donut' | 'sunburst';
  showTrends?: boolean;
  onTypeClick?: (type: QueryTypeData) => void;
}

const QueryTypeBreakdown: React.FC<QueryTypeBreakdownProps> = ({
  data = [],
  height = 400,
  title = 'Query Type Breakdown',
  chartType = 'donut',
  showTrends = true,
  onTypeClick,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height });
  const [selectedChartType, setSelectedChartType] = useState(chartType);
  const [animateTransitions, setAnimateTransitions] = useState(true);
  const [selectedSegment, setSelectedSegment] = useState<QueryTypeData | null>(null);

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

    const margin = 40;
    const radius = Math.min(dimensions.width, height) / 2 - margin;

    const g = svg.append('g')
      .attr('transform', `translate(${dimensions.width / 2},${height / 2})`);

    const colorScale = scaleOrdinal(schemeSet3);

    const pieGenerator = pie<QueryTypeData>()
      .value(d => d.count)
      .sort((a, b) => b.count - a.count);

    let arcGenerator: d3.Arc<any, QueryTypeData>;
    let arcGeneratorHover: d3.Arc<any, QueryTypeData>;

    switch (selectedChartType) {
      case 'pie':
        arcGenerator = arc<QueryTypeData>()
          .innerRadius(0)
          .outerRadius(radius);
        arcGeneratorHover = arc<QueryTypeData>()
          .innerRadius(0)
          .outerRadius(radius + 10);
        break;
      case 'donut':
        arcGenerator = arc<QueryTypeData>()
          .innerRadius(radius * 0.6)
          .outerRadius(radius);
        arcGeneratorHover = arc<QueryTypeData>()
          .innerRadius(radius * 0.6)
          .outerRadius(radius + 10);
        break;
      case 'sunburst':
        arcGenerator = arc<QueryTypeData>()
          .innerRadius(radius * 0.3)
          .outerRadius(d => {
            const scale = d3.scaleLinear()
              .domain([0, Math.max(...data.map(d => d.avgResponseTime))])
              .range([radius * 0.6, radius]);
            return scale(d.data.avgResponseTime);
          });
        arcGeneratorHover = arc<QueryTypeData>()
          .innerRadius(radius * 0.3)
          .outerRadius(d => {
            const scale = d3.scaleLinear()
              .domain([0, Math.max(...data.map(d => d.avgResponseTime))])
              .range([radius * 0.6, radius]);
            return scale(d.data.avgResponseTime) + 10;
          });
        break;
      default:
        arcGenerator = arc<QueryTypeData>()
          .innerRadius(radius * 0.6)
          .outerRadius(radius);
        arcGeneratorHover = arc<QueryTypeData>()
          .innerRadius(radius * 0.6)
          .outerRadius(radius + 10);
    }

    const arcs = pieGenerator(data);

    const path = g.selectAll('path')
      .data(arcs)
      .enter()
      .append('path')
      .attr('fill', (d, i) => colorScale(String(i)))
      .attr('stroke', '#fff')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .on('mouseover', function(event, d) {
        if (animateTransitions) {
          d3.select(this)
            .transition()
            .duration(200)
            .attr('d', arcGeneratorHover as any);
        }
        setSelectedSegment(d.data);
      })
      .on('mouseout', function(event, d) {
        if (animateTransitions) {
          d3.select(this)
            .transition()
            .duration(200)
            .attr('d', arcGenerator as any);
        }
        setSelectedSegment(null);
      })
      .on('click', (event, d) => {
        onTypeClick?.(d.data);
      });

    if (animateTransitions) {
      path
        .transition()
        .duration(1000)
        .attrTween('d', function(d) {
          const interpolate = d3.interpolate({ startAngle: 0, endAngle: 0 }, d);
          return function(t) {
            return arcGenerator(interpolate(t)) || '';
          };
        });
    } else {
      path.attr('d', arcGenerator as any);
    }

    const labelArc = arc<QueryTypeData>()
      .innerRadius(radius * 0.8)
      .outerRadius(radius * 0.8);

    const labels = g.selectAll('.label')
      .data(arcs)
      .enter()
      .append('g')
      .attr('class', 'label');

    labels.append('text')
      .attr('transform', d => `translate(${labelArc.centroid(d as any)})`)
      .attr('text-anchor', 'middle')
      .style('font-size', '12px')
      .style('font-weight', 'bold')
      .style('fill', '#fff')
      .text(d => {
        const percentage = ((d.endAngle - d.startAngle) / (2 * Math.PI)) * 100;
        return percentage > 5 ? d.data.type : '';
      });

    labels.append('text')
      .attr('transform', d => {
        const [x, y] = labelArc.centroid(d as any);
        return `translate(${x},${y + 15})`;
      })
      .attr('text-anchor', 'middle')
      .style('font-size', '10px')
      .style('fill', '#fff')
      .text(d => {
        const percentage = ((d.endAngle - d.startAngle) / (2 * Math.PI)) * 100;
        return percentage > 5 ? `${d.data.percentage.toFixed(1)}%` : '';
      });

    if (selectedChartType === 'donut') {
      const centerText = g.append('g')
        .attr('class', 'center-text');

      centerText.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '-0.5em')
        .style('font-size', '24px')
        .style('font-weight', 'bold')
        .text(data.reduce((sum, d) => sum + d.count, 0).toLocaleString());

      centerText.append('text')
        .attr('text-anchor', 'middle')
        .attr('dy', '1em')
        .style('font-size', '14px')
        .style('fill', '#666')
        .text('Total Queries');
    }

    if (showTrends && data.some(d => d.trend !== undefined)) {
      const trendRadius = radius + 25;
      
      data.forEach((d, i) => {
        const arcData = arcs[i];
        const angle = (arcData.startAngle + arcData.endAngle) / 2;
        const x = Math.sin(angle) * trendRadius;
        const y = -Math.cos(angle) * trendRadius;

        const trendGroup = g.append('g')
          .attr('transform', `translate(${x},${y})`);

        if (d.trend && d.trend !== 0) {
          const trendColor = d.trend > 0 ? '#4CAF50' : '#F44336';
          const trendSymbol = d.trend > 0 ? '▲' : '▼';
          
          trendGroup.append('text')
            .attr('text-anchor', 'middle')
            .style('font-size', '12px')
            .style('fill', trendColor)
            .text(`${trendSymbol} ${Math.abs(d.trend)}%`);
        }
      });
    }

    const legend = svg.append('g')
      .attr('transform', `translate(${dimensions.width - 150}, 20)`);

    const legendItems = data.slice(0, 10);

    legendItems.forEach((d, i) => {
      const legendRow = legend.append('g')
        .attr('transform', `translate(0, ${i * 25})`);

      legendRow.append('rect')
        .attr('width', 15)
        .attr('height', 15)
        .attr('fill', colorScale(String(i)));

      legendRow.append('text')
        .attr('x', 20)
        .attr('y', 12)
        .style('font-size', '12px')
        .text(d.type);

      if (d.trend !== undefined && d.trend !== 0) {
        const trendColor = d.trend > 0 ? '#4CAF50' : '#F44336';
        const trendSymbol = d.trend > 0 ? '↑' : '↓';
        
        legendRow.append('text')
          .attr('x', 100)
          .attr('y', 12)
          .style('font-size', '10px')
          .style('fill', trendColor)
          .text(`${trendSymbol}${Math.abs(d.trend)}%`);
      }
    });

  }, [data, dimensions, height, selectedChartType, animateTransitions, showTrends, onTypeClick]);

  const getTopQueryTypes = () => {
    return data
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
      .map(d => ({
        ...d,
        formattedCount: formatNumber(d.count),
      }));
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">{title}</Typography>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <ButtonGroup size="small" variant="outlined">
              <Button
                variant={selectedChartType === 'pie' ? 'contained' : 'outlined'}
                onClick={() => setSelectedChartType('pie')}
              >
                Pie
              </Button>
              <Button
                variant={selectedChartType === 'donut' ? 'contained' : 'outlined'}
                onClick={() => setSelectedChartType('donut')}
              >
                Donut
              </Button>
              <Button
                variant={selectedChartType === 'sunburst' ? 'contained' : 'outlined'}
                onClick={() => setSelectedChartType('sunburst')}
              >
                Sunburst
              </Button>
            </ButtonGroup>
            <FormControlLabel
              control={
                <Switch
                  checked={animateTransitions}
                  onChange={(e) => setAnimateTransitions(e.target.checked)}
                />
              }
              label="Animate"
            />
          </Box>
        </Box>

        {selectedSegment && (
          <Box sx={{ mb: 2, p: 1, bgcolor: 'background.default', borderRadius: 1 }}>
            <Typography variant="subtitle2" fontWeight="bold">
              {selectedSegment.type}
            </Typography>
            <Typography variant="body2">
              Count: {selectedSegment.count.toLocaleString()} ({selectedSegment.percentage.toFixed(1)}%)
            </Typography>
            <Typography variant="body2">
              Avg Response: {selectedSegment.avgResponseTime}ms
            </Typography>
            {selectedSegment.trend !== undefined && (
              <Typography 
                variant="body2" 
                color={selectedSegment.trend > 0 ? 'success.main' : 'error.main'}
              >
                Trend: {selectedSegment.trend > 0 ? '+' : ''}{selectedSegment.trend}%
              </Typography>
            )}
          </Box>
        )}

        <Box ref={containerRef} sx={{ width: '100%', height, position: 'relative' }}>
          <svg ref={svgRef} />
        </Box>

        <Box sx={{ mt: 3 }}>
          <Typography variant="subtitle2" gutterBottom>
            Top Query Types
          </Typography>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {getTopQueryTypes().map((type, index) => (
              <Box
                key={index}
                sx={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  p: 1,
                  bgcolor: 'background.default',
                  borderRadius: 1,
                }}
              >
                <Typography variant="body2">
                  {index + 1}. {type.type}
                </Typography>
                <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                  <Typography variant="body2" color="text.secondary">
                    {type.formattedCount} queries
                  </Typography>
                  <Typography variant="body2" fontWeight="bold">
                    {type.percentage.toFixed(1)}%
                  </Typography>
                  {type.trend !== undefined && type.trend !== 0 && (
                    <Typography 
                      variant="body2" 
                      color={type.trend > 0 ? 'success.main' : 'error.main'}
                    >
                      {type.trend > 0 ? '↑' : '↓'}{Math.abs(type.trend)}%
                    </Typography>
                  )}
                </Box>
              </Box>
            ))}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

export default QueryTypeBreakdown;