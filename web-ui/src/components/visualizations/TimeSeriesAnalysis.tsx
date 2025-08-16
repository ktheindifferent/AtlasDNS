import React, { useEffect, useRef, useState } from 'react';
import { Card, CardContent, Typography, Box, Button, ButtonGroup, Chip, Alert, FormControlLabel, Switch } from '@mui/material';
import * as d3 from 'd3';
import { bisector, extent, max, mean, deviation } from 'd3-array';
import { scaleTime, scaleLinear } from 'd3-scale';
import { line, area, curveMonotoneX } from 'd3-shape';
import { axisBottom, axisLeft } from 'd3-axis';
import { brush } from 'd3-brush';
import { zoom } from 'd3-zoom';

interface TimeSeriesDataPoint {
  timestamp: Date;
  value: number;
  predicted?: number;
  anomalyScore?: number;
  isAnomaly?: boolean;
}

interface AnomalyPeriod {
  start: Date;
  end: Date;
  severity: 'low' | 'medium' | 'high';
  description: string;
}

interface TimeSeriesAnalysisProps {
  data?: TimeSeriesDataPoint[];
  height?: number;
  title?: string;
  metric?: string;
  showPredictions?: boolean;
  anomalyThreshold?: number;
  onAnomalyDetected?: (anomalies: TimeSeriesDataPoint[]) => void;
}

const TimeSeriesAnalysis: React.FC<TimeSeriesAnalysisProps> = ({
  data = [],
  height = 500,
  title = 'Time Series Analysis with Anomaly Detection',
  metric = 'Queries',
  showPredictions = true,
  anomalyThreshold = 2.5,
  onAnomalyDetected,
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dimensions, setDimensions] = useState({ width: 0, height });
  const [selectedTimeRange, setSelectedTimeRange] = useState<[Date, Date] | null>(null);
  const [detectedAnomalies, setDetectedAnomalies] = useState<TimeSeriesDataPoint[]>([]);
  const [anomalyPeriods, setAnomalyPeriods] = useState<AnomalyPeriod[]>([]);
  const [showConfidenceBands, setShowConfidenceBands] = useState(true);
  const [anomalyDetectionMethod, setAnomalyDetectionMethod] = useState<'statistical' | 'ml'>('statistical');

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
    if (data.length > 0) {
      const anomalies = detectAnomalies(data, anomalyThreshold, anomalyDetectionMethod);
      setDetectedAnomalies(anomalies);
      const periods = identifyAnomalyPeriods(anomalies);
      setAnomalyPeriods(periods);
      onAnomalyDetected?.(anomalies);
    }
  }, [data, anomalyThreshold, anomalyDetectionMethod, onAnomalyDetected]);

  useEffect(() => {
    if (!svgRef.current || dimensions.width === 0 || data.length === 0) return;

    const margin = { top: 20, right: 80, bottom: 100, left: 60 };
    const innerWidth = dimensions.width - margin.left - margin.right;
    const innerHeight = height - margin.top - margin.bottom;
    const brushHeight = 50;

    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', dimensions.width)
      .attr('height', height);

    const mainG = svg.append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    const brushG = svg.append('g')
      .attr('transform', `translate(${margin.left},${innerHeight + margin.top + 20})`);

    const xScale = scaleTime()
      .domain(extent(data, d => d.timestamp) as [Date, Date])
      .range([0, innerWidth]);

    const yScale = scaleLinear()
      .domain([0, max(data, d => Math.max(d.value, d.predicted || 0)) || 0])
      .nice()
      .range([innerHeight, 0]);

    const xScaleBrush = scaleTime()
      .domain(xScale.domain())
      .range([0, innerWidth]);

    const yScaleBrush = scaleLinear()
      .domain(yScale.domain())
      .range([brushHeight, 0]);

    const lineGenerator = line<TimeSeriesDataPoint>()
      .x(d => xScale(d.timestamp))
      .y(d => yScale(d.value))
      .curve(curveMonotoneX);

    const predictionLineGenerator = line<TimeSeriesDataPoint>()
      .defined(d => d.predicted !== undefined)
      .x(d => xScale(d.timestamp))
      .y(d => yScale(d.predicted || 0))
      .curve(curveMonotoneX);

    const areaGenerator = area<TimeSeriesDataPoint>()
      .x(d => xScale(d.timestamp))
      .y0(innerHeight)
      .y1(d => yScale(d.value))
      .curve(curveMonotoneX);

    mainG.append('defs')
      .append('clipPath')
      .attr('id', 'clip')
      .append('rect')
      .attr('width', innerWidth)
      .attr('height', innerHeight);

    const focus = mainG.append('g')
      .attr('clip-path', 'url(#clip)');

    if (showConfidenceBands) {
      const confidenceBands = calculateConfidenceBands(data);
      
      const confidenceArea = area<any>()
        .x(d => xScale(d.timestamp))
        .y0(d => yScale(d.lower))
        .y1(d => yScale(d.upper))
        .curve(curveMonotoneX);

      focus.append('path')
        .datum(confidenceBands)
        .attr('fill', '#2196F3')
        .attr('opacity', 0.1)
        .attr('d', confidenceArea);
    }

    focus.append('path')
      .datum(data)
      .attr('fill', 'rgba(33, 150, 243, 0.1)')
      .attr('d', areaGenerator);

    focus.append('path')
      .datum(data)
      .attr('fill', 'none')
      .attr('stroke', '#2196F3')
      .attr('stroke-width', 2)
      .attr('d', lineGenerator);

    if (showPredictions && data.some(d => d.predicted !== undefined)) {
      focus.append('path')
        .datum(data)
        .attr('fill', 'none')
        .attr('stroke', '#4CAF50')
        .attr('stroke-width', 2)
        .attr('stroke-dasharray', '5,5')
        .attr('d', predictionLineGenerator);
    }

    anomalyPeriods.forEach(period => {
      const x1 = xScale(period.start);
      const x2 = xScale(period.end);
      const color = period.severity === 'high' ? '#FF5252' : 
                    period.severity === 'medium' ? '#FFA726' : '#FFEE58';
      
      focus.append('rect')
        .attr('x', x1)
        .attr('y', 0)
        .attr('width', x2 - x1)
        .attr('height', innerHeight)
        .attr('fill', color)
        .attr('opacity', 0.2);
    });

    focus.selectAll('.anomaly')
      .data(detectedAnomalies)
      .enter()
      .append('circle')
      .attr('class', 'anomaly')
      .attr('cx', d => xScale(d.timestamp))
      .attr('cy', d => yScale(d.value))
      .attr('r', 5)
      .attr('fill', '#FF5252')
      .attr('stroke', '#fff')
      .attr('stroke-width', 2);

    const xAxis = axisBottom(xScale)
      .tickFormat(d3.timeFormat('%Y-%m-%d %H:%M') as any);

    const yAxis = axisLeft(yScale);

    mainG.append('g')
      .attr('transform', `translate(0,${innerHeight})`)
      .call(xAxis)
      .append('text')
      .attr('fill', '#000')
      .attr('x', innerWidth / 2)
      .attr('y', 40)
      .attr('text-anchor', 'middle')
      .text('Time');

    mainG.append('g')
      .call(yAxis)
      .append('text')
      .attr('fill', '#000')
      .attr('transform', 'rotate(-90)')
      .attr('y', -40)
      .attr('x', -innerHeight / 2)
      .attr('text-anchor', 'middle')
      .text(metric);

    const brushLineGenerator = line<TimeSeriesDataPoint>()
      .x(d => xScaleBrush(d.timestamp))
      .y(d => yScaleBrush(d.value))
      .curve(curveMonotoneX);

    brushG.append('path')
      .datum(data)
      .attr('fill', 'rgba(33, 150, 243, 0.3)')
      .attr('stroke', '#2196F3')
      .attr('stroke-width', 1)
      .attr('d', brushLineGenerator);

    const brushSelection = brush()
      .extent([[0, 0], [innerWidth, brushHeight]])
      .on('brush end', (event) => {
        if (!event.selection) {
          setSelectedTimeRange(null);
          xScale.domain(extent(data, d => d.timestamp) as [Date, Date]);
        } else {
          const [x0, x1] = event.selection as [number, number];
          const timeRange: [Date, Date] = [
            xScaleBrush.invert(x0),
            xScaleBrush.invert(x1),
          ];
          setSelectedTimeRange(timeRange);
          xScale.domain(timeRange);
        }

        focus.select('.line')
          .attr('d', lineGenerator);
        focus.selectAll('.anomaly')
          .attr('cx', (d: any) => xScale(d.timestamp))
          .attr('cy', (d: any) => yScale(d.value));
        mainG.select('.x-axis').call(axisBottom(xScale) as any);
      });

    brushG.append('g')
      .attr('class', 'brush')
      .call(brushSelection);

    const zoomBehavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 20])
      .translateExtent([[0, 0], [innerWidth, innerHeight]])
      .on('zoom', (event) => {
        const newXScale = event.transform.rescaleX(xScale);
        focus.select('.line')
          .attr('d', lineGenerator.x(d => newXScale(d.timestamp)));
        focus.selectAll('.anomaly')
          .attr('cx', (d: any) => newXScale(d.timestamp));
        mainG.select('.x-axis').call(axisBottom(newXScale) as any);
      });

    svg.call(zoomBehavior);

    const tooltip = d3.select('body').append('div')
      .attr('class', 'timeseries-tooltip')
      .style('position', 'absolute')
      .style('padding', '10px')
      .style('background', 'rgba(0, 0, 0, 0.8)')
      .style('color', 'white')
      .style('border-radius', '4px')
      .style('pointer-events', 'none')
      .style('opacity', 0);

    const bisect = bisector<TimeSeriesDataPoint, Date>(d => d.timestamp).left;

    svg.on('mousemove', (event) => {
      const [mouseX] = d3.pointer(event, mainG.node());
      const x0 = xScale.invert(mouseX);
      const i = bisect(data, x0, 1);
      const d0 = data[i - 1];
      const d1 = data[i];
      
      if (d0 && d1) {
        const d = x0.getTime() - d0.timestamp.getTime() > d1.timestamp.getTime() - x0.getTime() ? d1 : d0;
        
        tooltip
          .style('opacity', 1)
          .html(`
            <strong>${d.timestamp.toLocaleString()}</strong><br/>
            Value: ${d.value.toFixed(2)}<br/>
            ${d.predicted ? `Predicted: ${d.predicted.toFixed(2)}<br/>` : ''}
            ${d.isAnomaly ? '<span style="color: #FF5252">⚠ Anomaly Detected</span>' : ''}
          `)
          .style('left', `${event.pageX + 10}px`)
          .style('top', `${event.pageY - 10}px`);
      }
    })
    .on('mouseout', () => {
      tooltip.style('opacity', 0);
    });

    return () => {
      d3.selectAll('.timeseries-tooltip').remove();
    };

  }, [data, dimensions, height, detectedAnomalies, anomalyPeriods, showPredictions, showConfidenceBands, metric]);

  const detectAnomalies = (
    data: TimeSeriesDataPoint[],
    threshold: number,
    method: 'statistical' | 'ml'
  ): TimeSeriesDataPoint[] => {
    if (method === 'statistical') {
      const values = data.map(d => d.value);
      const meanValue = mean(values) || 0;
      const stdDev = deviation(values) || 0;
      
      return data.filter(d => {
        const zScore = Math.abs((d.value - meanValue) / stdDev);
        return zScore > threshold;
      }).map(d => ({ ...d, isAnomaly: true }));
    } else {
      const windowSize = 20;
      const anomalies: TimeSeriesDataPoint[] = [];
      
      for (let i = windowSize; i < data.length; i++) {
        const window = data.slice(i - windowSize, i);
        const windowMean = mean(window, d => d.value) || 0;
        const windowStdDev = deviation(window, d => d.value) || 0;
        
        const current = data[i];
        const zScore = Math.abs((current.value - windowMean) / windowStdDev);
        
        if (zScore > threshold) {
          anomalies.push({ ...current, isAnomaly: true, anomalyScore: zScore });
        }
      }
      
      return anomalies;
    }
  };

  const identifyAnomalyPeriods = (anomalies: TimeSeriesDataPoint[]): AnomalyPeriod[] => {
    if (anomalies.length === 0) return [];
    
    const periods: AnomalyPeriod[] = [];
    let currentPeriod: AnomalyPeriod | null = null;
    const maxGap = 5 * 60 * 1000;
    
    anomalies.forEach((anomaly, index) => {
      if (!currentPeriod) {
        currentPeriod = {
          start: anomaly.timestamp,
          end: anomaly.timestamp,
          severity: getAnomalySeverity(anomaly.anomalyScore || 0),
          description: 'Anomaly detected',
        };
      } else {
        const timeDiff = anomaly.timestamp.getTime() - currentPeriod.end.getTime();
        
        if (timeDiff <= maxGap) {
          currentPeriod.end = anomaly.timestamp;
          currentPeriod.severity = getAnomalySeverity(
            Math.max(anomaly.anomalyScore || 0, getSeverityScore(currentPeriod.severity))
          );
        } else {
          periods.push(currentPeriod);
          currentPeriod = {
            start: anomaly.timestamp,
            end: anomaly.timestamp,
            severity: getAnomalySeverity(anomaly.anomalyScore || 0),
            description: 'Anomaly detected',
          };
        }
      }
      
      if (index === anomalies.length - 1 && currentPeriod) {
        periods.push(currentPeriod);
      }
    });
    
    return periods;
  };

  const getAnomalySeverity = (score: number): 'low' | 'medium' | 'high' => {
    if (score > 4) return 'high';
    if (score > 3) return 'medium';
    return 'low';
  };

  const getSeverityScore = (severity: 'low' | 'medium' | 'high'): number => {
    switch (severity) {
      case 'high': return 5;
      case 'medium': return 3.5;
      case 'low': return 2.5;
    }
  };

  const calculateConfidenceBands = (data: TimeSeriesDataPoint[]) => {
    const windowSize = 10;
    return data.map((d, i) => {
      const start = Math.max(0, i - windowSize);
      const end = Math.min(data.length, i + windowSize);
      const window = data.slice(start, end);
      const windowMean = mean(window, d => d.value) || 0;
      const windowStdDev = deviation(window, d => d.value) || 0;
      
      return {
        timestamp: d.timestamp,
        upper: windowMean + 2 * windowStdDev,
        lower: Math.max(0, windowMean - 2 * windowStdDev),
      };
    });
  };

  return (
    <Card>
      <CardContent>
        <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h6">{title}</Typography>
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <ButtonGroup size="small" variant="outlined">
              <Button
                variant={anomalyDetectionMethod === 'statistical' ? 'contained' : 'outlined'}
                onClick={() => setAnomalyDetectionMethod('statistical')}
              >
                Statistical
              </Button>
              <Button
                variant={anomalyDetectionMethod === 'ml' ? 'contained' : 'outlined'}
                onClick={() => setAnomalyDetectionMethod('ml')}
              >
                ML-Based
              </Button>
            </ButtonGroup>
            <FormControlLabel
              control={
                <Switch
                  checked={showConfidenceBands}
                  onChange={(e) => setShowConfidenceBands(e.target.checked)}
                />
              }
              label="Confidence Bands"
            />
          </Box>
        </Box>

        {detectedAnomalies.length > 0 && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            {detectedAnomalies.length} anomalies detected in the selected time range
          </Alert>
        )}

        <Box sx={{ mb: 2, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          {anomalyPeriods.slice(0, 3).map((period, index) => (
            <Chip
              key={index}
              label={`${period.start.toLocaleTimeString()} - ${period.end.toLocaleTimeString()}`}
              color={period.severity === 'high' ? 'error' : period.severity === 'medium' ? 'warning' : 'default'}
              size="small"
            />
          ))}
          {anomalyPeriods.length > 3 && (
            <Chip
              label={`+${anomalyPeriods.length - 3} more`}
              size="small"
            />
          )}
        </Box>

        <Box ref={containerRef} sx={{ width: '100%', height }}>
          <svg ref={svgRef} />
        </Box>

        <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between' }}>
          <Typography variant="caption" color="text.secondary">
            Drag on the timeline below to zoom into specific time ranges
          </Typography>
          {selectedTimeRange && (
            <Typography variant="caption" color="text.secondary">
              Selected: {selectedTimeRange[0].toLocaleString()} - {selectedTimeRange[1].toLocaleString()}
            </Typography>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default TimeSeriesAnalysis;