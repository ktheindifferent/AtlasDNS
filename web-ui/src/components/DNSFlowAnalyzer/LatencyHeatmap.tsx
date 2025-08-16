import React, { useRef, useEffect, useState } from 'react';
import { Box, Paper, Typography, FormControl, Select, MenuItem, Chip, SelectChangeEvent } from '@mui/material';
import * as d3 from 'd3';
import { geoPath, geoNaturalEarth1, geoGraticule } from 'd3-geo';
import { scaleSequential } from 'd3-scale';
import { interpolateYlOrRd } from 'd3-scale-chromatic';
import { DNSQuery, HeatmapData, GeoLocation } from './types';
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';

// Fix for default markers
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require('leaflet/dist/images/marker-icon-2x.png'),
  iconUrl: require('leaflet/dist/images/marker-icon.png'),
  shadowUrl: require('leaflet/dist/images/marker-shadow.png'),
});

interface LatencyHeatmapProps {
  queries: DNSQuery[];
  width?: number;
  height?: number;
}

type ViewMode = 'd3' | 'leaflet';

const LatencyHeatmap: React.FC<LatencyHeatmapProps> = ({ 
  queries, 
  width = 1200, 
  height = 600 
}) => {
  const svgRef = useRef<SVGSVGElement>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('leaflet');
  const [heatmapData, setHeatmapData] = useState<HeatmapData[]>([]);
  const [selectedMetric, setSelectedMetric] = useState<'avg' | 'max' | 'count'>('avg');

  useEffect(() => {
    // Process queries to create heatmap data
    const locationMap = new Map<string, HeatmapData>();

    queries.forEach(query => {
      if (query.geoLocation) {
        const key = `${query.geoLocation.lat},${query.geoLocation.lng}`;
        
        if (!locationMap.has(key)) {
          locationMap.set(key, {
            lat: query.geoLocation.lat,
            lng: query.geoLocation.lng,
            value: 0,
            count: 0,
            avgLatency: 0,
            maxLatency: 0,
            minLatency: Infinity,
          });
        }

        const data = locationMap.get(key)!;
        data.count += 1;
        data.avgLatency = (data.avgLatency * (data.count - 1) + query.latency) / data.count;
        data.maxLatency = Math.max(data.maxLatency, query.latency);
        data.minLatency = Math.min(data.minLatency, query.latency);
        
        // Set value based on selected metric
        switch (selectedMetric) {
          case 'avg':
            data.value = data.avgLatency;
            break;
          case 'max':
            data.value = data.maxLatency;
            break;
          case 'count':
            data.value = data.count;
            break;
        }
      }
    });

    setHeatmapData(Array.from(locationMap.values()));
  }, [queries, selectedMetric]);

  useEffect(() => {
    if (viewMode !== 'd3' || !svgRef.current || heatmapData.length === 0) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const projection = geoNaturalEarth1()
      .scale(width / 7)
      .translate([width / 2, height / 2]);

    const path = geoPath().projection(projection);

    const g = svg.append('g');

    // Add graticule
    const graticule = geoGraticule();
    g.append('path')
      .datum(graticule)
      .attr('class', 'graticule')
      .attr('d', path)
      .attr('fill', 'none')
      .attr('stroke', '#ccc')
      .attr('stroke-width', 0.5)
      .attr('stroke-opacity', 0.5);

    // Load world map data (simplified for performance)
    d3.json('https://cdn.jsdelivr.net/npm/world-atlas@2/land-110m.json').then((world: any) => {
      // Draw countries
      g.append('path')
        .datum(world)
        .attr('class', 'land')
        .attr('d', path)
        .attr('fill', '#2a2a2a')
        .attr('stroke', '#444')
        .attr('stroke-width', 0.5);

      // Create color scale
      const maxValue = Math.max(...heatmapData.map(d => d.value));
      const colorScale = scaleSequential(interpolateYlOrRd)
        .domain([0, maxValue]);

      // Add heatmap circles
      const circles = g.selectAll('.heatmap-circle')
        .data(heatmapData)
        .enter().append('circle')
        .attr('class', 'heatmap-circle')
        .attr('cx', d => {
          const coords = projection([d.lng, d.lat]);
          return coords ? coords[0] : 0;
        })
        .attr('cy', d => {
          const coords = projection([d.lng, d.lat]);
          return coords ? coords[1] : 0;
        })
        .attr('r', d => Math.sqrt(d.count) * 2)
        .attr('fill', d => colorScale(d.value))
        .attr('fill-opacity', 0.7)
        .attr('stroke', '#fff')
        .attr('stroke-width', 0.5)
        .on('mouseover', function(event, d) {
          d3.select(this)
            .attr('stroke-width', 2)
            .attr('fill-opacity', 1);

          // Show tooltip
          const tooltip = d3.select('body').append('div')
            .attr('class', 'heatmap-tooltip')
            .style('position', 'absolute')
            .style('padding', '10px')
            .style('background', 'rgba(0, 0, 0, 0.9)')
            .style('color', 'white')
            .style('border-radius', '5px')
            .style('pointer-events', 'none')
            .style('font-size', '12px');

          tooltip.html(`
            <strong>Location: ${d.lat.toFixed(2)}, ${d.lng.toFixed(2)}</strong><br/>
            Queries: ${d.count}<br/>
            Avg Latency: ${d.avgLatency.toFixed(2)}ms<br/>
            Max Latency: ${d.maxLatency.toFixed(2)}ms<br/>
            Min Latency: ${d.minLatency.toFixed(2)}ms
          `)
            .style('left', (event.pageX + 10) + 'px')
            .style('top', (event.pageY - 10) + 'px');
        })
        .on('mouseout', function() {
          d3.select(this)
            .attr('stroke-width', 0.5)
            .attr('fill-opacity', 0.7);
          d3.selectAll('.heatmap-tooltip').remove();
        });

      // Animate circles
      circles
        .attr('r', 0)
        .transition()
        .duration(1000)
        .attr('r', d => Math.sqrt(d.count) * 2);

      // Add legend
      const legendWidth = 200;
      const legendHeight = 20;
      const legend = svg.append('g')
        .attr('class', 'legend')
        .attr('transform', `translate(${width - legendWidth - 20}, ${height - 40})`);

      const legendScale = d3.scaleLinear()
        .domain([0, maxValue])
        .range([0, legendWidth]);

      const legendAxis = d3.axisBottom(legendScale)
        .ticks(5)
        .tickFormat(d => {
          if (selectedMetric === 'count') return d.toString();
          return `${d}ms`;
        });

      legend.append('g')
        .attr('transform', `translate(0, ${legendHeight})`)
        .call(legendAxis);

      // Create gradient for legend
      const gradientId = 'legend-gradient';
      const gradient = svg.append('defs')
        .append('linearGradient')
        .attr('id', gradientId)
        .attr('x1', '0%')
        .attr('x2', '100%')
        .attr('y1', '0%')
        .attr('y2', '0%');

      const steps = 10;
      for (let i = 0; i <= steps; i++) {
        gradient.append('stop')
          .attr('offset', `${(i / steps) * 100}%`)
          .attr('stop-color', colorScale(maxValue * (i / steps)));
      }

      legend.append('rect')
        .attr('width', legendWidth)
        .attr('height', legendHeight)
        .style('fill', `url(#${gradientId})`);

      legend.append('text')
        .attr('x', legendWidth / 2)
        .attr('y', -5)
        .attr('text-anchor', 'middle')
        .attr('font-size', '12px')
        .text(selectedMetric === 'avg' ? 'Average Latency' : 
              selectedMetric === 'max' ? 'Maximum Latency' : 'Query Count');
    });

    // Add zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 8])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

  }, [viewMode, heatmapData, width, height, selectedMetric]);

  const getColorForLatency = (latency: number): string => {
    if (latency < 50) return '#4caf50';
    if (latency < 100) return '#8bc34a';
    if (latency < 150) return '#ffeb3b';
    if (latency < 200) return '#ff9800';
    if (latency < 300) return '#ff5722';
    return '#f44336';
  };

  const handleMetricChange = (event: SelectChangeEvent) => {
    setSelectedMetric(event.target.value as 'avg' | 'max' | 'count');
  };

  const handleViewModeChange = (event: SelectChangeEvent) => {
    setViewMode(event.target.value as ViewMode);
  };

  return (
    <Paper sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h6">
          DNS Latency Geographic Distribution
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <FormControl size="small">
            <Select value={selectedMetric} onChange={handleMetricChange}>
              <MenuItem value="avg">Average Latency</MenuItem>
              <MenuItem value="max">Maximum Latency</MenuItem>
              <MenuItem value="count">Query Count</MenuItem>
            </Select>
          </FormControl>
          <FormControl size="small">
            <Select value={viewMode} onChange={handleViewModeChange}>
              <MenuItem value="leaflet">Interactive Map</MenuItem>
              <MenuItem value="d3">D3 Projection</MenuItem>
            </Select>
          </FormControl>
        </Box>
      </Box>

      <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
        <Chip label={`${heatmapData.length} Locations`} size="small" />
        <Chip label={`${queries.length} Total Queries`} size="small" />
        {heatmapData.length > 0 && (
          <Chip 
            label={`Avg: ${(heatmapData.reduce((sum, d) => sum + d.avgLatency, 0) / heatmapData.length).toFixed(1)}ms`} 
            size="small" 
          />
        )}
      </Box>

      {viewMode === 'leaflet' ? (
        <Box sx={{ flex: 1, position: 'relative' }}>
          <MapContainer
            center={[20, 0]}
            zoom={2}
            style={{ height: '100%', width: '100%' }}
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
            />
            {heatmapData.map((point, index) => (
              <CircleMarker
                key={index}
                center={[point.lat, point.lng]}
                radius={Math.sqrt(point.count) * 3}
                fillColor={getColorForLatency(point.avgLatency)}
                color="#fff"
                weight={1}
                opacity={1}
                fillOpacity={0.7}
              >
                <Popup>
                  <div>
                    <strong>Location: {point.lat.toFixed(2)}, {point.lng.toFixed(2)}</strong><br />
                    Queries: {point.count}<br />
                    Avg Latency: {point.avgLatency.toFixed(2)}ms<br />
                    Max Latency: {point.maxLatency.toFixed(2)}ms<br />
                    Min Latency: {point.minLatency.toFixed(2)}ms
                  </div>
                </Popup>
              </CircleMarker>
            ))}
          </MapContainer>
        </Box>
      ) : (
        <Box sx={{ flex: 1 }}>
          <svg ref={svgRef} width={width} height={height} />
        </Box>
      )}
    </Paper>
  );
};

export default LatencyHeatmap;