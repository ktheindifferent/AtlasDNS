import React, { useEffect, useRef, useState } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet';
import { Card, CardContent, Typography, Box, Button, ButtonGroup, Slider } from '@mui/material';
import { scaleLinear, scaleSequential } from 'd3-scale';
import { interpolateYlOrRd } from 'd3-scale-chromatic';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

interface QueryOrigin {
  lat: number;
  lng: number;
  city: string;
  country: string;
  queries: number;
  avgResponseTime: number;
  lastSeen: string;
}

interface GeographicHeatMapProps {
  data?: QueryOrigin[];
  height?: number;
  title?: string;
  refreshInterval?: number;
  onLocationClick?: (location: QueryOrigin) => void;
}

const MapUpdater: React.FC<{ center: [number, number]; zoom: number }> = ({ center, zoom }) => {
  const map = useMap();
  useEffect(() => {
    map.setView(center, zoom);
  }, [center, zoom, map]);
  return null;
};

const GeographicHeatMap: React.FC<GeographicHeatMapProps> = ({
  data = [],
  height = 400,
  title = 'DNS Query Origins',
  refreshInterval = 30000,
  onLocationClick,
}) => {
  const [mapData, setMapData] = useState<QueryOrigin[]>(data);
  const [heatmapIntensity, setHeatmapIntensity] = useState(50);
  const [selectedMetric, setSelectedMetric] = useState<'queries' | 'responseTime'>('queries');
  const [mapCenter, setMapCenter] = useState<[number, number]>([20, 0]);
  const [mapZoom, setMapZoom] = useState(2);
  const mapRef = useRef<L.Map | null>(null);

  useEffect(() => {
    setMapData(data);
  }, [data]);

  const maxValue = Math.max(...mapData.map(d => 
    selectedMetric === 'queries' ? d.queries : d.avgResponseTime
  ));
  const minValue = Math.min(...mapData.map(d => 
    selectedMetric === 'queries' ? d.queries : d.avgResponseTime
  ));

  const colorScale = scaleSequential(interpolateYlOrRd)
    .domain([minValue, maxValue]);

  const radiusScale = scaleLinear()
    .domain([minValue, maxValue])
    .range([5, 30]);

  const getColor = (value: number) => {
    return colorScale(value);
  };

  const getRadius = (value: number) => {
    const baseRadius = radiusScale(value);
    return baseRadius * (heatmapIntensity / 50);
  };

  const handleReset = () => {
    setMapCenter([20, 0]);
    setMapZoom(2);
  };

  const handleZoomToHotspot = () => {
    if (mapData.length > 0) {
      const hotspot = mapData.reduce((prev, current) => 
        (current.queries > prev.queries) ? current : prev
      );
      setMapCenter([hotspot.lat, hotspot.lng]);
      setMapZoom(6);
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
                variant={selectedMetric === 'queries' ? 'contained' : 'outlined'}
                onClick={() => setSelectedMetric('queries')}
              >
                Queries
              </Button>
              <Button 
                variant={selectedMetric === 'responseTime' ? 'contained' : 'outlined'}
                onClick={() => setSelectedMetric('responseTime')}
              >
                Response Time
              </Button>
            </ButtonGroup>
            <Button size="small" variant="outlined" onClick={handleZoomToHotspot}>
              Zoom to Hotspot
            </Button>
            <Button size="small" variant="outlined" onClick={handleReset}>
              Reset View
            </Button>
          </Box>
        </Box>

        <Box sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="body2">Intensity:</Typography>
          <Slider
            value={heatmapIntensity}
            onChange={(_, value) => setHeatmapIntensity(value as number)}
            min={10}
            max={100}
            sx={{ width: 200 }}
            valueLabelDisplay="auto"
          />
        </Box>

        <Box sx={{ height, position: 'relative' }}>
          <MapContainer
            center={mapCenter}
            zoom={mapZoom}
            style={{ height: '100%', width: '100%' }}
            ref={mapRef}
          >
            <TileLayer
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            <MapUpdater center={mapCenter} zoom={mapZoom} />
            {mapData.map((location, index) => {
              const value = selectedMetric === 'queries' ? location.queries : location.avgResponseTime;
              return (
                <CircleMarker
                  key={index}
                  center={[location.lat, location.lng]}
                  radius={getRadius(value)}
                  fillColor={getColor(value)}
                  fillOpacity={0.7}
                  color={getColor(value)}
                  weight={2}
                  eventHandlers={{
                    click: () => onLocationClick?.(location),
                  }}
                >
                  <Popup>
                    <Box>
                      <Typography variant="subtitle2" fontWeight="bold">
                        {location.city}, {location.country}
                      </Typography>
                      <Typography variant="body2">
                        Queries: {location.queries.toLocaleString()}
                      </Typography>
                      <Typography variant="body2">
                        Avg Response: {location.avgResponseTime}ms
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Last seen: {new Date(location.lastSeen).toLocaleString()}
                      </Typography>
                    </Box>
                  </Popup>
                </CircleMarker>
              );
            })}
          </MapContainer>
        </Box>

        <Box sx={{ mt: 2, display: 'flex', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="caption" color="text.secondary">Low</Typography>
            <Box sx={{ 
              width: 100, 
              height: 10, 
              background: `linear-gradient(to right, ${colorScale(minValue)}, ${colorScale(maxValue)})`,
              borderRadius: 1,
            }} />
            <Typography variant="caption" color="text.secondary">High</Typography>
          </Box>
          <Typography variant="caption" color="text.secondary">
            {mapData.length} locations tracked
          </Typography>
        </Box>
      </CardContent>
    </Card>
  );
};

export default GeographicHeatMap;