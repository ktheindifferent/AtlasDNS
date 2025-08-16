import React, { useRef, useEffect, useState, useMemo } from 'react';
import { Box, Paper, Typography, Chip } from '@mui/material';
import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls';
import { CSS2DRenderer, CSS2DObject } from 'three/examples/jsm/renderers/CSS2DRenderer';
import { DNSQuery, DNSNode } from './types';

interface FlowDiagramProps {
  queries: DNSQuery[];
  anomalies: DNSQuery[];
  currentTime: number;
  isPlaying: boolean;
}

interface NodePosition {
  id: string;
  position: THREE.Vector3;
  type: string;
  connections: Set<string>;
}

const FlowDiagram: React.FC<FlowDiagramProps> = ({
  queries,
  anomalies,
  currentTime,
  isPlaying,
}) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const sceneRef = useRef<THREE.Scene | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const labelRendererRef = useRef<CSS2DRenderer | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const animationIdRef = useRef<number | null>(null);
  const particlesRef = useRef<Map<string, THREE.Points>>(new Map());
  const connectionsRef = useRef<Map<string, THREE.Line>>(new Map());
  const nodesRef = useRef<Map<string, NodePosition>>(new Map());

  useEffect(() => {
    if (!mountRef.current) return;

    // Initialize Three.js scene
    const width = mountRef.current.clientWidth;
    const height = mountRef.current.clientHeight;

    // Scene
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x0a0a0a);
    scene.fog = new THREE.Fog(0x0a0a0a, 100, 1000);
    sceneRef.current = scene;

    // Camera
    const camera = new THREE.PerspectiveCamera(75, width / height, 0.1, 1000);
    camera.position.set(0, 50, 100);
    cameraRef.current = camera;

    // Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(window.devicePixelRatio);
    mountRef.current.appendChild(renderer.domElement);
    rendererRef.current = renderer;

    // CSS2D Renderer for labels
    const labelRenderer = new CSS2DRenderer();
    labelRenderer.setSize(width, height);
    labelRenderer.domElement.style.position = 'absolute';
    labelRenderer.domElement.style.top = '0px';
    labelRenderer.domElement.style.pointerEvents = 'none';
    mountRef.current.appendChild(labelRenderer.domElement);
    labelRendererRef.current = labelRenderer;

    // Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.screenSpacePanning = false;
    controls.minDistance = 10;
    controls.maxDistance = 500;
    controlsRef.current = controls;

    // Lighting
    const ambientLight = new THREE.AmbientLight(0x404040);
    scene.add(ambientLight);

    const directionalLight = new THREE.DirectionalLight(0xffffff, 0.5);
    directionalLight.position.set(1, 1, 1);
    scene.add(directionalLight);

    const pointLight = new THREE.PointLight(0x4fc3f7, 1, 100);
    pointLight.position.set(0, 20, 0);
    scene.add(pointLight);

    // Grid
    const gridHelper = new THREE.GridHelper(200, 20, 0x444444, 0x222222);
    scene.add(gridHelper);

    // Handle resize
    const handleResize = () => {
      if (!mountRef.current) return;
      const width = mountRef.current.clientWidth;
      const height = mountRef.current.clientHeight;
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      renderer.setSize(width, height);
      labelRenderer.setSize(width, height);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      if (mountRef.current && renderer.domElement) {
        mountRef.current.removeChild(renderer.domElement);
      }
      if (mountRef.current && labelRenderer.domElement) {
        mountRef.current.removeChild(labelRenderer.domElement);
      }
      renderer.dispose();
      if (animationIdRef.current) {
        cancelAnimationFrame(animationIdRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (!sceneRef.current) return;

    // Clear existing nodes and connections
    nodesRef.current.clear();
    particlesRef.current.forEach(particles => {
      sceneRef.current!.remove(particles);
    });
    particlesRef.current.clear();
    connectionsRef.current.forEach(line => {
      sceneRef.current!.remove(line);
    });
    connectionsRef.current.clear();

    // Process queries to create network topology
    const nodeMap = new Map<string, NodePosition>();
    const connections = new Map<string, Set<string>>();

    queries.forEach(query => {
      // Add source node
      if (!nodeMap.has(query.source)) {
        const position = new THREE.Vector3(
          (Math.random() - 0.5) * 100,
          Math.random() * 20,
          (Math.random() - 0.5) * 100
        );
        nodeMap.set(query.source, {
          id: query.source,
          position,
          type: 'client',
          connections: new Set(),
        });
      }

      // Add destination nodes
      if (!nodeMap.has(query.destination)) {
        const position = new THREE.Vector3(
          (Math.random() - 0.5) * 100,
          Math.random() * 20 + 20,
          (Math.random() - 0.5) * 100
        );
        nodeMap.set(query.destination, {
          id: query.destination,
          position,
          type: 'server',
          connections: new Set(),
        });
      }

      // Add path nodes
      query.path?.forEach((node, index) => {
        if (!nodeMap.has(node.id)) {
          const angle = (index / (query.path.length - 1)) * Math.PI;
          const position = new THREE.Vector3(
            Math.cos(angle) * 50,
            10 + index * 5,
            Math.sin(angle) * 50
          );
          nodeMap.set(node.id, {
            id: node.id,
            position,
            type: node.type,
            connections: new Set(),
          });
        }
      });

      // Create connections
      const sourceNode = nodeMap.get(query.source)!;
      const destNode = nodeMap.get(query.destination)!;
      sourceNode.connections.add(query.destination);
      
      if (query.path && query.path.length > 0) {
        let prevId = query.source;
        query.path.forEach(node => {
          const prevNode = nodeMap.get(prevId)!;
          prevNode.connections.add(node.id);
          prevId = node.id;
        });
        const lastPathNode = nodeMap.get(prevId)!;
        lastPathNode.connections.add(query.destination);
      }
    });

    nodesRef.current = nodeMap;

    // Create visual nodes
    nodeMap.forEach((node, id) => {
      const geometry = new THREE.SphereGeometry(2, 32, 32);
      let material: THREE.MeshPhongMaterial;
      
      switch (node.type) {
        case 'client':
          material = new THREE.MeshPhongMaterial({ 
            color: 0x4fc3f7,
            emissive: 0x4fc3f7,
            emissiveIntensity: 0.2,
          });
          break;
        case 'server':
        case 'authoritative':
          material = new THREE.MeshPhongMaterial({ 
            color: 0x66bb6a,
            emissive: 0x66bb6a,
            emissiveIntensity: 0.2,
          });
          break;
        case 'resolver':
          material = new THREE.MeshPhongMaterial({ 
            color: 0xffa726,
            emissive: 0xffa726,
            emissiveIntensity: 0.2,
          });
          break;
        case 'cache':
          material = new THREE.MeshPhongMaterial({ 
            color: 0xab47bc,
            emissive: 0xab47bc,
            emissiveIntensity: 0.2,
          });
          break;
        default:
          material = new THREE.MeshPhongMaterial({ 
            color: 0x757575,
            emissive: 0x757575,
            emissiveIntensity: 0.2,
          });
      }

      const mesh = new THREE.Mesh(geometry, material);
      mesh.position.copy(node.position);
      sceneRef.current!.add(mesh);

      // Add label
      const labelDiv = document.createElement('div');
      labelDiv.className = 'node-label';
      labelDiv.textContent = id.substring(0, 20);
      labelDiv.style.color = 'white';
      labelDiv.style.fontSize = '12px';
      labelDiv.style.backgroundColor = 'rgba(0, 0, 0, 0.6)';
      labelDiv.style.padding = '2px 6px';
      labelDiv.style.borderRadius = '3px';
      const label = new CSS2DObject(labelDiv);
      label.position.set(0, 3, 0);
      mesh.add(label);

      // Check if this is an anomaly
      const isAnomaly = anomalies.some(a => a.source === id || a.destination === id);
      if (isAnomaly) {
        const pulseGeometry = new THREE.RingGeometry(3, 4, 32);
        const pulseMaterial = new THREE.MeshBasicMaterial({
          color: 0xff0000,
          transparent: true,
          opacity: 0.5,
        });
        const pulseMesh = new THREE.Mesh(pulseGeometry, pulseMaterial);
        pulseMesh.position.copy(node.position);
        pulseMesh.lookAt(cameraRef.current!.position);
        sceneRef.current!.add(pulseMesh);
      }
    });

    // Create connections
    nodeMap.forEach((sourceNode, sourceId) => {
      sourceNode.connections.forEach(targetId => {
        const targetNode = nodeMap.get(targetId);
        if (!targetNode) return;

        const points = [];
        points.push(sourceNode.position);
        
        // Add curve to make connections more visible
        const midPoint = new THREE.Vector3()
          .addVectors(sourceNode.position, targetNode.position)
          .multiplyScalar(0.5);
        midPoint.y += 10;
        points.push(midPoint);
        
        points.push(targetNode.position);

        const curve = new THREE.CatmullRomCurve3(points);
        const curvePoints = curve.getPoints(50);
        const geometry = new THREE.BufferGeometry().setFromPoints(curvePoints);
        
        const material = new THREE.LineBasicMaterial({
          color: 0x00ff00,
          opacity: 0.6,
          transparent: true,
        });

        const line = new THREE.Line(geometry, material);
        sceneRef.current!.add(line);
        connectionsRef.current.set(`${sourceId}-${targetId}`, line);
      });
    });

    // Create particle system for active queries
    const particleGeometry = new THREE.BufferGeometry();
    const particleCount = 1000;
    const positions = new Float32Array(particleCount * 3);
    const colors = new Float32Array(particleCount * 3);

    for (let i = 0; i < particleCount; i++) {
      positions[i * 3] = (Math.random() - 0.5) * 200;
      positions[i * 3 + 1] = Math.random() * 100;
      positions[i * 3 + 2] = (Math.random() - 0.5) * 200;

      colors[i * 3] = 0.0;
      colors[i * 3 + 1] = 1.0;
      colors[i * 3 + 2] = 0.0;
    }

    particleGeometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    particleGeometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const particleMaterial = new THREE.PointsMaterial({
      size: 0.5,
      vertexColors: true,
      transparent: true,
      opacity: 0.8,
    });

    const particles = new THREE.Points(particleGeometry, particleMaterial);
    sceneRef.current!.add(particles);
    particlesRef.current.set('main', particles);
  }, [queries, anomalies]);

  useEffect(() => {
    if (!sceneRef.current || !rendererRef.current || !cameraRef.current || !labelRendererRef.current) return;

    const animate = () => {
      animationIdRef.current = requestAnimationFrame(animate);

      // Update controls
      if (controlsRef.current) {
        controlsRef.current.update();
      }

      // Animate particles
      particlesRef.current.forEach(particles => {
        const positions = particles.geometry.attributes.position.array as Float32Array;
        for (let i = 0; i < positions.length; i += 3) {
          positions[i + 1] += 0.1;
          if (positions[i + 1] > 100) {
            positions[i + 1] = 0;
          }
        }
        particles.geometry.attributes.position.needsUpdate = true;

        if (isPlaying) {
          particles.rotation.y += 0.001;
        }
      });

      // Animate connections based on current time
      if (isPlaying) {
        connectionsRef.current.forEach((line, key) => {
          const material = line.material as THREE.LineBasicMaterial;
          const pulse = (Math.sin(currentTime * 0.01) + 1) / 2;
          material.opacity = 0.3 + pulse * 0.4;
        });
      }

      // Render
      rendererRef.current!.render(sceneRef.current!, cameraRef.current!);
      labelRendererRef.current!.render(sceneRef.current!, cameraRef.current!);
    };

    animate();

    return () => {
      if (animationIdRef.current) {
        cancelAnimationFrame(animationIdRef.current);
      }
    };
  }, [isPlaying, currentTime]);

  return (
    <Box sx={{ width: '100%', height: '100%', position: 'relative' }}>
      <Box ref={mountRef} sx={{ width: '100%', height: '100%' }} />
      <Paper
        sx={{
          position: 'absolute',
          top: 16,
          left: 16,
          p: 2,
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          color: 'white',
        }}
      >
        <Typography variant="h6" gutterBottom>
          DNS Query Flow
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
          <Chip label="Client" sx={{ backgroundColor: '#4fc3f7', color: 'white' }} size="small" />
          <Chip label="Resolver" sx={{ backgroundColor: '#ffa726', color: 'white' }} size="small" />
          <Chip label="Authoritative" sx={{ backgroundColor: '#66bb6a', color: 'white' }} size="small" />
          <Chip label="Cache" sx={{ backgroundColor: '#ab47bc', color: 'white' }} size="small" />
        </Box>
        {anomalies.length > 0 && (
          <Typography variant="body2" sx={{ mt: 1, color: '#ff5252' }}>
            ⚠ {anomalies.length} anomalies detected
          </Typography>
        )}
      </Paper>
    </Box>
  );
};

export default FlowDiagram;