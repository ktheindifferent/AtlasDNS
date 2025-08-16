import React, { useState, useRef, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogTitle,
  Box,
  Typography,
  IconButton,
  Button,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  Slider,
  Chip,
  Paper,
  TextField,
  Tab,
  Tabs,
  Divider,
  LinearProgress,
  Tooltip,
  SpeedDial,
  SpeedDialAction,
  Collapse,
  Alert,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Close as CloseIcon,
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  VolumeUp as VolumeIcon,
  VolumeOff as MuteIcon,
  Fullscreen as FullscreenIcon,
  Speed as SpeedIcon,
  Subtitles as SubtitlesIcon,
  SkipNext as SkipNextIcon,
  SkipPrevious as SkipPreviousIcon,
  Replay10 as Replay10Icon,
  Forward10 as Forward10Icon,
  PictureInPicture as PipIcon,
  GetApp as DownloadIcon,
  Share as ShareIcon,
  Bookmark as BookmarkIcon,
  Notes as NotesIcon,
  QuestionAnswer as QAIcon,
} from '@mui/icons-material';
import { VideoSnippet } from './types';
import { useDispatch } from 'react-redux';
import { recordInteraction } from '../../store/slices/helpSlice';

interface VideoSnippetPlayerProps {
  open: boolean;
  onClose: () => void;
  video: VideoSnippet;
  context?: any;
  autoPlay?: boolean;
  startTime?: number;
}

interface VideoNote {
  timestamp: number;
  note: string;
  id: string;
}

const VideoSnippetPlayer: React.FC<VideoSnippetPlayerProps> = ({
  open,
  onClose,
  video,
  context,
  autoPlay = false,
  startTime = 0,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch();
  const videoRef = useRef<HTMLVideoElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  
  const [isPlaying, setIsPlaying] = useState(autoPlay);
  const [currentTime, setCurrentTime] = useState(startTime);
  const [duration, setDuration] = useState(0);
  const [volume, setVolume] = useState(1);
  const [isMuted, setIsMuted] = useState(false);
  const [playbackRate, setPlaybackRate] = useState(1);
  const [showControls, setShowControls] = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  const [notes, setNotes] = useState<VideoNote[]>([]);
  const [newNote, setNewNote] = useState('');
  const [isBookmarked, setIsBookmarked] = useState(false);
  const [showTranscript, setShowTranscript] = useState(false);
  const [selectedChapter, setSelectedChapter] = useState<number | null>(null);
  const [buffered, setBuffered] = useState(0);
  
  useEffect(() => {
    if (open) {
      dispatch(recordInteraction({
        type: 'video',
        context: context || { page: 'unknown' },
        query: video.title,
      }));
    }
  }, [open, video, context, dispatch]);
  
  useEffect(() => {
    const videoElement = videoRef.current;
    if (videoElement) {
      videoElement.currentTime = startTime;
      if (autoPlay) {
        videoElement.play();
      }
    }
  }, [startTime, autoPlay]);
  
  useEffect(() => {
    const interval = setInterval(() => {
      if (videoRef.current) {
        setCurrentTime(videoRef.current.currentTime);
        
        // Update buffered amount
        if (videoRef.current.buffered.length > 0) {
          const bufferedEnd = videoRef.current.buffered.end(videoRef.current.buffered.length - 1);
          setBuffered((bufferedEnd / videoRef.current.duration) * 100);
        }
      }
    }, 100);
    
    return () => clearInterval(interval);
  }, []);
  
  const handlePlayPause = () => {
    if (videoRef.current) {
      if (isPlaying) {
        videoRef.current.pause();
      } else {
        videoRef.current.play();
      }
      setIsPlaying(!isPlaying);
    }
  };
  
  const handleSeek = (newValue: number) => {
    if (videoRef.current) {
      videoRef.current.currentTime = newValue;
      setCurrentTime(newValue);
    }
  };
  
  const handleVolumeChange = (newValue: number) => {
    if (videoRef.current) {
      videoRef.current.volume = newValue;
      setVolume(newValue);
      setIsMuted(newValue === 0);
    }
  };
  
  const handleMute = () => {
    if (videoRef.current) {
      videoRef.current.muted = !isMuted;
      setIsMuted(!isMuted);
    }
  };
  
  const handleSpeedChange = (speed: number) => {
    if (videoRef.current) {
      videoRef.current.playbackRate = speed;
      setPlaybackRate(speed);
    }
  };
  
  const handleFullscreen = () => {
    if (containerRef.current) {
      if (document.fullscreenElement) {
        document.exitFullscreen();
      } else {
        containerRef.current.requestFullscreen();
      }
    }
  };
  
  const handlePictureInPicture = async () => {
    if (videoRef.current) {
      try {
        if (document.pictureInPictureElement) {
          await document.exitPictureInPicture();
        } else {
          await videoRef.current.requestPictureInPicture();
        }
      } catch (error) {
        console.error('PiP failed:', error);
      }
    }
  };
  
  const handleChapterClick = (timestamp: number) => {
    handleSeek(timestamp);
    setSelectedChapter(timestamp);
  };
  
  const handleAddNote = () => {
    if (newNote.trim()) {
      const note: VideoNote = {
        id: `note-${Date.now()}`,
        timestamp: currentTime,
        note: newNote.trim(),
      };
      setNotes([...notes, note]);
      setNewNote('');
    }
  };
  
  const handleNoteClick = (timestamp: number) => {
    handleSeek(timestamp);
  };
  
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };
  
  const handleShare = () => {
    const shareUrl = `${video.url}?t=${Math.floor(currentTime)}`;
    navigator.clipboard.writeText(shareUrl);
    // Show success notification
  };
  
  const handleDownload = () => {
    // Download video or transcript
    console.log('Download video/transcript');
  };
  
  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: {
          height: '90vh',
          maxHeight: '90vh',
        },
      }}
    >
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={2}>
            <Typography variant="h6">{video.title}</Typography>
            <Box display="flex" gap={1}>
              {video.tags.map((tag) => (
                <Chip key={tag} label={tag} size="small" />
              ))}
            </Box>
          </Box>
          <Box display="flex" gap={1}>
            <Tooltip title={isBookmarked ? 'Remove bookmark' : 'Add bookmark'}>
              <IconButton
                onClick={() => setIsBookmarked(!isBookmarked)}
                color={isBookmarked ? 'primary' : 'default'}
              >
                <BookmarkIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Share">
              <IconButton onClick={handleShare}>
                <ShareIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Download">
              <IconButton onClick={handleDownload}>
                <DownloadIcon />
              </IconButton>
            </Tooltip>
            <IconButton onClick={onClose}>
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>
      </DialogTitle>
      
      <DialogContent sx={{ p: 0, display: 'flex', height: 'calc(100% - 64px)' }}>
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          {/* Video Container */}
          <Box
            ref={containerRef}
            sx={{
              position: 'relative',
              flex: 1,
              bgcolor: 'black',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
            onMouseEnter={() => setShowControls(true)}
            onMouseLeave={() => setShowControls(false)}
          >
            <video
              ref={videoRef}
              src={video.url}
              style={{ width: '100%', height: '100%', objectFit: 'contain' }}
              onLoadedMetadata={(e) => {
                setDuration(e.currentTarget.duration);
              }}
              onPlay={() => setIsPlaying(true)}
              onPause={() => setIsPlaying(false)}
            />
            
            {/* Video Controls Overlay */}
            <Collapse in={showControls}>
              <Box
                sx={{
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  right: 0,
                  background: 'linear-gradient(transparent, rgba(0,0,0,0.8))',
                  p: 2,
                }}
              >
                {/* Progress Bar */}
                <Box sx={{ position: 'relative', mb: 2 }}>
                  <LinearProgress
                    variant="buffer"
                    value={(currentTime / duration) * 100}
                    valueBuffer={buffered}
                    sx={{
                      height: 6,
                      borderRadius: 3,
                      bgcolor: alpha(theme.palette.common.white, 0.2),
                      '& .MuiLinearProgress-bar': {
                        bgcolor: theme.palette.primary.main,
                      },
                      '& .MuiLinearProgress-bar2Buffer': {
                        bgcolor: alpha(theme.palette.common.white, 0.4),
                      },
                    }}
                  />
                  <Slider
                    value={currentTime}
                    max={duration}
                    onChange={(e, value) => handleSeek(value as number)}
                    sx={{
                      position: 'absolute',
                      top: -8,
                      left: 0,
                      right: 0,
                      color: theme.palette.primary.main,
                      '& .MuiSlider-thumb': {
                        width: 16,
                        height: 16,
                      },
                      '& .MuiSlider-rail': {
                        opacity: 0,
                      },
                      '& .MuiSlider-track': {
                        opacity: 0,
                      },
                    }}
                  />
                  
                  {/* Chapter markers */}
                  {video.timestamps?.map((chapter) => (
                    <Box
                      key={chapter.time}
                      sx={{
                        position: 'absolute',
                        left: `${(chapter.time / duration) * 100}%`,
                        top: 0,
                        width: 2,
                        height: 6,
                        bgcolor: theme.palette.warning.main,
                        cursor: 'pointer',
                      }}
                      onClick={() => handleChapterClick(chapter.time)}
                    />
                  ))}
                </Box>
                
                {/* Control Buttons */}
                <Box display="flex" alignItems="center" justifyContent="space-between">
                  <Box display="flex" alignItems="center" gap={1}>
                    <IconButton
                      onClick={() => handleSeek(Math.max(0, currentTime - 10))}
                      sx={{ color: 'white' }}
                    >
                      <Replay10Icon />
                    </IconButton>
                    
                    <IconButton
                      onClick={handlePlayPause}
                      sx={{ color: 'white' }}
                    >
                      {isPlaying ? <PauseIcon /> : <PlayIcon />}
                    </IconButton>
                    
                    <IconButton
                      onClick={() => handleSeek(Math.min(duration, currentTime + 10))}
                      sx={{ color: 'white' }}
                    >
                      <Forward10Icon />
                    </IconButton>
                    
                    <Box display="flex" alignItems="center" gap={1}>
                      <IconButton
                        onClick={handleMute}
                        sx={{ color: 'white' }}
                      >
                        {isMuted ? <MuteIcon /> : <VolumeIcon />}
                      </IconButton>
                      <Slider
                        value={isMuted ? 0 : volume}
                        onChange={(e, value) => handleVolumeChange(value as number)}
                        max={1}
                        step={0.1}
                        sx={{
                          width: 80,
                          color: 'white',
                        }}
                      />
                    </Box>
                    
                    <Typography variant="body2" sx={{ color: 'white', ml: 2 }}>
                      {formatTime(currentTime)} / {formatTime(duration)}
                    </Typography>
                  </Box>
                  
                  <Box display="flex" alignItems="center" gap={1}>
                    <Button
                      size="small"
                      variant="text"
                      startIcon={<SpeedIcon />}
                      sx={{ color: 'white' }}
                      onClick={(e) => {
                        const speeds = [0.5, 0.75, 1, 1.25, 1.5, 2];
                        const currentIndex = speeds.indexOf(playbackRate);
                        const nextSpeed = speeds[(currentIndex + 1) % speeds.length];
                        handleSpeedChange(nextSpeed);
                      }}
                    >
                      {playbackRate}x
                    </Button>
                    
                    <IconButton
                      onClick={() => setShowTranscript(!showTranscript)}
                      sx={{ color: 'white' }}
                    >
                      <SubtitlesIcon />
                    </IconButton>
                    
                    <IconButton
                      onClick={handlePictureInPicture}
                      sx={{ color: 'white' }}
                    >
                      <PipIcon />
                    </IconButton>
                    
                    <IconButton
                      onClick={handleFullscreen}
                      sx={{ color: 'white' }}
                    >
                      <FullscreenIcon />
                    </IconButton>
                  </Box>
                </Box>
              </Box>
            </Collapse>
            
            {/* Transcript Overlay */}
            {showTranscript && video.transcript && (
              <Box
                sx={{
                  position: 'absolute',
                  bottom: 100,
                  left: '50%',
                  transform: 'translateX(-50%)',
                  bgcolor: alpha(theme.palette.common.black, 0.8),
                  color: 'white',
                  p: 2,
                  borderRadius: 1,
                  maxWidth: '80%',
                }}
              >
                <Typography variant="body2">
                  {/* Show current transcript line based on timestamp */}
                  {video.transcript}
                </Typography>
              </Box>
            )}
          </Box>
          
          {/* Description */}
          <Paper sx={{ p: 2 }}>
            <Typography variant="body2" color="text.secondary">
              {video.description}
            </Typography>
          </Paper>
        </Box>
        
        {/* Sidebar */}
        <Box sx={{ width: 350, borderLeft: 1, borderColor: 'divider' }}>
          <Tabs
            value={activeTab}
            onChange={(e, value) => setActiveTab(value)}
            variant="fullWidth"
          >
            <Tab label="Chapters" />
            <Tab label="Notes" />
            <Tab label="Q&A" />
          </Tabs>
          
          {/* Chapters Tab */}
          {activeTab === 0 && (
            <Box sx={{ p: 2, height: 'calc(100% - 48px)', overflow: 'auto' }}>
              {video.timestamps && video.timestamps.length > 0 ? (
                <List>
                  {video.timestamps.map((chapter, index) => (
                    <ListItemButton
                      key={index}
                      selected={selectedChapter === chapter.time}
                      onClick={() => handleChapterClick(chapter.time)}
                    >
                      <ListItemText
                        primary={chapter.label}
                        secondary={formatTime(chapter.time)}
                      />
                    </ListItemButton>
                  ))}
                </List>
              ) : (
                <Alert severity="info">
                  No chapters available for this video
                </Alert>
              )}
            </Box>
          )}
          
          {/* Notes Tab */}
          {activeTab === 1 && (
            <Box sx={{ p: 2, height: 'calc(100% - 48px)', display: 'flex', flexDirection: 'column' }}>
              <Box sx={{ flex: 1, overflow: 'auto', mb: 2 }}>
                {notes.length > 0 ? (
                  <List>
                    {notes.map((note) => (
                      <ListItemButton
                        key={note.id}
                        onClick={() => handleNoteClick(note.timestamp)}
                      >
                        <ListItemText
                          primary={note.note}
                          secondary={formatTime(note.timestamp)}
                        />
                      </ListItemButton>
                    ))}
                  </List>
                ) : (
                  <Alert severity="info">
                    No notes yet. Add notes while watching the video.
                  </Alert>
                )}
              </Box>
              
              <Box display="flex" gap={1}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Add a note at current time..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  onKeyPress={(e) => {
                    if (e.key === 'Enter') {
                      handleAddNote();
                    }
                  }}
                />
                <Button
                  variant="contained"
                  onClick={handleAddNote}
                  disabled={!newNote.trim()}
                >
                  Add
                </Button>
              </Box>
            </Box>
          )}
          
          {/* Q&A Tab */}
          {activeTab === 2 && (
            <Box sx={{ p: 2, height: 'calc(100% - 48px)', overflow: 'auto' }}>
              <Alert severity="info">
                Have questions about this video? Ask our AI assistant for clarification.
              </Alert>
              <Button
                variant="contained"
                fullWidth
                startIcon={<QAIcon />}
                sx={{ mt: 2 }}
                onClick={() => {
                  // Open AI chat with video context
                  console.log('Open AI chat with video context');
                }}
              >
                Ask a Question
              </Button>
            </Box>
          )}
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default VideoSnippetPlayer;