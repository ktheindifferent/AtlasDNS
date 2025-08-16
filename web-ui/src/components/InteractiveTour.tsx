import React, { useState, useCallback } from 'react';
import Joyride, { CallBackProps, STATUS, EVENTS, Step } from 'react-joyride';
import { Box, Typography, Button, IconButton } from '@mui/material';
import { Close as CloseIcon, PlayArrow, Skip } from '@mui/icons-material';
import { useOnboarding } from '../contexts/OnboardingContext';

const tourStyles = {
  options: {
    primaryColor: '#1976d2',
    textColor: '#333',
    backgroundColor: '#fff',
    arrowColor: '#fff',
    overlayColor: 'rgba(0, 0, 0, 0.5)',
    zIndex: 10000,
  },
  buttonNext: {
    backgroundColor: '#1976d2',
    color: '#fff',
    borderRadius: 4,
    padding: '8px 16px',
  },
  buttonBack: {
    color: '#1976d2',
    marginRight: 8,
  },
  buttonSkip: {
    color: '#757575',
  },
  tooltip: {
    borderRadius: 8,
    padding: 16,
  },
  tooltipContent: {
    padding: '8px 0',
  },
  spotlight: {
    borderRadius: 8,
  },
};

interface InteractiveTourProps {
  run?: boolean;
  steps?: Step[];
  onComplete?: () => void;
}

const InteractiveTour: React.FC<InteractiveTourProps> = ({ 
  run: runProp, 
  steps: stepsProp,
  onComplete 
}) => {
  const { 
    isRunning, 
    tourSteps, 
    currentTour, 
    endTour, 
    updateProgress, 
    skipAllTours 
  } = useOnboarding();
  
  const [stepIndex, setStepIndex] = useState(0);
  const [run, setRun] = useState(runProp || isRunning);
  
  const steps = stepsProp || tourSteps;

  const handleJoyrideCallback = useCallback((data: CallBackProps) => {
    const { status, type, index, action } = data;
    
    if (type === EVENTS.STEP_AFTER || type === EVENTS.TARGET_NOT_FOUND) {
      setStepIndex(index + (action === 'prev' ? -1 : 1));
    }
    
    if (status === STATUS.FINISHED) {
      if (currentTour) {
        updateProgress('tour', currentTour);
      }
      endTour();
      if (onComplete) {
        onComplete();
      }
    }
    
    if (status === STATUS.SKIPPED) {
      endTour();
    }
  }, [currentTour, updateProgress, endTour, onComplete]);

  if (!steps || steps.length === 0) {
    return null;
  }

  return (
    <>
      <Joyride
        steps={steps}
        run={run || isRunning}
        stepIndex={stepIndex}
        continuous
        showProgress
        showSkipButton
        scrollToFirstStep
        scrollOffset={100}
        disableScrolling={false}
        callback={handleJoyrideCallback}
        styles={tourStyles}
        locale={{
          back: 'Back',
          close: 'Close',
          last: 'Finish',
          next: 'Next',
          skip: 'Skip Tour',
        }}
        floaterProps={{
          disableAnimation: false,
        }}
        tooltipComponent={({ 
          continuous, 
          index, 
          step, 
          backProps, 
          closeProps, 
          primaryProps, 
          skipProps, 
          tooltipProps,
          isLastStep,
          size
        }: any) => (
          <Box
            {...tooltipProps}
            sx={{
              backgroundColor: 'white',
              borderRadius: 2,
              boxShadow: 3,
              maxWidth: 480,
              p: 2,
            }}
          >
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6" component="div">
                {step.title || `Step ${index + 1} of ${size}`}
              </Typography>
              <IconButton
                {...closeProps}
                size="small"
                sx={{ ml: 2 }}
              >
                <CloseIcon />
              </IconButton>
            </Box>
            
            <Typography variant="body1" sx={{ mb: 3 }}>
              {step.content}
            </Typography>
            
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                {index > 0 && (
                  <Button
                    {...backProps}
                    variant="text"
                    sx={{ mr: 1 }}
                  >
                    Back
                  </Button>
                )}
              </Box>
              
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button
                  {...skipProps}
                  variant="text"
                  color="inherit"
                  startIcon={<Skip />}
                >
                  Skip Tour
                </Button>
                <Button
                  {...primaryProps}
                  variant="contained"
                  endIcon={!isLastStep && <PlayArrow />}
                >
                  {isLastStep ? 'Finish' : 'Next'}
                </Button>
              </Box>
            </Box>
            
            {/* Progress indicator */}
            <Box sx={{ mt: 2, display: 'flex', justifyContent: 'center', gap: 0.5 }}>
              {Array.from({ length: size }).map((_, i) => (
                <Box
                  key={i}
                  sx={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    backgroundColor: i === index ? 'primary.main' : 'grey.300',
                    transition: 'background-color 0.3s',
                  }}
                />
              ))}
            </Box>
          </Box>
        )}
      />
      
      {/* Skip all tours option */}
      {isRunning && (
        <Box
          sx={{
            position: 'fixed',
            bottom: 20,
            right: 20,
            zIndex: 10001,
          }}
        >
          <Button
            variant="text"
            size="small"
            onClick={skipAllTours}
            sx={{ backgroundColor: 'rgba(255, 255, 255, 0.9)' }}
          >
            Don't show tours again
          </Button>
        </Box>
      )}
    </>
  );
};

export default InteractiveTour;