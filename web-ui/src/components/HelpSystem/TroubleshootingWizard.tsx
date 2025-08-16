import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Chip,
  Alert,
  AlertTitle,
  CircularProgress,
  LinearProgress,
  Collapse,
  Paper,
  TextField,
  RadioGroup,
  FormControlLabel,
  Radio,
  Checkbox,
  Divider,
  Tooltip,
  Fade,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Build as BuildIcon,
  CheckCircle as CheckIcon,
  Cancel as CancelIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  NavigateNext as NextIcon,
  NavigateBefore as BackIcon,
  Refresh as RetryIcon,
  Help as HelpIcon,
  PlayArrow as StartIcon,
  Stop as StopIcon,
  Assignment as LogIcon,
  BugReport as BugIcon,
  Speed as SpeedIcon,
  Security as SecurityIcon,
  Dns as DnsIcon,
  Email as EmailIcon,
  Cloud as CloudIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  Share as ShareIcon,
  AutoAwesome as AIIcon,
} from '@mui/icons-material';
import { useDispatch, useSelector } from 'react-redux';
import { RootState } from '../../store';
import { startTroubleshooting, recordInteraction } from '../../store/slices/helpSlice';
import { TroubleshootingWizard as WizardType, TroubleshootingStep } from './types';

interface TroubleshootingWizardProps {
  open: boolean;
  onClose: () => void;
  wizardId?: string;
  issue?: string;
  context?: any;
}

interface CheckResult {
  checkId: string;
  passed: boolean;
  message: string;
  solution?: string;
  documentation?: string;
}

interface WizardState {
  currentStep: number;
  checkResults: Map<string, CheckResult>;
  userAnswers: Map<string, any>;
  logs: string[];
  startTime: number;
  endTime?: number;
  resolved: boolean;
}

const TroubleshootingWizardComponent: React.FC<TroubleshootingWizardProps> = ({
  open,
  onClose,
  wizardId,
  issue,
  context,
}) => {
  const theme = useTheme();
  const dispatch = useDispatch();
  
  const { troubleshootingWizards, sessionId } = useSelector((state: RootState) => state.help);
  
  const [wizard, setWizard] = useState<WizardType | null>(null);
  const [wizardState, setWizardState] = useState<WizardState>({
    currentStep: 0,
    checkResults: new Map(),
    userAnswers: new Map(),
    logs: [],
    startTime: Date.now(),
    resolved: false,
  });
  const [running, setRunning] = useState(false);
  const [expandedSolutions, setExpandedSolutions] = useState<Set<string>>(new Set());
  const [showLogs, setShowLogs] = useState(false);
  const [userFeedback, setUserFeedback] = useState('');
  
  // Load wizard
  useEffect(() => {
    if (open && wizardId) {
      loadWizard();
    } else if (open && issue) {
      findWizardForIssue();
    }
  }, [open, wizardId, issue]);
  
  // Record interaction when wizard starts
  useEffect(() => {
    if (open && wizard) {
      dispatch(recordInteraction({
        type: 'wizard',
        context: context || { page: 'unknown' },
        query: wizard.title,
        sessionId,
      }));
    }
  }, [open, wizard, context, dispatch, sessionId]);
  
  const loadWizard = async () => {
    if (wizardId) {
      const foundWizard = troubleshootingWizards.find(w => w.id === wizardId);
      if (foundWizard) {
        setWizard(foundWizard);
      } else {
        // Load from API if not in state
        const result = await dispatch(startTroubleshooting(wizardId)).unwrap();
        setWizard(result);
      }
    }
  };
  
  const findWizardForIssue = () => {
    // Find best matching wizard for the issue
    const matchingWizard = troubleshootingWizards.find(w =>
      w.commonIssues.some(commonIssue =>
        issue?.toLowerCase().includes(commonIssue.toLowerCase())
      )
    );
    
    if (matchingWizard) {
      setWizard(matchingWizard);
    }
  };
  
  // Run diagnostic check
  const runCheck = async (step: TroubleshootingStep, checkIndex: number) => {
    const check = step.checks[checkIndex];
    setRunning(true);
    
    addLog(`Running check: ${check.label}`);
    
    try {
      // Simulate check execution
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Run the actual check
      const passed = await check.action();
      
      const result: CheckResult = {
        checkId: check.id,
        passed,
        message: passed ? 'Check passed successfully' : 'Check failed',
        solution: !passed ? check.solution : undefined,
        documentation: check.documentation,
      };
      
      setWizardState(prev => ({
        ...prev,
        checkResults: new Map(prev.checkResults).set(check.id, result),
      }));
      
      addLog(`Check ${check.label}: ${passed ? 'PASSED' : 'FAILED'}`);
      
      if (!passed && check.solution) {
        addLog(`Suggested solution: ${check.solution}`);
      }
      
      return passed;
    } catch (error) {
      addLog(`Error running check: ${error}`);
      return false;
    } finally {
      setRunning(false);
    }
  };
  
  // Run all checks in current step
  const runAllChecks = async () => {
    if (!wizard) return;
    
    const currentStepData = wizard.steps[wizardState.currentStep];
    let allPassed = true;
    
    for (let i = 0; i < currentStepData.checks.length; i++) {
      const passed = await runCheck(currentStepData, i);
      if (!passed) {
        allPassed = false;
      }
    }
    
    if (allPassed) {
      addLog('All checks passed! Moving to next step...');
      handleNext();
    } else {
      addLog('Some checks failed. Please review the solutions above.');
    }
  };
  
  // Add log entry
  const addLog = (message: string) => {
    const timestamp = new Date().toLocaleTimeString();
    setWizardState(prev => ({
      ...prev,
      logs: [...prev.logs, `[${timestamp}] ${message}`],
    }));
  };
  
  // Handle step navigation
  const handleNext = () => {
    if (!wizard) return;
    
    if (wizardState.currentStep < wizard.steps.length - 1) {
      setWizardState(prev => ({
        ...prev,
        currentStep: prev.currentStep + 1,
      }));
    } else {
      // Wizard completed
      handleComplete();
    }
  };
  
  const handleBack = () => {
    setWizardState(prev => ({
      ...prev,
      currentStep: Math.max(0, prev.currentStep - 1),
    }));
  };
  
  const handleComplete = () => {
    setWizardState(prev => ({
      ...prev,
      endTime: Date.now(),
      resolved: true,
    }));
    
    addLog('Troubleshooting completed!');
    
    // Record completion
    dispatch(recordInteraction({
      type: 'wizard',
      context: context || { page: 'unknown' },
      query: `Completed: ${wizard?.title}`,
      sessionId,
      resolved: true,
      duration: Date.now() - wizardState.startTime,
    }));
  };
  
  // Toggle solution expansion
  const toggleSolution = (checkId: string) => {
    setExpandedSolutions(prev => {
      const newSet = new Set(prev);
      if (newSet.has(checkId)) {
        newSet.delete(checkId);
      } else {
        newSet.add(checkId);
      }
      return newSet;
    });
  };
  
  // Export troubleshooting report
  const exportReport = () => {
    const report = {
      wizard: wizard?.title,
      issue,
      startTime: new Date(wizardState.startTime).toISOString(),
      endTime: wizardState.endTime ? new Date(wizardState.endTime).toISOString() : null,
      resolved: wizardState.resolved,
      checkResults: Array.from(wizardState.checkResults.entries()),
      logs: wizardState.logs,
      userAnswers: Array.from(wizardState.userAnswers.entries()),
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `troubleshooting-report-${Date.now()}.json`;
    a.click();
  };
  
  // Copy logs to clipboard
  const copyLogs = () => {
    const logsText = wizardState.logs.join('\n');
    navigator.clipboard.writeText(logsText);
  };
  
  if (!wizard) {
    return (
      <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
        <DialogContent>
          <Box display="flex" justifyContent="center" alignItems="center" p={4}>
            <CircularProgress />
          </Box>
        </DialogContent>
      </Dialog>
    );
  }
  
  const currentStepData = wizard.steps[wizardState.currentStep];
  const progress = ((wizardState.currentStep + 1) / wizard.steps.length) * 100;
  
  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" justifyContent="space-between">
          <Box display="flex" alignItems="center" gap={2}>
            <BuildIcon color="primary" />
            <Box>
              <Typography variant="h6">{wizard.title}</Typography>
              <Typography variant="caption" color="text.secondary">
                {wizard.description}
              </Typography>
            </Box>
          </Box>
          <Box display="flex" gap={1}>
            <Chip
              label={wizard.category}
              size="small"
              color="primary"
            />
            <Chip
              label={`~${wizard.estimatedTime} min`}
              size="small"
              icon={<SpeedIcon />}
            />
          </Box>
        </Box>
        <LinearProgress
          variant="determinate"
          value={progress}
          sx={{ mt: 2, height: 6, borderRadius: 3 }}
        />
      </DialogTitle>
      
      <DialogContent>
        <Box display="flex" gap={2}>
          {/* Main Content */}
          <Box flex={1}>
            <Stepper activeStep={wizardState.currentStep} orientation="vertical">
              {wizard.steps.map((step, index) => (
                <Step key={step.id}>
                  <StepLabel
                    optional={
                      index === wizard.steps.length - 1 ? (
                        <Typography variant="caption">Last step</Typography>
                      ) : null
                    }
                  >
                    {step.title}
                  </StepLabel>
                  <StepContent>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      {step.description}
                    </Typography>
                    
                    {/* Diagnostic Checks */}
                    <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Diagnostic Checks
                      </Typography>
                      <List>
                        {step.checks.map((check, checkIndex) => {
                          const result = wizardState.checkResults.get(check.id);
                          
                          return (
                            <ListItem key={check.id}>
                              <ListItemIcon>
                                {result ? (
                                  result.passed ? (
                                    <CheckIcon color="success" />
                                  ) : (
                                    <CancelIcon color="error" />
                                  )
                                ) : (
                                  <Radio checked={false} />
                                )}
                              </ListItemIcon>
                              <ListItemText
                                primary={check.label}
                                secondary={result?.message}
                              />
                              <ListItemSecondaryAction>
                                {!result && (
                                  <Button
                                    size="small"
                                    onClick={() => runCheck(step, checkIndex)}
                                    disabled={running}
                                  >
                                    Run Check
                                  </Button>
                                )}
                              </ListItemSecondaryAction>
                            </ListItem>
                          );
                        })}
                      </List>
                      
                      <Box display="flex" justifyContent="center" mt={2}>
                        <Button
                          variant="contained"
                          startIcon={running ? <CircularProgress size={16} /> : <StartIcon />}
                          onClick={runAllChecks}
                          disabled={running}
                        >
                          {running ? 'Running Checks...' : 'Run All Checks'}
                        </Button>
                      </Box>
                    </Paper>
                    
                    {/* Failed Check Solutions */}
                    {Array.from(wizardState.checkResults.entries()).map(([checkId, result]) => {
                      if (!result.passed && result.solution) {
                        const check = step.checks.find(c => c.id === checkId);
                        return (
                          <Alert
                            key={checkId}
                            severity="warning"
                            sx={{ mb: 2 }}
                            action={
                              <IconButton
                                size="small"
                                onClick={() => toggleSolution(checkId)}
                              >
                                {expandedSolutions.has(checkId) ? <CollapseIcon /> : <ExpandIcon />}
                              </IconButton>
                            }
                          >
                            <AlertTitle>{check?.label} - Solution</AlertTitle>
                            <Collapse in={expandedSolutions.has(checkId)}>
                              <Typography variant="body2" paragraph>
                                {result.solution}
                              </Typography>
                              {result.documentation && (
                                <Button
                                  size="small"
                                  href={result.documentation}
                                  target="_blank"
                                >
                                  View Documentation
                                </Button>
                              )}
                            </Collapse>
                          </Alert>
                        );
                      }
                      return null;
                    })}
                    
                    {/* Navigation */}
                    <Box display="flex" gap={1} mt={2}>
                      <Button
                        disabled={index === 0}
                        onClick={handleBack}
                        startIcon={<BackIcon />}
                      >
                        Back
                      </Button>
                      <Button
                        variant="contained"
                        onClick={handleNext}
                        endIcon={<NextIcon />}
                      >
                        {index === wizard.steps.length - 1 ? 'Complete' : 'Next'}
                      </Button>
                    </Box>
                  </StepContent>
                </Step>
              ))}
            </Stepper>
            
            {/* Completion Message */}
            {wizardState.resolved && (
              <Alert severity="success" sx={{ mt: 2 }}>
                <AlertTitle>Troubleshooting Completed!</AlertTitle>
                <Typography variant="body2" paragraph>
                  The troubleshooting wizard has been completed. If your issue persists, 
                  please contact support with the exported report.
                </Typography>
                <Box display="flex" gap={1}>
                  <Button
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={exportReport}
                  >
                    Export Report
                  </Button>
                  <Button
                    size="small"
                    startIcon={<AIIcon />}
                    onClick={() => {
                      // Open AI chat with context
                      console.log('Open AI chat with troubleshooting context');
                    }}
                  >
                    Get More Help
                  </Button>
                </Box>
              </Alert>
            )}
          </Box>
          
          {/* Sidebar */}
          <Paper sx={{ width: 300, p: 2 }}>
            {/* Common Issues */}
            <Typography variant="subtitle2" gutterBottom>
              Common Issues Covered
            </Typography>
            <List dense>
              {wizard.commonIssues.map((issue, index) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    <BugIcon fontSize="small" />
                  </ListItemIcon>
                  <ListItemText primary={issue} />
                </ListItem>
              ))}
            </List>
            
            <Divider sx={{ my: 2 }} />
            
            {/* Diagnostic Logs */}
            <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
              <Typography variant="subtitle2">
                Diagnostic Logs
              </Typography>
              <IconButton size="small" onClick={() => setShowLogs(!showLogs)}>
                {showLogs ? <CollapseIcon /> : <ExpandIcon />}
              </IconButton>
            </Box>
            
            <Collapse in={showLogs}>
              <Paper
                variant="outlined"
                sx={{
                  p: 1,
                  maxHeight: 200,
                  overflow: 'auto',
                  bgcolor: theme.palette.grey[900],
                  color: theme.palette.common.white,
                  fontFamily: 'monospace',
                  fontSize: '0.75rem',
                }}
              >
                {wizardState.logs.length === 0 ? (
                  <Typography variant="caption">No logs yet...</Typography>
                ) : (
                  wizardState.logs.map((log, index) => (
                    <Box key={index}>{log}</Box>
                  ))
                )}
              </Paper>
              <Box display="flex" gap={1} mt={1}>
                <Button
                  size="small"
                  startIcon={<CopyIcon />}
                  onClick={copyLogs}
                  disabled={wizardState.logs.length === 0}
                >
                  Copy
                </Button>
                <Button
                  size="small"
                  startIcon={<DownloadIcon />}
                  onClick={exportReport}
                >
                  Export
                </Button>
              </Box>
            </Collapse>
            
            <Divider sx={{ my: 2 }} />
            
            {/* Quick Actions */}
            <Typography variant="subtitle2" gutterBottom>
              Quick Actions
            </Typography>
            <Box display="flex" flexDirection="column" gap={1}>
              <Button
                size="small"
                startIcon={<RetryIcon />}
                onClick={() => {
                  setWizardState({
                    currentStep: 0,
                    checkResults: new Map(),
                    userAnswers: new Map(),
                    logs: [],
                    startTime: Date.now(),
                    resolved: false,
                  });
                }}
              >
                Restart Wizard
              </Button>
              <Button
                size="small"
                startIcon={<ShareIcon />}
                onClick={() => {
                  // Share troubleshooting session
                  console.log('Share session');
                }}
              >
                Share Session
              </Button>
              <Button
                size="small"
                startIcon={<HelpIcon />}
                onClick={() => {
                  // Open help for current step
                  console.log('Get help for current step');
                }}
              >
                Get Help
              </Button>
            </Box>
          </Paper>
        </Box>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        {wizardState.resolved && (
          <Button
            variant="contained"
            onClick={() => {
              onClose();
              // Mark issue as resolved
            }}
          >
            Mark as Resolved
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};

export default TroubleshootingWizardComponent;