import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { Step } from 'react-joyride';

interface OnboardingProgress {
  completedTours: string[];
  completedWizards: string[];
  totalSteps: number;
  completedSteps: number;
  lastActivity: Date;
  preferences: {
    skipTours: boolean;
    preferredLearningStyle: 'visual' | 'text' | 'interactive';
  };
}

interface OnboardingContextType {
  isFirstVisit: boolean;
  currentTour: string | null;
  tourSteps: Step[];
  isRunning: boolean;
  progress: OnboardingProgress;
  userRole: 'admin' | 'operator' | 'viewer';
  startTour: (tourName: string) => void;
  endTour: () => void;
  skipAllTours: () => void;
  updateProgress: (type: 'tour' | 'wizard', name: string) => void;
  getTourSteps: (tourName: string, role?: string) => Step[];
  resetOnboarding: () => void;
  setUserRole: (role: 'admin' | 'operator' | 'viewer') => void;
}

const OnboardingContext = createContext<OnboardingContextType | undefined>(undefined);

export const useOnboarding = () => {
  const context = useContext(OnboardingContext);
  if (!context) {
    throw new Error('useOnboarding must be used within OnboardingProvider');
  }
  return context;
};

interface OnboardingProviderProps {
  children: React.ReactNode;
}

export const OnboardingProvider: React.FC<OnboardingProviderProps> = ({ children }) => {
  const [isFirstVisit, setIsFirstVisit] = useState(true);
  const [currentTour, setCurrentTour] = useState<string | null>(null);
  const [tourSteps, setTourSteps] = useState<Step[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [userRole, setUserRole] = useState<'admin' | 'operator' | 'viewer'>('viewer');
  const [progress, setProgress] = useState<OnboardingProgress>({
    completedTours: [],
    completedWizards: [],
    totalSteps: 0,
    completedSteps: 0,
    lastActivity: new Date(),
    preferences: {
      skipTours: false,
      preferredLearningStyle: 'interactive',
    },
  });

  // Load saved progress from localStorage
  useEffect(() => {
    const savedProgress = localStorage.getItem('onboardingProgress');
    const hasVisited = localStorage.getItem('hasVisited');
    
    if (savedProgress) {
      setProgress(JSON.parse(savedProgress));
    }
    
    if (hasVisited) {
      setIsFirstVisit(false);
    }
  }, []);

  // Save progress to localStorage
  useEffect(() => {
    localStorage.setItem('onboardingProgress', JSON.stringify(progress));
  }, [progress]);

  const getTourSteps = useCallback((tourName: string, role?: string): Step[] => {
    const currentUserRole = role || userRole;
    
    const tours: Record<string, Step[]> = {
      dashboard: [
        {
          target: '.dashboard-header',
          content: 'Welcome to Atlas DNS Manager! This is your main dashboard where you can monitor all DNS activities.',
          placement: 'bottom',
          disableBeacon: true,
        },
        {
          target: '.zones-widget',
          content: 'Here you can see an overview of all your DNS zones and their current status.',
          placement: 'right',
        },
        {
          target: '.analytics-widget',
          content: 'Monitor real-time DNS query analytics and performance metrics.',
          placement: 'left',
        },
        {
          target: '.health-status',
          content: 'Keep track of the health status of your DNS servers and zones.',
          placement: 'bottom',
        },
        ...(currentUserRole === 'admin' ? [
          {
            target: '.admin-controls',
            content: 'As an admin, you have access to advanced controls and settings.',
            placement: 'bottom',
          } as Step,
        ] : []),
      ],
      zones: [
        {
          target: '.add-zone-button',
          content: 'Click here to add a new DNS zone to your system.',
          placement: 'bottom',
          disableBeacon: true,
        },
        {
          target: '.zone-list',
          content: 'All your DNS zones are listed here. Click on any zone to manage its records.',
          placement: 'right',
        },
        {
          target: '.zone-search',
          content: 'Use the search bar to quickly find specific zones.',
          placement: 'bottom',
        },
        {
          target: '.zone-actions',
          content: 'Access zone-specific actions like editing, deleting, or configuring DNSSEC.',
          placement: 'left',
        },
        {
          target: '.import-zone',
          content: 'Import existing zone files or configurations from other DNS providers.',
          placement: 'bottom',
        },
      ],
      dnssec: [
        {
          target: '.dnssec-overview',
          content: 'DNSSEC adds security to your DNS by signing zones with cryptographic signatures.',
          placement: 'bottom',
          disableBeacon: true,
        },
        {
          target: '.enable-dnssec',
          content: 'Enable DNSSEC for a zone with a single click.',
          placement: 'right',
        },
        {
          target: '.key-management',
          content: 'Manage your DNSSEC keys, including ZSK and KSK rotation.',
          placement: 'left',
        },
        {
          target: '.ds-records',
          content: 'View and copy DS records to provide to your domain registrar.',
          placement: 'bottom',
        },
        {
          target: '.dnssec-validation',
          content: 'Check the validation status of your DNSSEC configuration.',
          placement: 'top',
        },
      ],
      records: [
        {
          target: '.add-record-button',
          content: 'Add new DNS records like A, AAAA, CNAME, MX, TXT, and more.',
          placement: 'bottom',
          disableBeacon: true,
        },
        {
          target: '.record-table',
          content: 'View and manage all records for this zone in the table.',
          placement: 'center',
        },
        {
          target: '.bulk-operations',
          content: 'Perform bulk operations on multiple records at once.',
          placement: 'left',
        },
        {
          target: '.record-templates',
          content: 'Use templates for common record configurations.',
          placement: 'right',
        },
      ],
      geodns: [
        {
          target: '.geodns-map',
          content: 'Configure geographic-based DNS routing to serve different responses based on user location.',
          placement: 'bottom',
          disableBeacon: true,
        },
        {
          target: '.location-policies',
          content: 'Create location-based policies for intelligent traffic routing.',
          placement: 'right',
        },
        {
          target: '.geodns-analytics',
          content: 'View geographic distribution of your DNS queries.',
          placement: 'left',
        },
      ],
      monitoring: [
        {
          target: '.monitoring-dashboard',
          content: 'Monitor the health and performance of your DNS infrastructure.',
          placement: 'bottom',
          disableBeacon: true,
        },
        {
          target: '.alert-configuration',
          content: 'Set up alerts for DNS issues and anomalies.',
          placement: 'right',
        },
        {
          target: '.performance-metrics',
          content: 'Track query response times and server performance.',
          placement: 'left',
        },
      ],
    };

    return tours[tourName] || [];
  }, [userRole]);

  const startTour = useCallback((tourName: string) => {
    if (!progress.preferences.skipTours) {
      const steps = getTourSteps(tourName);
      setCurrentTour(tourName);
      setTourSteps(steps);
      setIsRunning(true);
      localStorage.setItem('hasVisited', 'true');
      setIsFirstVisit(false);
    }
  }, [progress.preferences.skipTours, getTourSteps]);

  const endTour = useCallback(() => {
    setIsRunning(false);
    setCurrentTour(null);
    setTourSteps([]);
  }, []);

  const skipAllTours = useCallback(() => {
    setProgress(prev => ({
      ...prev,
      preferences: {
        ...prev.preferences,
        skipTours: true,
      },
    }));
    endTour();
  }, [endTour]);

  const updateProgress = useCallback((type: 'tour' | 'wizard', name: string) => {
    setProgress(prev => {
      const updated = { ...prev };
      if (type === 'tour' && !prev.completedTours.includes(name)) {
        updated.completedTours = [...prev.completedTours, name];
        updated.completedSteps += 1;
      } else if (type === 'wizard' && !prev.completedWizards.includes(name)) {
        updated.completedWizards = [...prev.completedWizards, name];
        updated.completedSteps += 1;
      }
      updated.lastActivity = new Date();
      
      // Calculate total steps (example: 6 tours + 5 wizards = 11 total)
      updated.totalSteps = 11;
      
      return updated;
    });
  }, []);

  const resetOnboarding = useCallback(() => {
    localStorage.removeItem('onboardingProgress');
    localStorage.removeItem('hasVisited');
    setIsFirstVisit(true);
    setProgress({
      completedTours: [],
      completedWizards: [],
      totalSteps: 0,
      completedSteps: 0,
      lastActivity: new Date(),
      preferences: {
        skipTours: false,
        preferredLearningStyle: 'interactive',
      },
    });
  }, []);

  const value: OnboardingContextType = {
    isFirstVisit,
    currentTour,
    tourSteps,
    isRunning,
    progress,
    userRole,
    startTour,
    endTour,
    skipAllTours,
    updateProgress,
    getTourSteps,
    resetOnboarding,
    setUserRole,
  };

  return (
    <OnboardingContext.Provider value={value}>
      {children}
    </OnboardingContext.Provider>
  );
};