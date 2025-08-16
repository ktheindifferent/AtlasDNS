import React, { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { setContext } from '../../store/slices/helpSlice';
import AIChatbot from './AIChatbot';
import ContextHelpPanel from './ContextHelpPanel';
import ProactiveHelpEngine from './ProactiveHelpEngine';
import { HelpContext } from './types';

// Export all components
export { default as AIChatbot } from './AIChatbot';
export { default as ContextHelpPanel } from './ContextHelpPanel';
export { default as InlineHelpBubble } from './InlineHelpBubble';
export { default as VideoSnippetPlayer } from './VideoSnippetPlayer';
export { default as SmartFAQ } from './SmartFAQ';
export { default as NaturalLanguageSearch } from './NaturalLanguageSearch';
export { default as TroubleshootingWizard } from './TroubleshootingWizard';
export { default as UserGeneratedContent } from './UserGeneratedContent';
export { default as ProactiveHelpEngine } from './ProactiveHelpEngine';
export { default as HelpAnalyticsDashboard } from './HelpAnalyticsDashboard';

// Export types
export * from './types';

// Export services
export { docsFetcher } from '../../services/docsFetcher';
export { helpApi } from '../../services/helpApi';

interface HelpSystemProps {
  children?: React.ReactNode;
  enableProactiveHelp?: boolean;
}

/**
 * Main HelpSystem component that manages context and integrates all help components
 */
const HelpSystem: React.FC<HelpSystemProps> = ({
  children,
  enableProactiveHelp = true,
}) => {
  const dispatch = useDispatch();
  const location = useLocation();
  
  // Update context based on route changes
  useEffect(() => {
    const pathSegments = location.pathname.split('/').filter(Boolean);
    const page = pathSegments[0] || 'dashboard';
    const feature = pathSegments[1];
    const action = pathSegments[2];
    
    const context: HelpContext = {
      page,
      feature,
      action,
      data: {
        pathname: location.pathname,
        search: location.search,
      },
    };
    
    dispatch(setContext(context));
  }, [location, dispatch]);
  
  return (
    <>
      {/* Core help components that are always available */}
      <AIChatbot />
      <ContextHelpPanel />
      <ProactiveHelpEngine enabled={enableProactiveHelp} />
      
      {/* Render children */}
      {children}
    </>
  );
};

export default HelpSystem;