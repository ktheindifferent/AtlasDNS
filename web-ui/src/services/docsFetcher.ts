import { HelpContext } from '../components/HelpSystem/types';

interface DocsFetchResult {
  content: string;
  title: string;
  url: string;
  lastUpdated?: Date;
  relatedTopics?: string[];
  summary?: string;
}

class DocsFetcher {
  private cache: Map<string, { data: DocsFetchResult; timestamp: number }> = new Map();
  private cacheTimeout = 15 * 60 * 1000; // 15 minutes
  private baseDocsUrl = 'https://docs.atlasdns.com';
  
  /**
   * Fetch documentation for a specific topic using WebFetch
   */
  async fetchDocumentation(topic: string, context?: HelpContext): Promise<DocsFetchResult> {
    const cacheKey = `${topic}-${JSON.stringify(context || {})}`;
    
    // Check cache
    const cached = this.cache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTimeout) {
      return cached.data;
    }
    
    try {
      // Build the documentation URL based on topic and context
      const url = this.buildDocsUrl(topic, context);
      
      // Use WebFetch to get the documentation
      const response = await this.webFetch(url, this.buildPrompt(topic, context));
      
      const result: DocsFetchResult = {
        content: response.content,
        title: response.title || topic,
        url: url,
        lastUpdated: new Date(),
        relatedTopics: response.relatedTopics || [],
        summary: response.summary,
      };
      
      // Cache the result
      this.cache.set(cacheKey, {
        data: result,
        timestamp: Date.now(),
      });
      
      return result;
    } catch (error) {
      console.error('Failed to fetch documentation:', error);
      throw error;
    }
  }
  
  /**
   * Search documentation for relevant content
   */
  async searchDocumentation(query: string, limit: number = 5): Promise<DocsFetchResult[]> {
    const searchUrl = `${this.baseDocsUrl}/search?q=${encodeURIComponent(query)}`;
    
    try {
      const response = await this.webFetch(searchUrl, `Search for: ${query}. Return top ${limit} relevant documentation pages.`);
      
      // Parse search results
      const results = this.parseSearchResults(response.content);
      
      return results.slice(0, limit);
    } catch (error) {
      console.error('Documentation search failed:', error);
      return [];
    }
  }
  
  /**
   * Get contextual documentation based on current page/feature
   */
  async getContextualDocs(context: HelpContext): Promise<DocsFetchResult[]> {
    const topics = this.getTopicsForContext(context);
    const results: DocsFetchResult[] = [];
    
    for (const topic of topics) {
      try {
        const doc = await this.fetchDocumentation(topic, context);
        results.push(doc);
      } catch (error) {
        console.error(`Failed to fetch doc for topic ${topic}:`, error);
      }
    }
    
    return results;
  }
  
  /**
   * Fetch quick reference guide
   */
  async getQuickReference(feature: string): Promise<DocsFetchResult> {
    const url = `${this.baseDocsUrl}/reference/${feature}`;
    
    try {
      const response = await this.webFetch(
        url,
        `Extract quick reference information for ${feature}. Include examples, common patterns, and best practices.`
      );
      
      return {
        content: response.content,
        title: `${feature} Quick Reference`,
        url: url,
        lastUpdated: new Date(),
        summary: response.summary,
      };
    } catch (error) {
      console.error('Failed to fetch quick reference:', error);
      throw error;
    }
  }
  
  /**
   * Get API documentation
   */
  async getAPIDocumentation(endpoint: string): Promise<DocsFetchResult> {
    const url = `${this.baseDocsUrl}/api/${endpoint}`;
    
    try {
      const response = await this.webFetch(
        url,
        `Extract API documentation for ${endpoint}. Include parameters, response format, examples, and error codes.`
      );
      
      return {
        content: response.content,
        title: `API: ${endpoint}`,
        url: url,
        lastUpdated: new Date(),
      };
    } catch (error) {
      console.error('Failed to fetch API documentation:', error);
      throw error;
    }
  }
  
  /**
   * Get troubleshooting guide
   */
  async getTroubleshootingGuide(issue: string): Promise<DocsFetchResult> {
    const url = `${this.baseDocsUrl}/troubleshooting/${encodeURIComponent(issue)}`;
    
    try {
      const response = await this.webFetch(
        url,
        `Find troubleshooting steps for: ${issue}. Include common causes, diagnostic steps, and solutions.`
      );
      
      return {
        content: response.content,
        title: `Troubleshooting: ${issue}`,
        url: url,
        lastUpdated: new Date(),
        relatedTopics: response.relatedTopics || [],
      };
    } catch (error) {
      console.error('Failed to fetch troubleshooting guide:', error);
      throw error;
    }
  }
  
  /**
   * Fetch best practices documentation
   */
  async getBestPractices(topic: string): Promise<DocsFetchResult> {
    const url = `${this.baseDocsUrl}/best-practices/${encodeURIComponent(topic)}`;
    
    try {
      const response = await this.webFetch(
        url,
        `Extract best practices for ${topic}. Include recommendations, common pitfalls, and optimization tips.`
      );
      
      return {
        content: response.content,
        title: `Best Practices: ${topic}`,
        url: url,
        lastUpdated: new Date(),
      };
    } catch (error) {
      console.error('Failed to fetch best practices:', error);
      throw error;
    }
  }
  
  /**
   * Clear documentation cache
   */
  clearCache(): void {
    this.cache.clear();
  }
  
  /**
   * Build documentation URL based on topic and context
   */
  private buildDocsUrl(topic: string, context?: HelpContext): string {
    let path = topic.toLowerCase().replace(/\s+/g, '-');
    
    if (context?.page) {
      path = `${context.page}/${path}`;
    }
    
    if (context?.feature) {
      path = `${path}#${context.feature}`;
    }
    
    return `${this.baseDocsUrl}/${path}`;
  }
  
  /**
   * Build intelligent prompt for WebFetch
   */
  private buildPrompt(topic: string, context?: HelpContext): string {
    let prompt = `Extract comprehensive documentation about ${topic}.`;
    
    if (context?.page) {
      prompt += ` Focus on information relevant to the ${context.page} section.`;
    }
    
    if (context?.action) {
      prompt += ` User is trying to ${context.action}.`;
    }
    
    prompt += ` Include:
    1. Overview and purpose
    2. Step-by-step instructions if applicable
    3. Examples and code snippets
    4. Common issues and solutions
    5. Related topics and links
    6. Best practices
    
    Format the response in a clear, structured manner suitable for display in a help system.`;
    
    return prompt;
  }
  
  /**
   * Get relevant topics based on context
   */
  private getTopicsForContext(context: HelpContext): string[] {
    const topics: string[] = [];
    
    // Map pages to relevant documentation topics
    const topicMap: Record<string, string[]> = {
      records: ['DNS Record Types', 'Managing DNS Records', 'Record TTL', 'Record Validation'],
      zones: ['DNS Zones', 'Zone Management', 'Zone Transfers', 'Zone Files'],
      dnssec: ['DNSSEC Overview', 'Enabling DNSSEC', 'DNSSEC Keys', 'DS Records'],
      analytics: ['Query Analytics', 'Performance Metrics', 'Traffic Reports', 'Data Export'],
      monitoring: ['Health Checks', 'Alerts', 'Status Monitoring', 'Uptime Tracking'],
      geodns: ['GeoDNS Configuration', 'Geographic Routing', 'Location-Based DNS'],
      'traffic-policies': ['Traffic Management', 'Load Balancing', 'Failover Configuration'],
    };
    
    if (context.page && topicMap[context.page]) {
      topics.push(...topicMap[context.page]);
    }
    
    // Add action-specific topics
    if (context.action) {
      const actionMap: Record<string, string[]> = {
        create: ['Creating Resources', 'Configuration Guide'],
        edit: ['Updating Resources', 'Modification Best Practices'],
        delete: ['Deleting Resources', 'Cleanup Procedures'],
        import: ['Import Process', 'Data Migration'],
        export: ['Export Options', 'Data Formats'],
      };
      
      if (actionMap[context.action]) {
        topics.push(...actionMap[context.action]);
      }
    }
    
    return topics;
  }
  
  /**
   * Parse search results from WebFetch response
   */
  private parseSearchResults(content: string): DocsFetchResult[] {
    // This would parse the actual search results
    // For now, return mock data
    return [
      {
        content: content,
        title: 'Search Result',
        url: this.baseDocsUrl,
        lastUpdated: new Date(),
      },
    ];
  }
  
  /**
   * Simulate WebFetch call
   * In production, this would use the actual WebFetch tool
   */
  private async webFetch(url: string, prompt: string): Promise<any> {
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 500));
    
    return {
      content: `Documentation content for ${url}\n\nPrompt: ${prompt}\n\nThis is simulated content that would be fetched from the actual documentation.`,
      title: 'Documentation Page',
      summary: 'Summary of the documentation content',
      relatedTopics: ['Related Topic 1', 'Related Topic 2'],
    };
  }
}

// Export singleton instance
export const docsFetcher = new DocsFetcher();

// Export types
export type { DocsFetchResult };