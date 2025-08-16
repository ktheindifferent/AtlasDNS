// Package atlasdns provides a Go client library for Atlas DNS Server
package atlasdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"golang.org/x/time/rate"
)

// Client represents an Atlas DNS API client
type Client struct {
	baseURL     string
	apiKey      string
	httpClient  *resty.Client
	rateLimiter *rate.Limiter
	debug       bool
}

// ClientOption is a function that configures a Client
type ClientOption func(*Client)

// NewClient creates a new Atlas DNS client
func NewClient(baseURL string, apiKey string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL:     baseURL,
		apiKey:      apiKey,
		httpClient:  resty.New(),
		rateLimiter: rate.NewLimiter(rate.Every(time.Second/10), 10), // 10 requests per second
		debug:       false,
	}

	// Set default timeout
	c.httpClient.SetTimeout(30 * time.Second)
	c.httpClient.SetRetryCount(3)
	c.httpClient.SetRetryWaitTime(1 * time.Second)
	c.httpClient.SetRetryMaxWaitTime(10 * time.Second)

	// Set headers
	c.httpClient.SetHeader("Content-Type", "application/json")
	c.httpClient.SetHeader("User-Agent", "atlas-dns-go-sdk/1.0.0")
	
	if apiKey != "" {
		c.httpClient.SetHeader("X-API-Key", apiKey)
	}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	c.httpClient.SetBaseURL(baseURL + "/api/v2")
	c.httpClient.SetDebug(c.debug)

	// Add response middleware for error handling
	c.httpClient.OnAfterResponse(func(client *resty.Client, response *resty.Response) error {
		return handleAPIError(response)
	})

	return c
}

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.httpClient.SetTimeout(timeout)
	}
}

// WithRateLimit sets the rate limiter
func WithRateLimit(rps int) ClientOption {
	return func(c *Client) {
		c.rateLimiter = rate.NewLimiter(rate.Every(time.Second/time.Duration(rps)), rps)
	}
}

// WithDebug enables debug mode
func WithDebug(debug bool) ClientOption {
	return func(c *Client) {
		c.debug = debug
	}
}

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		c.httpClient.SetTransport(httpClient.Transport)
		c.httpClient.SetTimeout(httpClient.Timeout)
	}
}

// doRequest performs an API request with rate limiting and context support
func (c *Client) doRequest(ctx context.Context, req *resty.Request) (*resty.Response, error) {
	// Apply rate limiting
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter error: %w", err)
	}

	// Set context
	req.SetContext(ctx)

	// Execute request
	return req.Execute(req.Method, req.URL)
}

// Zone Management

// ListZones returns all DNS zones
func (c *Client) ListZones(ctx context.Context, params *ListParams) ([]Zone, error) {
	var zones []Zone
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&zones)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/zones"))
	return zones, err
}

// GetZone retrieves a specific zone
func (c *Client) GetZone(ctx context.Context, zoneID string) (*Zone, error) {
	var zone Zone
	
	req := c.httpClient.R().
		SetResult(&zone)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/zones/%s", zoneID)))
	return &zone, err
}

// CreateZone creates a new DNS zone
func (c *Client) CreateZone(ctx context.Context, zone *Zone) (*Zone, error) {
	var result Zone
	
	req := c.httpClient.R().
		SetBody(zone).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post("/zones"))
	return &result, err
}

// UpdateZone updates an existing zone
func (c *Client) UpdateZone(ctx context.Context, zoneID string, updates *ZoneUpdate) (*Zone, error) {
	var zone Zone
	
	req := c.httpClient.R().
		SetBody(updates).
		SetResult(&zone)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Put(fmt.Sprintf("/zones/%s", zoneID)))
	return &zone, err
}

// DeleteZone deletes a zone
func (c *Client) DeleteZone(ctx context.Context, zoneID string) error {
	req := c.httpClient.R()
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Delete(fmt.Sprintf("/zones/%s", zoneID)))
	return err
}

// ValidateZone validates zone configuration
func (c *Client) ValidateZone(ctx context.Context, zoneID string) (*ValidationResult, error) {
	var result ValidationResult
	
	req := c.httpClient.R().
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/zones/%s/validate", zoneID)))
	return &result, err
}

// Record Management

// ListRecords returns all records in a zone
func (c *Client) ListRecords(ctx context.Context, zoneID string, params *ListParams) ([]Record, error) {
	var records []Record
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&records)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/zones/%s/records", zoneID)))
	return records, err
}

// GetRecord retrieves a specific record
func (c *Client) GetRecord(ctx context.Context, zoneID, recordID string) (*Record, error) {
	var record Record
	
	req := c.httpClient.R().
		SetResult(&record)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/zones/%s/records/%s", zoneID, recordID)))
	return &record, err
}

// CreateRecord creates a new DNS record
func (c *Client) CreateRecord(ctx context.Context, zoneID string, record *Record) (*Record, error) {
	var result Record
	
	req := c.httpClient.R().
		SetBody(record).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/zones/%s/records", zoneID)))
	return &result, err
}

// UpdateRecord updates an existing record
func (c *Client) UpdateRecord(ctx context.Context, zoneID, recordID string, updates *RecordUpdate) (*Record, error) {
	var record Record
	
	req := c.httpClient.R().
		SetBody(updates).
		SetResult(&record)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Put(fmt.Sprintf("/zones/%s/records/%s", zoneID, recordID)))
	return &record, err
}

// DeleteRecord deletes a record
func (c *Client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	req := c.httpClient.R()
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Delete(fmt.Sprintf("/zones/%s/records/%s", zoneID, recordID)))
	return err
}

// BulkCreateRecords creates multiple records at once
func (c *Client) BulkCreateRecords(ctx context.Context, zoneID string, records []Record) ([]Record, error) {
	var result []Record
	
	req := c.httpClient.R().
		SetBody(map[string]interface{}{"records": records}).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/zones/%s/records/bulk", zoneID)))
	return result, err
}

// Health Checks

// ListHealthChecks returns all health checks
func (c *Client) ListHealthChecks(ctx context.Context, params *ListParams) ([]HealthCheck, error) {
	var checks []HealthCheck
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&checks)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/health-checks"))
	return checks, err
}

// GetHealthCheck retrieves a specific health check
func (c *Client) GetHealthCheck(ctx context.Context, checkID string) (*HealthCheck, error) {
	var check HealthCheck
	
	req := c.httpClient.R().
		SetResult(&check)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/health-checks/%s", checkID)))
	return &check, err
}

// CreateHealthCheck creates a new health check
func (c *Client) CreateHealthCheck(ctx context.Context, check *HealthCheck) (*HealthCheck, error) {
	var result HealthCheck
	
	req := c.httpClient.R().
		SetBody(check).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post("/health-checks"))
	return &result, err
}

// UpdateHealthCheck updates a health check
func (c *Client) UpdateHealthCheck(ctx context.Context, checkID string, updates *HealthCheckUpdate) (*HealthCheck, error) {
	var check HealthCheck
	
	req := c.httpClient.R().
		SetBody(updates).
		SetResult(&check)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Put(fmt.Sprintf("/health-checks/%s", checkID)))
	return &check, err
}

// DeleteHealthCheck deletes a health check
func (c *Client) DeleteHealthCheck(ctx context.Context, checkID string) error {
	req := c.httpClient.R()
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Delete(fmt.Sprintf("/health-checks/%s", checkID)))
	return err
}

// TestHealthCheck runs a health check test
func (c *Client) TestHealthCheck(ctx context.Context, checkID string) (*HealthCheckResult, error) {
	var result HealthCheckResult
	
	req := c.httpClient.R().
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/health-checks/%s/test", checkID)))
	return &result, err
}

// Traffic Policies

// ListTrafficPolicies returns all traffic policies
func (c *Client) ListTrafficPolicies(ctx context.Context, params *ListParams) ([]TrafficPolicy, error) {
	var policies []TrafficPolicy
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&policies)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/traffic-policies"))
	return policies, err
}

// GetTrafficPolicy retrieves a specific traffic policy
func (c *Client) GetTrafficPolicy(ctx context.Context, policyID string) (*TrafficPolicy, error) {
	var policy TrafficPolicy
	
	req := c.httpClient.R().
		SetResult(&policy)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/traffic-policies/%s", policyID)))
	return &policy, err
}

// CreateTrafficPolicy creates a new traffic policy
func (c *Client) CreateTrafficPolicy(ctx context.Context, policy *TrafficPolicy) (*TrafficPolicy, error) {
	var result TrafficPolicy
	
	req := c.httpClient.R().
		SetBody(policy).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post("/traffic-policies"))
	return &result, err
}

// SimulateTrafficPolicy simulates a traffic policy
func (c *Client) SimulateTrafficPolicy(ctx context.Context, policyID string, params *SimulationParams) (*SimulationResult, error) {
	var result SimulationResult
	
	req := c.httpClient.R().
		SetBody(params).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/traffic-policies/%s/simulate", policyID)))
	return &result, err
}

// GeoDNS

// ListGeoDNSRules returns all GeoDNS rules
func (c *Client) ListGeoDNSRules(ctx context.Context, params *ListParams) ([]GeoDNSRule, error) {
	var rules []GeoDNSRule
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&rules)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/geodns"))
	return rules, err
}

// GetGeoDNSRule retrieves a specific GeoDNS rule
func (c *Client) GetGeoDNSRule(ctx context.Context, ruleID string) (*GeoDNSRule, error) {
	var rule GeoDNSRule
	
	req := c.httpClient.R().
		SetResult(&rule)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/geodns/%s", ruleID)))
	return &rule, err
}

// CreateGeoDNSRule creates a new GeoDNS rule
func (c *Client) CreateGeoDNSRule(ctx context.Context, rule *GeoDNSRule) (*GeoDNSRule, error) {
	var result GeoDNSRule
	
	req := c.httpClient.R().
		SetBody(rule).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post("/geodns"))
	return &result, err
}

// GetGeoDNSRegions returns available GeoDNS regions
func (c *Client) GetGeoDNSRegions(ctx context.Context) ([]Region, error) {
	var regions []Region
	
	req := c.httpClient.R().
		SetResult(&regions)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/geodns/regions"))
	return regions, err
}

// DNSSEC

// GetDNSSECStatus retrieves DNSSEC status for a zone
func (c *Client) GetDNSSECStatus(ctx context.Context, zoneID string) (*DNSSECConfig, error) {
	var config DNSSECConfig
	
	req := c.httpClient.R().
		SetResult(&config)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/zones/%s/dnssec", zoneID)))
	return &config, err
}

// EnableDNSSEC enables DNSSEC for a zone
func (c *Client) EnableDNSSEC(ctx context.Context, zoneID string, config *DNSSECConfig) (*DNSSECConfig, error) {
	var result DNSSECConfig
	
	req := c.httpClient.R().
		SetBody(config).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/zones/%s/dnssec/enable", zoneID)))
	return &result, err
}

// DisableDNSSEC disables DNSSEC for a zone
func (c *Client) DisableDNSSEC(ctx context.Context, zoneID string) error {
	req := c.httpClient.R()
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/zones/%s/dnssec/disable", zoneID)))
	return err
}

// RotateDNSSECKeys rotates DNSSEC keys for a zone
func (c *Client) RotateDNSSECKeys(ctx context.Context, zoneID string) (*DNSSECConfig, error) {
	var config DNSSECConfig
	
	req := c.httpClient.R().
		SetResult(&config)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/zones/%s/dnssec/rotate-keys", zoneID)))
	return &config, err
}

// Analytics

// GetAnalyticsOverview retrieves analytics overview
func (c *Client) GetAnalyticsOverview(ctx context.Context, params *AnalyticsParams) (*AnalyticsData, error) {
	var data AnalyticsData
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&data)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/analytics/overview"))
	return &data, err
}

// GetQueryAnalytics retrieves query analytics
func (c *Client) GetQueryAnalytics(ctx context.Context, params *AnalyticsParams) (*QueryAnalytics, error) {
	var analytics QueryAnalytics
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&analytics)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/analytics/queries"))
	return &analytics, err
}

// GetTopDomains retrieves top queried domains
func (c *Client) GetTopDomains(ctx context.Context, params *TopDomainsParams) ([]DomainStats, error) {
	var domains []DomainStats
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&domains)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/analytics/top-domains"))
	return domains, err
}

// Query

// QueryDNS performs a DNS query
func (c *Client) QueryDNS(ctx context.Context, query *DNSQuery) (*QueryResult, error) {
	var result QueryResult
	
	req := c.httpClient.R().
		SetBody(query).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post("/query"))
	return &result, err
}

// Monitoring

// GetSystemStatus retrieves system status
func (c *Client) GetSystemStatus(ctx context.Context) (*SystemStatus, error) {
	var status SystemStatus
	
	req := c.httpClient.R().
		SetResult(&status)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/monitoring/status"))
	return &status, err
}

// GetMetrics retrieves system metrics
func (c *Client) GetMetrics(ctx context.Context, params *MetricsParams) (*Metrics, error) {
	var metrics Metrics
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&metrics)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/monitoring/metrics"))
	return &metrics, err
}

// Webhooks

// ListWebhooks returns all webhook endpoints
func (c *Client) ListWebhooks(ctx context.Context, params *ListParams) ([]WebhookEndpoint, error) {
	var webhooks []WebhookEndpoint
	
	req := c.httpClient.R().
		SetQueryParams(params.ToMap()).
		SetResult(&webhooks)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get("/webhooks"))
	return webhooks, err
}

// GetWebhook retrieves a specific webhook endpoint
func (c *Client) GetWebhook(ctx context.Context, webhookID string) (*WebhookEndpoint, error) {
	var webhook WebhookEndpoint
	
	req := c.httpClient.R().
		SetResult(&webhook)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Get(fmt.Sprintf("/webhooks/%s", webhookID)))
	return &webhook, err
}

// CreateWebhook creates a new webhook endpoint
func (c *Client) CreateWebhook(ctx context.Context, webhook *WebhookEndpoint) (*WebhookEndpoint, error) {
	var result WebhookEndpoint
	
	req := c.httpClient.R().
		SetBody(webhook).
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post("/webhooks"))
	return &result, err
}

// TestWebhook tests a webhook endpoint
func (c *Client) TestWebhook(ctx context.Context, webhookID string) (*WebhookTestResult, error) {
	var result WebhookTestResult
	
	req := c.httpClient.R().
		SetResult(&result)
	
	_, err := c.doRequest(ctx, req.SetContext(ctx).Post(fmt.Sprintf("/webhooks/%s/test", webhookID)))
	return &result, err
}

// handleAPIError processes API error responses
func handleAPIError(response *resty.Response) error {
	if response.IsSuccess() {
		return nil
	}

	var apiErr APIError
	if err := json.Unmarshal(response.Body(), &apiErr); err == nil && apiErr.Message != "" {
		apiErr.StatusCode = response.StatusCode()
		return &apiErr
	}

	return &APIError{
		StatusCode: response.StatusCode(),
		Message:    response.String(),
	}
}