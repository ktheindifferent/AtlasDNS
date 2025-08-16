"""
Atlas DNS Client Implementation

Provides both synchronous and asynchronous clients for interacting with Atlas DNS Server.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin

import backoff
import httpx
from pydantic import BaseModel

from .models import (
    Zone, Record, HealthCheck, TrafficPolicy, GeoDNSRule,
    DNSSECConfig, WebhookEndpoint, BulkOperation, QueryResult,
    AnalyticsData, SystemStatus, User, Settings
)
from .exceptions import (
    AtlasDNSException, AuthenticationError, RateLimitError,
    ResourceNotFoundError, ValidationError, ServerError
)


class BaseClient:
    """Base client with common functionality."""
    
    def __init__(
        self,
        base_url: str = "http://localhost:5380",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        verify_ssl: bool = True,
    ):
        """
        Initialize the Atlas DNS client.
        
        Args:
            base_url: Base URL of the Atlas DNS server
            api_key: API key for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "atlas-dns-python-sdk/1.0.0",
        }
        
        if api_key:
            self.headers["X-API-Key"] = api_key
    
    def _handle_response(self, response: httpx.Response) -> Any:
        """Handle API response and raise appropriate exceptions."""
        if response.status_code == 401:
            raise AuthenticationError("Authentication failed")
        elif response.status_code == 403:
            raise AuthenticationError("Permission denied")
        elif response.status_code == 404:
            raise ResourceNotFoundError("Resource not found")
        elif response.status_code == 422:
            raise ValidationError(f"Validation error: {response.text}")
        elif response.status_code == 429:
            raise RateLimitError("Rate limit exceeded")
        elif response.status_code >= 500:
            raise ServerError(f"Server error: {response.status_code}")
        elif response.status_code >= 400:
            raise AtlasDNSException(f"API error: {response.text}")
        
        try:
            return response.json()
        except json.JSONDecodeError:
            return response.text


class AtlasDNSClient(BaseClient):
    """Synchronous client for Atlas DNS Server."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = httpx.Client(
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers=self.headers,
        )
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def close(self):
        """Close the HTTP client."""
        self.client.close()
    
    @backoff.on_exception(
        backoff.expo,
        (httpx.TimeoutException, httpx.ConnectError),
        max_tries=3,
    )
    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
    ) -> Any:
        """Make an HTTP request to the API."""
        url = urljoin(self.base_url, f"/api/v2{path}")
        response = self.client.request(
            method=method,
            url=url,
            params=params,
            json=json_data,
        )
        return self._handle_response(response)
    
    # Zone Management
    
    def list_zones(self, **params) -> List[Zone]:
        """List all DNS zones."""
        data = self._request("GET", "/zones", params=params)
        return [Zone(**zone) for zone in data]
    
    def get_zone(self, zone_id: str) -> Zone:
        """Get a specific zone by ID."""
        data = self._request("GET", f"/zones/{zone_id}")
        return Zone(**data)
    
    def create_zone(self, zone: Union[Zone, Dict]) -> Zone:
        """Create a new DNS zone."""
        if isinstance(zone, Zone):
            zone = zone.model_dump()
        data = self._request("POST", "/zones", json_data=zone)
        return Zone(**data)
    
    def update_zone(self, zone_id: str, updates: Dict) -> Zone:
        """Update an existing zone."""
        data = self._request("PUT", f"/zones/{zone_id}", json_data=updates)
        return Zone(**data)
    
    def delete_zone(self, zone_id: str) -> bool:
        """Delete a zone."""
        self._request("DELETE", f"/zones/{zone_id}")
        return True
    
    def validate_zone(self, zone_id: str) -> Dict:
        """Validate zone configuration."""
        return self._request("GET", f"/zones/{zone_id}/validate")
    
    # Record Management
    
    def list_records(self, zone_id: str, **params) -> List[Record]:
        """List all records in a zone."""
        data = self._request("GET", f"/zones/{zone_id}/records", params=params)
        return [Record(**record) for record in data]
    
    def get_record(self, zone_id: str, record_id: str) -> Record:
        """Get a specific record."""
        data = self._request("GET", f"/zones/{zone_id}/records/{record_id}")
        return Record(**data)
    
    def create_record(self, zone_id: str, record: Union[Record, Dict]) -> Record:
        """Create a new DNS record."""
        if isinstance(record, Record):
            record = record.model_dump()
        data = self._request("POST", f"/zones/{zone_id}/records", json_data=record)
        return Record(**data)
    
    def update_record(
        self, zone_id: str, record_id: str, updates: Dict
    ) -> Record:
        """Update an existing record."""
        data = self._request(
            "PUT", f"/zones/{zone_id}/records/{record_id}", json_data=updates
        )
        return Record(**data)
    
    def delete_record(self, zone_id: str, record_id: str) -> bool:
        """Delete a record."""
        self._request("DELETE", f"/zones/{zone_id}/records/{record_id}")
        return True
    
    # Bulk Operations
    
    def bulk_create_records(
        self, zone_id: str, records: List[Union[Record, Dict]]
    ) -> List[Record]:
        """Create multiple records at once."""
        records_data = [
            r.model_dump() if isinstance(r, Record) else r for r in records
        ]
        data = self._request(
            "POST", f"/zones/{zone_id}/records/bulk", json_data={"records": records_data}
        )
        return [Record(**record) for record in data]
    
    def execute_bulk_operation(self, operation: Union[BulkOperation, Dict]) -> Dict:
        """Execute a bulk operation."""
        if isinstance(operation, BulkOperation):
            operation = operation.model_dump()
        return self._request("POST", "/bulk", json_data=operation)
    
    # Health Checks
    
    def list_health_checks(self, **params) -> List[HealthCheck]:
        """List all health checks."""
        data = self._request("GET", "/health-checks", params=params)
        return [HealthCheck(**check) for check in data]
    
    def get_health_check(self, check_id: str) -> HealthCheck:
        """Get a specific health check."""
        data = self._request("GET", f"/health-checks/{check_id}")
        return HealthCheck(**data)
    
    def create_health_check(
        self, health_check: Union[HealthCheck, Dict]
    ) -> HealthCheck:
        """Create a new health check."""
        if isinstance(health_check, HealthCheck):
            health_check = health_check.model_dump()
        data = self._request("POST", "/health-checks", json_data=health_check)
        return HealthCheck(**data)
    
    def update_health_check(
        self, check_id: str, updates: Dict
    ) -> HealthCheck:
        """Update a health check."""
        data = self._request(
            "PUT", f"/health-checks/{check_id}", json_data=updates
        )
        return HealthCheck(**data)
    
    def delete_health_check(self, check_id: str) -> bool:
        """Delete a health check."""
        self._request("DELETE", f"/health-checks/{check_id}")
        return True
    
    def test_health_check(self, check_id: str) -> Dict:
        """Test a health check."""
        return self._request("POST", f"/health-checks/{check_id}/test")
    
    # Traffic Policies
    
    def list_traffic_policies(self, **params) -> List[TrafficPolicy]:
        """List all traffic policies."""
        data = self._request("GET", "/traffic-policies", params=params)
        return [TrafficPolicy(**policy) for policy in data]
    
    def get_traffic_policy(self, policy_id: str) -> TrafficPolicy:
        """Get a specific traffic policy."""
        data = self._request("GET", f"/traffic-policies/{policy_id}")
        return TrafficPolicy(**data)
    
    def create_traffic_policy(
        self, policy: Union[TrafficPolicy, Dict]
    ) -> TrafficPolicy:
        """Create a new traffic policy."""
        if isinstance(policy, TrafficPolicy):
            policy = policy.model_dump()
        data = self._request("POST", "/traffic-policies", json_data=policy)
        return TrafficPolicy(**data)
    
    def update_traffic_policy(
        self, policy_id: str, updates: Dict
    ) -> TrafficPolicy:
        """Update a traffic policy."""
        data = self._request(
            "PUT", f"/traffic-policies/{policy_id}", json_data=updates
        )
        return TrafficPolicy(**data)
    
    def delete_traffic_policy(self, policy_id: str) -> bool:
        """Delete a traffic policy."""
        self._request("DELETE", f"/traffic-policies/{policy_id}")
        return True
    
    def simulate_traffic_policy(self, policy_id: str, params: Dict) -> Dict:
        """Simulate a traffic policy."""
        return self._request(
            "POST", f"/traffic-policies/{policy_id}/simulate", json_data=params
        )
    
    # GeoDNS
    
    def list_geodns_rules(self, **params) -> List[GeoDNSRule]:
        """List all GeoDNS rules."""
        data = self._request("GET", "/geodns", params=params)
        return [GeoDNSRule(**rule) for rule in data]
    
    def get_geodns_rule(self, rule_id: str) -> GeoDNSRule:
        """Get a specific GeoDNS rule."""
        data = self._request("GET", f"/geodns/{rule_id}")
        return GeoDNSRule(**data)
    
    def create_geodns_rule(self, rule: Union[GeoDNSRule, Dict]) -> GeoDNSRule:
        """Create a new GeoDNS rule."""
        if isinstance(rule, GeoDNSRule):
            rule = rule.model_dump()
        data = self._request("POST", "/geodns", json_data=rule)
        return GeoDNSRule(**data)
    
    def update_geodns_rule(self, rule_id: str, updates: Dict) -> GeoDNSRule:
        """Update a GeoDNS rule."""
        data = self._request("PUT", f"/geodns/{rule_id}", json_data=updates)
        return GeoDNSRule(**data)
    
    def delete_geodns_rule(self, rule_id: str) -> bool:
        """Delete a GeoDNS rule."""
        self._request("DELETE", f"/geodns/{rule_id}")
        return True
    
    def get_geodns_regions(self) -> List[Dict]:
        """Get available GeoDNS regions."""
        return self._request("GET", "/geodns/regions")
    
    # DNSSEC
    
    def get_dnssec_status(self, zone_id: str) -> DNSSECConfig:
        """Get DNSSEC status for a zone."""
        data = self._request("GET", f"/zones/{zone_id}/dnssec")
        return DNSSECConfig(**data)
    
    def enable_dnssec(self, zone_id: str, config: Dict) -> DNSSECConfig:
        """Enable DNSSEC for a zone."""
        data = self._request(
            "POST", f"/zones/{zone_id}/dnssec/enable", json_data=config
        )
        return DNSSECConfig(**data)
    
    def disable_dnssec(self, zone_id: str) -> bool:
        """Disable DNSSEC for a zone."""
        self._request("POST", f"/zones/{zone_id}/dnssec/disable")
        return True
    
    def rotate_dnssec_keys(self, zone_id: str) -> DNSSECConfig:
        """Rotate DNSSEC keys for a zone."""
        data = self._request("POST", f"/zones/{zone_id}/dnssec/rotate-keys")
        return DNSSECConfig(**data)
    
    # Analytics
    
    def get_analytics_overview(self, **params) -> AnalyticsData:
        """Get analytics overview."""
        data = self._request("GET", "/analytics/overview", params=params)
        return AnalyticsData(**data)
    
    def get_query_analytics(self, **params) -> Dict:
        """Get query analytics."""
        return self._request("GET", "/analytics/queries", params=params)
    
    def get_performance_metrics(self, **params) -> Dict:
        """Get performance metrics."""
        return self._request("GET", "/analytics/performance", params=params)
    
    def get_geographic_analytics(self, **params) -> Dict:
        """Get geographic analytics."""
        return self._request("GET", "/analytics/geography", params=params)
    
    def get_top_domains(self, **params) -> List[Dict]:
        """Get top queried domains."""
        return self._request("GET", "/analytics/top-domains", params=params)
    
    # Query
    
    def query_dns(
        self,
        domain: str,
        record_type: str = "A",
        **params
    ) -> QueryResult:
        """Query DNS records."""
        data = self._request(
            "POST",
            "/query",
            json_data={
                "domain": domain,
                "type": record_type,
                **params
            }
        )
        return QueryResult(**data)
    
    # Monitoring
    
    def get_system_status(self) -> SystemStatus:
        """Get system status."""
        data = self._request("GET", "/monitoring/status")
        return SystemStatus(**data)
    
    def get_metrics(self, **params) -> Dict:
        """Get system metrics."""
        return self._request("GET", "/monitoring/metrics", params=params)
    
    # Webhooks
    
    def list_webhooks(self, **params) -> List[WebhookEndpoint]:
        """List all webhook endpoints."""
        data = self._request("GET", "/webhooks", params=params)
        return [WebhookEndpoint(**webhook) for webhook in data]
    
    def get_webhook(self, webhook_id: str) -> WebhookEndpoint:
        """Get a specific webhook endpoint."""
        data = self._request("GET", f"/webhooks/{webhook_id}")
        return WebhookEndpoint(**data)
    
    def create_webhook(
        self, webhook: Union[WebhookEndpoint, Dict]
    ) -> WebhookEndpoint:
        """Create a new webhook endpoint."""
        if isinstance(webhook, WebhookEndpoint):
            webhook = webhook.model_dump()
        data = self._request("POST", "/webhooks", json_data=webhook)
        return WebhookEndpoint(**data)
    
    def update_webhook(
        self, webhook_id: str, updates: Dict
    ) -> WebhookEndpoint:
        """Update a webhook endpoint."""
        data = self._request(
            "PUT", f"/webhooks/{webhook_id}", json_data=updates
        )
        return WebhookEndpoint(**data)
    
    def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook endpoint."""
        self._request("DELETE", f"/webhooks/{webhook_id}")
        return True
    
    def test_webhook(self, webhook_id: str) -> Dict:
        """Test a webhook endpoint."""
        return self._request("POST", f"/webhooks/{webhook_id}/test")


class AsyncAtlasDNSClient(BaseClient):
    """Asynchronous client for Atlas DNS Server."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers=self.headers,
        )
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()
    
    @backoff.on_exception(
        backoff.expo,
        (httpx.TimeoutException, httpx.ConnectError),
        max_tries=3,
    )
    async def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
    ) -> Any:
        """Make an HTTP request to the API."""
        url = urljoin(self.base_url, f"/api/v2{path}")
        response = await self.client.request(
            method=method,
            url=url,
            params=params,
            json=json_data,
        )
        return self._handle_response(response)
    
    # Async versions of all methods from AtlasDNSClient
    # Implementation follows the same pattern as sync client but with async/await
    
    async def list_zones(self, **params) -> List[Zone]:
        """List all DNS zones."""
        data = await self._request("GET", "/zones", params=params)
        return [Zone(**zone) for zone in data]
    
    async def get_zone(self, zone_id: str) -> Zone:
        """Get a specific zone by ID."""
        data = await self._request("GET", f"/zones/{zone_id}")
        return Zone(**data)
    
    async def create_zone(self, zone: Union[Zone, Dict]) -> Zone:
        """Create a new DNS zone."""
        if isinstance(zone, Zone):
            zone = zone.model_dump()
        data = await self._request("POST", "/zones", json_data=zone)
        return Zone(**data)
    
    async def update_zone(self, zone_id: str, updates: Dict) -> Zone:
        """Update an existing zone."""
        data = await self._request("PUT", f"/zones/{zone_id}", json_data=updates)
        return Zone(**data)
    
    async def delete_zone(self, zone_id: str) -> bool:
        """Delete a zone."""
        await self._request("DELETE", f"/zones/{zone_id}")
        return True
    
    # ... (Continue with async versions of all other methods)