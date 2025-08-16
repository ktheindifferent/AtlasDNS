"""
Atlas DNS Python SDK

Official Python client library for Atlas DNS Server with async support.
"""

__version__ = "1.0.0"
__author__ = "Atlas DNS Team"

from .client import AtlasDNSClient, AsyncAtlasDNSClient
from .models import (
    Zone,
    Record,
    RecordType,
    HealthCheck,
    TrafficPolicy,
    GeoDNSRule,
    DNSSECConfig,
    WebhookEndpoint,
    BulkOperation,
)
from .exceptions import (
    AtlasDNSException,
    AuthenticationError,
    RateLimitError,
    ResourceNotFoundError,
    ValidationError,
    ServerError,
)

__all__ = [
    # Clients
    "AtlasDNSClient",
    "AsyncAtlasDNSClient",
    
    # Models
    "Zone",
    "Record",
    "RecordType",
    "HealthCheck",
    "TrafficPolicy",
    "GeoDNSRule",
    "DNSSECConfig",
    "WebhookEndpoint",
    "BulkOperation",
    
    # Exceptions
    "AtlasDNSException",
    "AuthenticationError",
    "RateLimitError",
    "ResourceNotFoundError",
    "ValidationError",
    "ServerError",
]