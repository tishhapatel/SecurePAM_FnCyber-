"""
Common Pydantic schemas used across the application.
"""

from datetime import datetime
from typing import Any, Generic, List, Literal, Optional, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    error_code: Optional[str] = None


class PaginationParams(BaseModel):
    """Pagination parameters."""
    page: int = 1
    page_size: int = 25
    sort_by: Optional[str] = None
    sort_order: Literal["asc", "desc"] = "desc"


T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response wrapper."""
    items: List[T]
    total: int
    page: int
    page_size: int
    pages: int


class HealthCheck(BaseModel):
    """Health check response."""
    status: str
    version: str
    environment: str
    dev_mode: bool


class ServiceHealth(BaseModel):
    """Individual service health."""
    service: str
    status: str  # healthy, unhealthy, degraded
    latency_ms: Optional[float] = None
    details: Optional[str] = None


class LivenessCheck(BaseModel):
    """Liveness probe response — process is alive, no dependency checks."""
    status: str


class ReadinessCheck(BaseModel):
    """Readiness probe response — required dependencies are reachable."""
    status: str  # ready, not_ready
    checks: List[ServiceHealth]


class DetailedHealthCheck(BaseModel):
    """Detailed health check with all service statuses."""
    status: str
    version: str
    environment: str
    dev_mode: bool
    services: List[ServiceHealth]


class DashboardSummary(BaseModel):
    """Dashboard summary statistics."""
    active_sessions: int = 0
    pending_requests: int = 0
    high_risk_sessions: int = 0
    today_sessions: int = 0
    failed_mfa_attempts: int = 0
    jit_grants_active: int = 0
    registered_assets: int = 0
    recording_storage_mb: float = 0.0


class DashboardActivity(BaseModel):
    """Recent security activity for dashboard."""
    event_id: str
    timestamp: datetime
    severity: str
    action: str
    actor: str
    target: Optional[str] = None
    details: Optional[str] = None


class UserInfo(BaseModel):
    """Current user info returned by /me endpoint."""
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    username: str
    email: str
    full_name: str
    roles: List[str]
    permissions: List[str]
    mfa_enabled: bool
    is_active: bool
