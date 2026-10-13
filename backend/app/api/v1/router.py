"""
API v1 Router — aggregates all v1 endpoint routers.
"""

from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.auth import router as auth_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.assets import router as assets_router
from app.api.v1.applications import router as applications_router
from app.api.v1.policies import router as policies_router
from app.api.v1.access_requests import router as access_requests_router
from app.api.v1.approvals import router as approvals_router
from app.api.v1.credential_refs import router as credential_refs_router
# M9 & M12 Routers
from app.api.v1.sessions import router as sessions_router
from app.api.v1.recordings import router as recordings_router
from app.api.v1.audit import router as audit_router
from app.api.v1.gateway import router as gateway_router          # Member 11 — Day 1
from app.api.v1.gateway import internal_router as gateway_internal_router  # Member 11 — Day 3 auth hook


# Main v1 router
api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(assets_router)
api_router.include_router(applications_router)
api_router.include_router(policies_router)
api_router.include_router(access_requests_router)
api_router.include_router(approvals_router)
api_router.include_router(credential_refs_router)
# Registered M9 & M12 sub-routers
api_router.include_router(sessions_router)
api_router.include_router(recordings_router)
api_router.include_router(audit_router)
api_router.include_router(gateway_router)
# Internal gateway router — auth_request hook for NGINX.
# Protected by X-Gateway-Auth-Token pre-shared secret; not publicly exploitable.
api_router.include_router(gateway_internal_router)

# Health is mounted at root level, not under /api/v1
