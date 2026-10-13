"""
SecurePAM — FastAPI Application Entry Point.

This is the main application factory that:
1. Configures CORS, middleware, and security headers
2. Mounts health check endpoints (no auth required)
3. Mounts API v1 endpoints (auth required)
4. Runs database initialization and seeding on startup
"""

import asyncio
import time
import uuid
from contextlib import asynccontextmanager, suppress
from app.core.rate_limit import (
    RateLimitUnavailable,
    RedisRateLimiter,
    client_identifier,
)
import structlog
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.health import router as health_router
from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.database.session import async_session_factory, close_db, engine
from app.services.keycloak_mfa_sync import sync_keycloak_mfa_failures

configure_logging()
logger = get_logger(__name__)

async def _keycloak_mfa_sync_loop() -> None:
    """Periodically import failed MFA events from Keycloak."""
    interval = max(10, settings.KEYCLOAK_MFA_SYNC_INTERVAL_SECONDS)

    while True:
        try:
            async with async_session_factory() as db:
                imported = await sync_keycloak_mfa_failures(
                    db,
                    lookback_hours=settings.KEYCLOAK_MFA_SYNC_LOOKBACK_HOURS,
                )

            logger.info(
                "keycloak_mfa_sync_completed",
                imported_count=imported,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("keycloak_mfa_sync_failed")

        await asyncio.sleep(interval)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle — startup and shutdown."""
    logger.info(
        "app_starting",
        app=settings.APP_NAME,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        dev_mode=settings.DEV_MODE,
    )

    # Initialize database tables (in dev mode, create tables directly)
    if settings.DEV_MODE:
        from app.models import Base
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("db_tables_created", mode="DEV_MODE")

        # Seed default data
        await _seed_default_data()

    mfa_sync_task = None

    if (
        settings.KEYCLOAK_MFA_SYNC_ENABLED
        and settings.ENVIRONMENT != "test"
    ):
        mfa_sync_task = asyncio.create_task(_keycloak_mfa_sync_loop())
        logger.info("keycloak_mfa_sync_started")
    app.state.rate_limiter = RedisRateLimiter(settings.REDIS_URL)
    try:
        yield
    finally:
        if mfa_sync_task is not None:
            mfa_sync_task.cancel()
            with suppress(asyncio.CancelledError):
                await mfa_sync_task
        await app.state.rate_limiter.close()
        # Shutdown
        await close_db()
        logger.info("app_shutdown", app=settings.APP_NAME)



app = FastAPI(
    title=settings.APP_NAME,
    description="Risk-Adaptive Privileged Access Management Platform",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEV_MODE else None,
    redoc_url="/redoc" if settings.DEV_MODE else None,
    lifespan=lifespan,
)


# --- Middleware ---

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)



@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """
    Assign a request ID, bind it (plus method/path) to structlog's
    contextvars so every log line emitted while handling this request
    carries it, expose it back to the client via X-Request-ID, and log
    one structured line per request with status/duration.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )

    start = time.monotonic()

    try:
        api_prefix = settings.API_V1_PREFIX.rstrip("/")
        is_api_request = request.url.path.startswith(f"{api_prefix}/")
        is_auth_login = (
            request.url.path == f"{api_prefix}/auth/login"
            and request.method == "POST"
        )

        # NGINX calls the gateway auth hook once per proxied request, all from
        # its own address, so a per-client bucket would throttle every gateway
        # user together. The hook is gated by GATEWAY_AUTH_TOKEN instead.
        is_gateway_auth_hook = request.url.path == f"{api_prefix}/gateway/internal/auth"

        if is_api_request and not is_gateway_auth_hook and settings.ENVIRONMENT != "test":
            limiter = getattr(request.app.state, "rate_limiter", None)

            if limiter is None:
                raise RateLimitUnavailable()

            bucket = "auth" if is_auth_login else "api"
            limit = (
                settings.RATE_LIMIT_AUTH_PER_MINUTE
                if is_auth_login
                else settings.RATE_LIMIT_PER_MINUTE
            )
            client_id = client_identifier(request)

            try:
                allowed, retry_after = await limiter.check(
                    key=f"securepam:rate:{bucket}:{client_id}",
                    limit=limit,
                    window_seconds=60,
                )
            except RateLimitUnavailable:
                response = JSONResponse(
                    status_code=503,
                    content={
                        "detail": (
                            "Rate limiting is temporarily unavailable. "
                            "Please retry shortly."
                        ),
                        "error_code": "RATE_LIMIT_UNAVAILABLE",
                        "errors": None,
                    },
                    headers={"Retry-After": "1"},
                )
            else:
                if not allowed:
                    response = JSONResponse(
                        status_code=429,
                        content={
                            "detail": (
                                "Too many requests. Please try again later."
                            ),
                            "error_code": "RATE_LIMIT_EXCEEDED",
                            "errors": None,
                        },
                        headers={"Retry-After": str(retry_after)},
                    )
                else:
                    response = await call_next(request)
        else:
            response = await call_next(request)

    except RateLimitUnavailable:
        response = JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "Rate limiting is temporarily unavailable. "
                    "Please retry shortly."
                ),
                "error_code": "RATE_LIMIT_UNAVAILABLE",
                "errors": None,
            },
            headers={"Retry-After": "1"},
        )

    except Exception:
        duration_ms = round((time.monotonic() - start) * 1000, 2)
        logger.error(
            "request_failed",
            duration_ms=duration_ms,
            exc_info=True,
        )
        raise

    duration_ms = round((time.monotonic() - start) * 1000, 2)
    response.headers["X-Request-ID"] = request_id

    logger.info(
        "request_completed",
        status_code=response.status_code,
        duration_ms=duration_ms,
    )

    return response



@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # This is a pure JSON API — no inline scripts/styles are ever served, so
    # the policy can stay maximally restrictive.
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    if not settings.DEV_MODE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# --- Exception Handlers ---
#
# Every error response — validation failures, raised HTTPExceptions, and
# unhandled exceptions alike — shares the same envelope:
#   {"detail": "<message>", "error_code": "<MACHINE_CODE>", "errors": [...] | null}
# so frontend error handling has exactly one shape to deal with. Internals
# (stack traces, exception class names, SQL) are logged server-side and
# never put in the response body.


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Pydantic/FastAPI request validation failures — 422."""
    logger.info("validation_failed", errors=exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Request validation failed.",
            "error_code": "VALIDATION_ERROR",
            "errors": [
                {"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")}
                for e in exc.errors()
            ],
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Any explicitly raised HTTPException (401/403/404/409/503/...)."""
    logger.info("http_exception", status_code=exc.status_code, detail=exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": None, "errors": None},
        headers=exc.headers,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch-all for unhandled exceptions. Never expose stack traces to users —
    log the real error server-side and return a generic 500.
    """
    logger.error("unhandled_exception", exc_info=True)
    request_id = getattr(request.state, "request_id", None)
    if not request_id:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred. Please try again later.",
            "error_code": "INTERNAL_ERROR",
            "errors": None,
        },
        headers={"X-Request-ID": request_id},
    )


# --- Routes ---

# Health endpoints — no auth, no prefix
app.include_router(health_router)

# API v1 endpoints — auth required
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


# --- Database Seeding ---

async def _seed_default_data():
    """Seed default roles, permissions, and dev users."""
    from app.database.session import async_session_factory
    from app.models.role import Permission, Role
    from app.models.user import User, UserRole
    from app.core.security import hash_password
    from sqlalchemy import select

    async with async_session_factory() as db:
        # Check if already seeded
        result = await db.execute(select(Role).limit(1))
        if result.scalar_one_or_none():
            logger.info("Database already seeded")
            return

        logger.info("Seeding default data...")

        # --- Create Permissions ---
        permission_defs = [
            # Users
            ("users:read", "users", "read", "View users"),
            ("users:create", "users", "create", "Create users"),
            ("users:update", "users", "update", "Update users"),
            ("users:delete", "users", "delete", "Delete users"),
            # Assets
            ("assets:read", "assets", "read", "View assets"),
            ("assets:create", "assets", "create", "Create assets"),
            ("assets:update", "assets", "update", "Update assets"),
            ("assets:delete", "assets", "delete", "Delete assets"),
            # Applications
            ("applications:read", "applications", "read", "View applications"),
            ("applications:create", "applications", "create", "Create applications"),
            ("applications:update", "applications", "update", "Update applications"),
            ("applications:delete", "applications", "delete", "Delete applications"),
            # Access Requests
            ("access_requests:read", "access_requests", "read", "View access requests"),
            ("access_requests:create", "access_requests", "create", "Create access requests"),
            ("access_requests:read_own", "access_requests", "read_own", "View own requests"),
            # Approvals
            ("approvals:read", "approvals", "read", "View approvals"),
            ("approvals:approve", "approvals", "approve", "Approve requests"),
            ("approvals:reject", "approvals", "reject", "Reject requests"),
            # Sessions
            ("sessions:read", "sessions", "read", "View all sessions"),
            ("sessions:read_own", "sessions", "read_own", "View own sessions"),
            ("sessions:create", "sessions", "create", "Start sessions"),
            ("sessions:terminate", "sessions", "terminate", "Terminate sessions"),
            # Recordings
            ("recordings:read", "recordings", "read", "View recordings"),
            ("recordings:download", "recordings", "download", "Download recordings"),
            ("recordings:delete", "recordings", "delete", "Delete recordings"),
            # Audit
            ("audit:read", "audit", "read", "View audit logs"),
            ("audit:export", "audit", "export", "Export audit logs"),
            # Policies
            ("policies:read", "policies", "read", "View policies"),
            ("policies:create", "policies", "create", "Create policies"),
            ("policies:update", "policies", "update", "Update policies"),
            ("policies:delete", "policies", "delete", "Delete policies"),
            # Vault
            ("vault:read", "vault", "read", "View vault references"),
            ("vault:manage", "vault", "manage", "Manage vault entries"),
            # Risk
            ("risk:read", "risk", "read", "View risk data"),
            # Dashboard
            ("dashboard:read", "dashboard", "read", "View dashboard"),
            # Settings
            ("settings:read", "settings", "read", "View settings"),
            ("settings:update", "settings", "update", "Update settings"),
        ]

        permissions = {}
        for name, resource, action, description in permission_defs:
            perm = Permission(
                name=name,
                resource=resource,
                action=action,
                description=description,
            )
            db.add(perm)
            permissions[name] = perm

        await db.flush()

        # --- Create Roles ---
        admin_role = Role(
            name="ADMIN",
            description="Full system administrator with all privileges",
            is_system=True,
        )
        admin_role.permissions = list(permissions.values())

        operator_role = Role(
            name="OPERATOR",
            description="Standard operator who can request and use privileged access",
            is_system=True,
        )
        operator_role.permissions = [
            permissions["assets:read"],
            permissions["applications:read"],
            permissions["access_requests:create"],
            permissions["access_requests:read_own"],
            permissions["sessions:read_own"],
            permissions["sessions:create"],
            permissions["dashboard:read"],
        ]

        approver_role = Role(
            name="APPROVER",
            description="Can review and approve/reject access requests",
            is_system=True,
        )
        approver_role.permissions = [
            permissions["assets:read"],
            permissions["applications:read"],
            permissions["policies:read"],
            permissions["access_requests:read"],
            permissions["approvals:read"],
            permissions["approvals:approve"],
            permissions["approvals:reject"],
            permissions["risk:read"],
            permissions["dashboard:read"],
        ]

        auditor_role = Role(
            name="AUDITOR",
            description="Can view audit logs, recordings, and generate reports",
            is_system=True,
        )
        auditor_role.permissions = [
            permissions["audit:read"],
            permissions["audit:export"],
            permissions["recordings:read"],
            permissions["sessions:read"],
            permissions["access_requests:read"],
            permissions["risk:read"],
            permissions["dashboard:read"],
            permissions["assets:read"],
            permissions["applications:read"],
            permissions["policies:read"],
            permissions["approvals:read"],
        ]

        db.add_all([admin_role, operator_role, approver_role, auditor_role])
        await db.flush()

        # --- Create Dev Users (DEV_MODE only) ---
        dev_users = [
            {
                "username": "admin",
                "email": "admin@securepam.local",
                "full_name": "System Administrator",
                "password": "admin123",
                "mfa_enabled": True,
                "role": admin_role,
            },
            {
                "username": "operator",
                "email": "operator@securepam.local",
                "full_name": "John Operator",
                "password": "operator123",
                "mfa_enabled": True,
                "role": operator_role,
            },
            {
                "username": "approver",
                "email": "approver@securepam.local",
                "full_name": "Jane Approver",
                "password": "approver123",
                "mfa_enabled": True,
                "role": approver_role,
            },
            {
                "username": "auditor",
                "email": "auditor@securepam.local",
                "full_name": "Bob Auditor",
                "password": "auditor123",
                "mfa_enabled": True,
                "role": auditor_role,
            },
        ]

        for user_data in dev_users:
            user = User(
                username=user_data["username"],
                email=user_data["email"],
                full_name=user_data["full_name"],
                hashed_password=hash_password(user_data["password"]),
                mfa_enabled=user_data["mfa_enabled"],
                is_active=True,
            )
            db.add(user)
            await db.flush()

            user_role = UserRole(
                user_id=user.id,
                role_id=user_data["role"].id,
            )
            db.add(user_role)

        # --- Seed Sample Assets ---
        from app.models.asset import Asset

        sample_assets = [
            Asset(
                name="WIN-PROD-01",
                hostname="win-prod-01.internal",
                ip_address="10.0.1.10",
                port=3389,
                protocol="RDP",
                asset_type="WINDOWS_SERVER",
                environment="PRODUCTION",
                criticality="HIGH",
                description="Production Windows Server — Domain Controller",
                status="ACTIVE",
                enabled=True,
                owner="Infrastructure Team",
                recording_required=True,
                approval_required=True,
                jit_required=True,
            ),
            Asset(
                name="WIN-DEV-01",
                hostname="win-dev-01.internal",
                ip_address="10.0.2.10",
                port=3389,
                protocol="RDP",
                asset_type="WINDOWS_WORKSTATION",
                environment="DEVELOPMENT",
                criticality="LOW",
                description="Development Windows Workstation",
                status="ACTIVE",
                enabled=True,
                owner="Development Team",
                recording_required=False,
                approval_required=False,
                jit_required=True,
            ),
            Asset(
                name="LINUX-PROD-01",
                hostname="linux-prod-01.internal",
                ip_address="10.0.1.20",
                port=22,
                protocol="SSH",
                asset_type="LINUX_SERVER",
                environment="PRODUCTION",
                criticality="HIGH",
                description="Production Linux Server — Application Host",
                status="ACTIVE",
                enabled=True,
                owner="DevOps Team",
                recording_required=True,
                approval_required=True,
                jit_required=True,
            ),
            Asset(
                name="LINUX-DEV-01",
                hostname="linux-dev-01.internal",
                ip_address="10.0.2.20",
                port=22,
                protocol="SSH",
                asset_type="LINUX_SERVER",
                environment="DEVELOPMENT",
                criticality="MEDIUM",
                description="Development Ubuntu Server",
                status="ACTIVE",
                enabled=True,
                owner="Development Team",
                recording_required=False,
                approval_required=False,
                jit_required=True,
            ),
            Asset(
                name="LINUX-STAGING-01",
                hostname="linux-staging-01.internal",
                ip_address="10.0.3.20",
                port=22,
                protocol="SSH",
                asset_type="LINUX_SERVER",
                environment="STAGING",
                criticality="MEDIUM",
                description="Staging Linux Server",
                status="ACTIVE",
                enabled=True,
                owner="QA Team",
                recording_required=True,
                approval_required=False,
                jit_required=True,
            ),
        ]
        db.add_all(sample_assets)

        # --- Seed Sample Applications ---
        from app.models.application import Application

        sample_apps = [
            Application(
                name="Admin Portal",
                description="Internal administration dashboard — HIGH risk",
                target_url="https://admin.internal:8443",
                protocol="HTTPS",
                hostname="admin.internal",
                port=8443,
                environment="PRODUCTION",
                criticality="HIGH",
                access_mode="ISOLATED_BROWSER",
                approval_required=True,
                mfa_required=True,
                recording_required=True,
                download_allowed=False,
                upload_allowed=False,
                clipboard_allowed=False,
                session_timeout=30,
                status="ACTIVE",
                enabled=True,
            ),
            Application(
                name="Monitoring Dashboard",
                description="Grafana monitoring dashboard",
                target_url="http://monitoring.internal:3000",
                protocol="HTTP",
                hostname="monitoring.internal",
                port=3000,
                environment="PRODUCTION",
                criticality="LOW",
                access_mode="STANDARD_PROXY",
                approval_required=False,
                mfa_required=False,
                recording_required=False,
                download_allowed=True,
                upload_allowed=False,
                clipboard_allowed=True,
                session_timeout=60,
                status="ACTIVE",
                enabled=True,
            ),
            Application(
                name="CI/CD Pipeline",
                description="Jenkins CI/CD server",
                target_url="https://jenkins.internal:8080",
                protocol="HTTPS",
                hostname="jenkins.internal",
                port=8080,
                environment="STAGING",
                criticality="MEDIUM",
                access_mode="STANDARD_PROXY",
                approval_required=False,
                mfa_required=True,
                recording_required=False,
                download_allowed=True,
                upload_allowed=True,
                clipboard_allowed=True,
                session_timeout=60,
                status="ACTIVE",
                enabled=True,
            ),
        ]
        db.add_all(sample_apps)

        # --- Seed Default Policies ---
        from app.models.policy import Policy

        default_policies = [
            Policy(
                name="Standard Access",
                description="Default policy for low-risk access",
                risk_threshold="LOW",
                min_risk_score=0,
                allowed_environments=["DEVELOPMENT", "TEST"],
                require_approval=False,
                jit_required=True,
                require_mfa=False,
                require_recording=False,
                max_session_duration=60,
                download_allowed=True,
                upload_allowed=True,
                clipboard_allowed=True,
                auto_approve=True,
                deny_access=False,
                enabled=True,
            ),
            Policy(
                name="Enhanced Security",
                description="Policy for medium-risk access requiring MFA",
                risk_threshold="MEDIUM",
                min_risk_score=30,
                allowed_environments=["STAGING"],
                require_approval=False,
                jit_required=True,
                require_mfa=True,
                require_recording=False,
                max_session_duration=30,
                download_allowed=True,
                upload_allowed=True,
                clipboard_allowed=True,
                auto_approve=False,
                deny_access=False,
                enabled=True,
            ),
            Policy(
                name="Production Linux Access",
                description="High-security policy for OPERATOR SSH access to production Linux hosts",
                risk_threshold="HIGH",
                min_risk_score=60,
                allowed_roles=["OPERATOR"],
                allowed_asset_types=["LINUX_SERVER", "UNIX_SERVER"],
                allowed_environments=["PRODUCTION"],
                allowed_protocols=["SSH"],
                business_hours_only=True,
                allowed_days=["MON", "TUE", "WED", "THU", "FRI"],
                require_approval=True,
                jit_required=True,
                require_mfa=True,
                require_recording=True,
                max_session_duration=30,
                download_allowed=False,
                upload_allowed=False,
                clipboard_allowed=False,
                auto_approve=False,
                deny_access=False,
                enabled=True,
            ),
            Policy(
                name="Critical Lockdown",
                description="Policy for critical-risk — deny or require elevated approval",
                risk_threshold="CRITICAL",
                min_risk_score=80,
                require_approval=True,
                jit_required=True,
                require_mfa=True,
                require_recording=True,
                max_session_duration=15,
                download_allowed=False,
                upload_allowed=False,
                clipboard_allowed=False,
                auto_approve=False,
                deny_access=True,
                enabled=True,
            ),
        ]
        db.add_all(default_policies)

        await db.commit()
        logger.info("Default data seeded successfully")
