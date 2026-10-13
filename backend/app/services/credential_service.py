"""
CredentialService — the only code path that turns a registered asset's
credential reference into a usable credential.

Backend-only by design. There is no HTTP endpoint that returns what this
yields: the future RDP/SSH gateway calls `checkout()` in-process while
setting up an authorized session and hands the secret straight to the
protocol handshake. Usage:

    async with CredentialService().checkout(db, CheckoutRequest(...)) as cred:
        connect(username=cred.username, password=cred.reveal())
    # cred is wiped here

Every check below must pass, in order, or retrieval is refused (fail
closed) — nothing is read from the secret store until they all have:

  1. User exists, is active, not deleted, and holds sessions:create.
  2. Access request exists, belongs to that user, targets that asset, is
     ACTIVE, and — if it required approval — has an APPROVED Approval.
  3. Asset exists, is not deleted, is enabled, and has status ACTIVE.
  4. The JIT grant exists, is bound to the same request/user/asset, its
     protocol matches the request and asset, and JITService says it is
     live (status ACTIVE, not past expires_at — a lapsed ACTIVE grant is
     flipped to EXPIRED here, the same way JITService.validate does).
  5. If a session_id is given, that session is bound to the same
     user/asset/request/grant and is not finished.
  6. Exactly one active credential reference exists for the asset, it
     names the provider currently configured (no cross-provider
     fallback), and its path passes app/secret_providers/paths.py.

Audit trail (app/core/audit.py): CREDENTIAL_RETRIEVAL_ATTEMPTED, then one
of CREDENTIAL_RETRIEVED / CREDENTIAL_RETRIEVAL_DENIED (authorization) /
CREDENTIAL_RETRIEVAL_FAILED (provider). Metadata holds IDs, the reference
path, provider name, version and a reason code — never the secret, the
token, or a provider response body. Audit rows are committed before any
exception is raised, per write_audit_log's commit-before-raise rule.
"""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import write_audit_log
from app.core.config import settings
from app.core.deps import user_has_permission
from app.models.access_request import AccessRequest
from app.models.application import Application
from app.models.approval import Approval
from app.models.asset import Asset
from app.models.jit_grant import JITGrant
from app.models.session import Session
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.secret_providers import (
    Credential,
    InvalidSecretReferenceError,
    SecretProvider,
    SecretProviderError,
    get_secret_provider,
)
from app.secret_providers.paths import validate_secret_path
from app.services.jit_service import JITService

# KV field holding the secret for each VaultRef.secret_type.
SECRET_FIELDS = {
    "PASSWORD": "password",
    "SSH_KEY": "private_key",
    "API_KEY": "api_key",
    "CERTIFICATE": "certificate",
}

LIVE_SESSION_STATUSES = {"CREATED", "STARTING", "ACTIVE"}


@dataclass(frozen=True)
class CheckoutRequest:
    """What a gateway knows about the session it is setting up. All IDs
    are re-resolved from the database — none of them is trusted as-is."""

    user_id: UUID
    access_request_id: UUID
    jit_grant_id: UUID
    asset_id: Optional[UUID] = None
    application_id: Optional[UUID] = None
    session_id: Optional[UUID] = None
    source_ip: Optional[str] = None


class CredentialAccessDenied(Exception):
    """Authorization failed. `reason` is a stable code (also in the audit
    row); deliberately coarse so callers can't probe which check failed
    beyond what the audit log already records for operators."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Credential retrieval denied: {reason}")


class CredentialUnavailable(Exception):
    """Authorized, but the provider could not supply the secret."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(f"Credential retrieval failed: {reason}")


class CredentialService:
    def __init__(self, provider: Optional[SecretProvider] = None, jit: Optional[JITService] = None):
        self._provider = provider
        self._jit = jit or JITService()

    @property
    def provider(self) -> SecretProvider:
        return self._provider or get_secret_provider()

    @asynccontextmanager
    async def checkout(self, db: AsyncSession, req: CheckoutRequest) -> AsyncIterator[Credential]:
        credential = await self._retrieve(db, req)
        try:
            yield credential
        finally:
            credential.wipe()

    # --- internals ---

    async def _retrieve(self, db: AsyncSession, req: CheckoutRequest) -> Credential:
        user = await self._load_user(db, req.user_id)
        access_request = await db.get(AccessRequest, req.access_request_id)
        session = await db.get(Session, req.session_id) if req.session_id else None

        target_type = "application" if req.application_id else "asset"
        target_id = str(req.application_id if req.application_id else req.asset_id)

        audit = dict(
            actor=user,
            target_type=target_type,
            target_id=target_id,
            # These columns are FKs — only set them once the row is known to exist.
            request_id=access_request.id if access_request else None,
            session_id=session.id if session else None,
            source_ip=req.source_ip,
        )
        base_meta = {
            "user_id": str(req.user_id),
            "access_request_id": str(req.access_request_id),
            "jit_grant_id": str(req.jit_grant_id),
            "session_id": str(req.session_id) if req.session_id else None,
            "provider": self.provider.name,
            "target_type": target_type,
            "target_id": target_id,
        }

        await write_audit_log(
            db, action="CREDENTIAL_RETRIEVAL_ATTEMPTED", result="SUCCESS", severity="INFO",
            metadata=base_meta, **audit,
        )

        reason = await self._authorize(db, req, user, access_request, session)
        ref: Optional[VaultRef] = None
        if reason is None:
            ref, reason = await self._resolve_reference(
                db, asset_id=req.asset_id, application_id=req.application_id
            )

        if reason is not None:
            await write_audit_log(
                db, action="CREDENTIAL_RETRIEVAL_DENIED", result="DENIED", severity="MEDIUM",
                metadata={**base_meta, "reason": reason}, **audit,
            )
            await db.commit()
            raise CredentialAccessDenied(reason)

        ref_meta = {**base_meta, "secret_reference": ref.vault_path, "vault_ref_id": str(ref.id)}
        try:
            record = await self.provider.read_secret(ref.vault_path, version=ref.secret_version)
            field = SECRET_FIELDS.get(ref.secret_type)
            secret = record.data.get(field) if field else None
            if not isinstance(secret, str) or not secret:
                raise SecretProviderError("Secret is missing its expected field")
            username = record.data.get("username") or ref.username
            credential = Credential(
                username=username if isinstance(username, str) else None,
                secret=secret,
                secret_type=ref.secret_type,
                version=record.version,
            )
            del record, secret
        except SecretProviderError as exc:
            await write_audit_log(
                db, action="CREDENTIAL_RETRIEVAL_FAILED", result="FAILURE", severity="HIGH",
                metadata={**ref_meta, "reason": exc.code}, **audit,
            )
            await db.commit()
            raise CredentialUnavailable(exc.code) from None

        await write_audit_log(
            db, action="CREDENTIAL_RETRIEVED", result="SUCCESS", severity="INFO",
            metadata={**ref_meta, "secret_version": credential.version}, **audit,
        )
        await db.commit()
        return credential

    async def _load_user(self, db: AsyncSession, user_id: UUID) -> Optional[User]:
        result = await db.execute(
            select(User).where(User.id == user_id, User.is_active == True, User.is_deleted == False)
        )
        return result.scalar_one_or_none()

    async def _authorize(
        self, db: AsyncSession, req: CheckoutRequest, user: Optional[User],
        access_request: Optional[AccessRequest], session: Optional[Session],
    ) -> Optional[str]:
        """Returns None if every check passes, else the first failing reason code."""
        # 0. target validation — exactly one target must be specified
        if (req.asset_id is None and req.application_id is None) or (
            req.asset_id is not None and req.application_id is not None
        ):
            return "INVALID_TARGET_SPECIFICATION"

        # 1. user
        if user is None:
            return "USER_NOT_FOUND_OR_INACTIVE"
        if not user_has_permission(user, "sessions", "create"):
            return "PERMISSION_DENIED"

        # 2. access request
        if access_request is None:
            return "ACCESS_REQUEST_NOT_FOUND"
        if access_request.user_id != user.id:
            return "ACCESS_REQUEST_USER_MISMATCH"
        if req.application_id is not None:
            if access_request.application_id != req.application_id:
                return "ACCESS_REQUEST_TARGET_MISMATCH"
        else:
            if access_request.asset_id != req.asset_id:
                return "ACCESS_REQUEST_TARGET_MISMATCH"
        if access_request.status != "ACTIVE":
            return "ACCESS_REQUEST_NOT_ACTIVE"
        if access_request.approval_required:
            approved = await db.execute(
                select(Approval.id).where(
                    Approval.request_id == access_request.id, Approval.status == "APPROVED"
                )
            )
            if approved.first() is None:
                return "APPROVAL_MISSING"

        # 3. target
        if req.application_id is not None:
            target_obj = await db.get(Application, req.application_id)
            if target_obj is None or target_obj.is_deleted:
                return "APPLICATION_NOT_FOUND"
            if not target_obj.enabled or target_obj.status != "ACTIVE":
                return "APPLICATION_DISABLED"
        else:
            target_obj = await db.get(Asset, req.asset_id)
            if target_obj is None or target_obj.is_deleted:
                return "ASSET_NOT_FOUND"
            if not target_obj.enabled or target_obj.status != "ACTIVE":
                return "ASSET_DISABLED"

        # 4. JIT grant
        grant = await db.get(JITGrant, req.jit_grant_id)
        if grant is None:
            return "JIT_GRANT_NOT_FOUND"
        if (
            grant.request_id != access_request.id
            or grant.user_id != user.id
        ):
            return "JIT_GRANT_MISMATCH"
        if req.application_id is not None:
            if grant.application_id != target_obj.id:
                return "JIT_GRANT_MISMATCH"
        else:
            if grant.asset_id != target_obj.id:
                return "JIT_GRANT_MISMATCH"

        if not (grant.protocol == access_request.protocol == target_obj.protocol):
            return "PROTOCOL_MISMATCH"
        if not self._jit.is_active(grant):
            if grant.status == "ACTIVE":  # lapsed but not yet flipped
                await self._jit.expire(db, grant)
                target_type = "application" if req.application_id else "asset"
                await write_audit_log(
                    db, actor=user, action="JIT_EXPIRED", target_type=target_type, target_id=str(target_obj.id),
                    request_id=access_request.id, result="SUCCESS", severity="INFO",
                    metadata={"jit_grant_id": str(grant.id), "expires_at": grant.expires_at.isoformat()},
                )
                return "JIT_GRANT_EXPIRED"
            return f"JIT_GRANT_{grant.status}"  # JIT_GRANT_EXPIRED / JIT_GRANT_REVOKED

        # 5. session binding (when the gateway has already created one)
        if req.session_id is not None:
            if session is None:
                return "SESSION_NOT_FOUND"
            if (
                session.user_id != user.id
                or session.request_id != access_request.id
                or session.jit_grant_id != grant.id
            ):
                return "SESSION_MISMATCH"
            if req.application_id is not None:
                if session.application_id != target_obj.id:
                    return "SESSION_MISMATCH"
            else:
                if session.asset_id != target_obj.id:
                    return "SESSION_MISMATCH"
            if session.status not in LIVE_SESSION_STATUSES:
                return "SESSION_NOT_LIVE"

        return None

    async def _resolve_reference(
        self, db: AsyncSession, *, asset_id: Optional[UUID] = None, application_id: Optional[UUID] = None
    ) -> tuple[Optional[VaultRef], Optional[str]]:
        if application_id is not None:
            stmt = select(VaultRef).where(VaultRef.application_id == application_id, VaultRef.is_active == True)
        elif asset_id is not None:
            stmt = select(VaultRef).where(VaultRef.asset_id == asset_id, VaultRef.is_active == True)
        else:
            return None, "NO_CREDENTIAL_REFERENCE"

        result = await db.execute(stmt)
        refs = result.scalars().all()
        if not refs:
            return None, "NO_CREDENTIAL_REFERENCE"
        if len(refs) > 1:
            return None, "AMBIGUOUS_CREDENTIAL_REFERENCE"
        ref = refs[0]
        if ref.provider != self.provider.name:
            return None, "PROVIDER_MISMATCH"
        if ref.secret_type not in SECRET_FIELDS:
            return None, "UNSUPPORTED_SECRET_TYPE"
        try:
            validate_secret_path(ref.vault_path, settings.OPENBAO_SECRET_PATH_PREFIX)
        except InvalidSecretReferenceError:
            return None, InvalidSecretReferenceError.code
        return ref, None
