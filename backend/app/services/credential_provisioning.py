"""
Integrated asset-credential provisioning (admin-only).

One workflow instead of "create the asset, then go to OpenBao, then come back and bind a reference":

  1. the secret NAME must be in settings.ASSET_CREDENTIAL_SECRET_NAMES (the browser never supplies a
     path) and not already bound to another asset;
  2. the password is written through the separate WRITER identity (create+update, no read);
  3. the write is VERIFIED by reading that exact version back with the backend's READER identity and
     comparing in constant time; the value is discarded immediately;
  4. only then is the vault_refs binding written and the transaction committed.

Any failure raises ProvisioningError with the stage that failed and a recovery hint; callers roll the
database back, so an asset is never left pointing at a credential that was not verified. If the write
succeeded but a later stage failed, the hint says so (a retry simply writes a newer version).
Nothing here logs, audits or returns the password.
"""

import hmac
from dataclasses import dataclass
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset
from app.models.vault_ref import VaultRef
from app.secret_providers import (
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretProviderError,
    SecretProviderUnavailableError,
    get_secret_provider,
)
from app.secret_providers.paths import asset_secret_path
from app.secret_providers.writer import CredentialWriterNotConfigured, get_credential_writer

SECRET_FIELD = {"PASSWORD": "password", "SSH_KEY": "private_key"}


class ProvisioningError(Exception):
    def __init__(self, stage: str, code: str, detail: str, recovery: str, http_status: int,
                 written_version: Optional[int] = None):
        super().__init__(code)
        self.stage, self.code, self.detail, self.recovery = stage, code, detail, recovery
        self.http_status, self.written_version = http_status, written_version

    def body(self) -> dict:
        return {"stage": self.stage, "error_code": self.code, "detail": self.detail,
                "recovery": self.recovery, "written_version": self.written_version}


@dataclass
class ProvisioningResult:
    vault_ref: VaultRef
    path: str
    version: int


def allowed_secret_names() -> list[str]:
    return list(settings.ASSET_CREDENTIAL_SECRET_NAMES)


async def bound_assets(db: AsyncSession) -> dict[str, UUID]:
    """secret name -> asset currently holding the active binding."""
    prefix = f"{settings.OPENBAO_SECRET_PATH_PREFIX}/assets/"
    # A binding still held by a soft-deleted asset must not keep the reference "taken".
    rows = (await db.execute(
        select(VaultRef.vault_path, VaultRef.asset_id)
        .join(Asset, Asset.id == VaultRef.asset_id)
        .where(VaultRef.is_active == True, Asset.is_deleted == False)  # noqa: E712
    )).all()
    return {path[len(prefix):]: asset_id for path, asset_id in rows if path.startswith(prefix)}


async def provision(db: AsyncSession, *, asset_id: UUID, secret_name: str, username: str, secret: str,
                    secret_type: str = "PASSWORD") -> ProvisioningResult:
    """Write + verify + bind. Does NOT commit: the caller commits (with its audit row) or rolls back."""
    if secret_name not in allowed_secret_names():
        raise ProvisioningError("validate", "SECRET_NAME_NOT_ALLOWLISTED",
                                f"'{secret_name}' is not an approved credential reference.",
                                "Choose one of the approved references, or have an operator register a new one "
                                "(policy + ASSET_CREDENTIAL_SECRET_NAMES).", 422)
    field = SECRET_FIELD.get(secret_type)
    if field is None:
        raise ProvisioningError("validate", "UNSUPPORTED_SECRET_TYPE", "Unsupported secret type.",
                                "Use PASSWORD or SSH_KEY.", 422)
    holder = (await bound_assets(db)).get(secret_name)
    if holder is not None and holder != asset_id:
        raise ProvisioningError("validate", "SECRET_ALREADY_BOUND",
                                "This credential reference already belongs to another asset.",
                                "Unbind it there first, or choose a different approved reference.", 409)
    try:
        writer = get_credential_writer()
    except CredentialWriterNotConfigured as exc:
        raise ProvisioningError("configure", "PROVISIONING_NOT_CONFIGURED", str(exc),
                                "Deploy AWS OpenBao, set SECRET_PROVIDER=openbao, OPENBAO_TOKEN (reader) and "
                                "OPENBAO_WRITER_TOKEN (writer), or store the credential in the OpenBao UI.", 503) from None

    path = asset_secret_path(settings.OPENBAO_SECRET_PATH_PREFIX, secret_name)
    try:
        version = await writer.write(path, {"username": username, field: secret})
    except SecretAccessDeniedError:
        raise ProvisioningError("write", "WRITE_DENIED", "OpenBao refused the write.",
                                "The writer token is expired/revoked or its policy lacks this path: rotate it "
                                "(provision.sh --rotate writer) and check securepam-writer.hcl.", 502) from None
    except SecretProviderUnavailableError as exc:
        raise ProvisioningError("write", "OPENBAO_UNAVAILABLE", str(exc),
                                "Nothing was stored. Check OpenBao health/TLS and retry.", 503) from None
    except SecretProviderError as exc:
        raise ProvisioningError("write", "WRITE_FAILED", str(exc), "Nothing was stored. Retry.", 502) from None

    try:
        record = await get_secret_provider().read_secret(path, version=version)
        stored_secret = record.data.get(field)
        stored_user = record.data.get("username")
        ok = (isinstance(stored_secret, str) and hmac.compare_digest(stored_secret.encode(), secret.encode())
              and stored_user == username)
        del record, stored_secret
    except (SecretAccessDeniedError, SecretNotFoundError, SecretProviderError):
        ok = False
    if not ok:
        raise ProvisioningError("verify", "VERIFY_FAILED",
                                "The credential was written but could not be verified with the reader identity.",
                                f"Version {version} exists in OpenBao but is NOT bound. Check that the reader policy "
                                "covers this path and retry (a retry writes a newer version).", 502, written_version=version)

    await db.execute(update(VaultRef).where(VaultRef.asset_id == asset_id, VaultRef.is_active == True)  # noqa: E712
                     .values(is_active=False))
    ref = VaultRef(asset_id=asset_id, provider=settings.SECRET_PROVIDER, vault_path=path, secret_type=secret_type,
                   username=username, secret_version=None, is_active=True)
    db.add(ref)
    await db.flush()
    return ProvisioningResult(vault_ref=ref, path=path, version=version)
