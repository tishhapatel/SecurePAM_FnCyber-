"""
Secret reference path rules — the single definition every layer (admin API,
CredentialService, and each provider as defence in depth) validates against.

A reference path is relative to the KV mount (no "secret/", no "data/"),
always starts with the configured server-side prefix, and consists only of
conservative segments — so a stored or supplied value can never traverse
("..") or escape into another part of the secret store.
"""

import re

from app.secret_providers.base import InvalidSecretReferenceError

MAX_PATH_LENGTH = 512
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def validate_secret_path(path: str, prefix: str) -> str:
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_LENGTH:
        raise InvalidSecretReferenceError("Secret reference path is empty or too long")

    segments = path.split("/")
    if any(not _SEGMENT_RE.match(s) or ".." in s for s in segments):
        raise InvalidSecretReferenceError("Secret reference path contains an invalid segment")

    prefix_segments = prefix.split("/")
    if segments[: len(prefix_segments)] != prefix_segments or len(segments) <= len(prefix_segments):
        raise InvalidSecretReferenceError("Secret reference path is outside the allowed prefix")

    return path


def validate_secret_name(name: str) -> str:
    """One path segment, as an administrator supplies it when registering a
    reference (e.g. "test-linux-01") — never a full path."""
    if not isinstance(name, str) or not _SEGMENT_RE.match(name) or ".." in name:
        raise InvalidSecretReferenceError("Secret name must be a single safe path segment")
    return name


def asset_secret_path(prefix: str, secret_name: str) -> str:
    """Server-controlled convention: <prefix>/assets/<secret_name>."""
    return validate_secret_path(f"{prefix}/assets/{validate_secret_name(secret_name)}", prefix)


def application_secret_path(prefix: str, secret_name: str) -> str:
    """Server-controlled convention: <prefix>/applications/<secret_name>."""
    return validate_secret_path(f"{prefix}/applications/{validate_secret_name(secret_name)}", prefix)
