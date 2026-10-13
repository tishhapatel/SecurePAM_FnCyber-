"""sessions.request_id nullable for gateway — Member 11

Revision ID: a1b2c3d4e5f6
Revises: 4a0d91a07728
Create Date: 2026-10-09 22:45:00.000000

Context:
  The web gateway (Member 11) creates Session rows before a formal
  AccessRequest record exists.  sessions.request_id was
  originally nullable=False (FK to access_requests.id), which prevented
  gateway-initiated sessions from being stored.

  This migration relaxes the constraint to nullable=True.  The FK itself
  is kept — when the full access-request→JIT→session flow is wired by M2
  and M7, request_id will be populated.  Existing rows are unaffected
  (there are none in production yet; this is a dev/staging environment).

  Upgrade:   ALTER COLUMN request_id DROP NOT NULL
  Downgrade: ALTER COLUMN request_id SET NOT NULL (safe to reverse only if
             all sessions have a non-null request_id at that point)
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = '235fd5fdd69a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Make sessions.request_id nullable so gateway sessions can exist
    # without a prior access_request row.  See module docstring.
    op.alter_column(
        'sessions',
        'request_id',
        existing_type=sa.UUID(),
        nullable=True,
    )


def downgrade() -> None:
    # WARNING: This will fail if any session row has request_id = NULL.
    # Ensure all gateway-created sessions have been backfilled before
    # running this downgrade.
    op.alter_column(
        'sessions',
        'request_id',
        existing_type=sa.UUID(),
        nullable=False,
    )
