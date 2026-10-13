-- PostgreSQL migration for the versioned SecurePAM policy store (matches securepam_policy_engine/db.py).
-- Rows are append-only per version; only is_current is flipped when a new version is published.
-- Named policy_engine_policies: the backend's Alembic schema already owns a "policies" table,
-- and CREATE TABLE IF NOT EXISTS against that name would silently keep the wrong schema.
CREATE TABLE IF NOT EXISTS policy_engine_policies (
    id            BIGSERIAL PRIMARY KEY,
    policy_id     VARCHAR(64)  NOT NULL,
    version       INTEGER      NOT NULL CHECK (version >= 1),
    name          VARCHAR(200) NOT NULL,
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE,
    is_current    BOOLEAN      NOT NULL DEFAULT TRUE,
    definition    JSONB        NOT NULL,
    changed_by    VARCHAR(128) NOT NULL,
    change_note   VARCHAR(500) NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_policy_engine_policy_version UNIQUE (policy_id, version)
);
CREATE INDEX IF NOT EXISTS ix_policy_engine_policies_policy_id  ON policy_engine_policies (policy_id);
CREATE INDEX IF NOT EXISTS ix_policy_engine_policies_is_current ON policy_engine_policies (is_current);
-- Exactly one current version per policy_id:
CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_engine_policies_one_current ON policy_engine_policies (policy_id) WHERE is_current;
