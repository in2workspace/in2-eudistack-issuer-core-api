-- Vxxx__create_status_list_tables.sql
-- PostgreSQL

-- 1) Main table: status_list
CREATE TABLE IF NOT EXISTS status_list (
    id               BIGSERIAL PRIMARY KEY,
    issuer_id        TEXT        NOT NULL,
    purpose          TEXT        NOT NULL,
    encoded_list     TEXT        NOT NULL,
    signed_credential TEXT       NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Useful index for: findLatestByIssuerAndPurpose (ORDER BY id DESC LIMIT 1)
CREATE INDEX IF NOT EXISTS idx_status_list_issuer_purpose_id_desc
    ON status_list (issuer_id, purpose, id DESC);


-- 2) Mapping table: status_list_index
CREATE TABLE IF NOT EXISTS status_list_index (
    id            BIGSERIAL PRIMARY KEY,
    status_list_id BIGINT      NOT NULL,
    idx           INTEGER     NOT NULL,
    procedure_id  TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_status_list_index_status_list
        FOREIGN KEY (status_list_id)
        REFERENCES status_list(id)
        ON DELETE RESTRICT
);

-- Enforce "one allocation per procedure"
ALTER TABLE status_list_index
    ADD CONSTRAINT uq_status_list_index_procedure_id
    UNIQUE (procedure_id);

-- Enforce "one row per bit index in a given list"
ALTER TABLE status_list_index
    ADD CONSTRAINT uq_status_list_index_list_id_idx
    UNIQUE (status_list_id, idx);

-- Keep idx within allowed range
ALTER TABLE status_list_index
    ADD CONSTRAINT chk_status_list_index_idx_range
    CHECK (idx >= 0 AND idx < 131072);

-- Indexes for typical access patterns:
-- - lookup by procedureId (allocate / revoke)
CREATE INDEX IF NOT EXISTS idx_status_list_index_procedure_id
    ON status_list_index (procedure_id);

-- - countByStatusListId + joins
CREATE INDEX IF NOT EXISTS idx_status_list_index_status_list_id
    ON status_list_index (status_list_id);

