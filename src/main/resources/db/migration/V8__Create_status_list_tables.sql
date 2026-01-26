CREATE TABLE IF NOT EXISTS issuer.status_list (
    id                BIGSERIAL PRIMARY KEY,
    issuer_id         TEXT        NOT NULL,
    purpose           TEXT        NOT NULL,
    encoded_list      TEXT        NOT NULL,
    signed_credential TEXT        NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_status_list_issuer_purpose_id_desc
    ON issuer.status_list (issuer_id, purpose, id DESC);

CREATE TABLE IF NOT EXISTS issuer.status_list_index_new (
    id             BIGSERIAL PRIMARY KEY,
    status_list_id BIGINT      NOT NULL,
    idx            INTEGER     NOT NULL,
    procedure_id   TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_status_list_index_status_list
        FOREIGN KEY (status_list_id)
        REFERENCES issuer.status_list(id)
        ON DELETE RESTRICT
);

ALTER TABLE issuer.status_list_index_new
    ADD CONSTRAINT uq_status_list_index_new_procedure_id
    UNIQUE (procedure_id);

ALTER TABLE issuer.status_list_index_new
    ADD CONSTRAINT uq_status_list_index_new_list_id_idx
    UNIQUE (status_list_id, idx);

ALTER TABLE issuer.status_list_index_new
    ADD CONSTRAINT chk_status_list_index_new_idx_range
    CHECK (idx >= 0 AND idx < 131072);

CREATE INDEX IF NOT EXISTS idx_status_list_index_new_procedure_id
    ON issuer.status_list_index_new (procedure_id);

CREATE INDEX IF NOT EXISTS idx_status_list_index_new_status_list_id
    ON issuer.status_list_index_new (status_list_id);