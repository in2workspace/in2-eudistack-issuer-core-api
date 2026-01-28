CREATE TABLE IF NOT EXISTS issuer.status_list (
   id                BIGSERIAL PRIMARY KEY,
   purpose           TEXT        NOT NULL,
   encoded_list      TEXT        NOT NULL,
   signed_credential TEXT        NULL,
   created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
   updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_status_list_desc
   ON issuer.status_list (purpose, id DESC);

-- Rename old index table to legacy if needed
DO $$
BEGIN
 IF to_regclass('issuer.status_list_index') IS NOT NULL
    AND to_regclass('issuer.legacy_status_list_index') IS NULL THEN
   ALTER TABLE issuer.status_list_index RENAME TO legacy_status_list_index;
 END IF;
END $$;

CREATE TABLE IF NOT EXISTS issuer.status_list_index (
   id             BIGSERIAL PRIMARY KEY,
   status_list_id BIGINT      NOT NULL,
   idx            INTEGER     NOT NULL,
   procedure_id   UUID        NOT NULL,
   created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

   CONSTRAINT fk_status_list_index_status_list
       FOREIGN KEY (status_list_id)
       REFERENCES issuer.status_list(id)
       ON DELETE RESTRICT
);

DO $$
BEGIN
    ALTER TABLE issuer.status_list_index
       ADD CONSTRAINT uq_status_list_index_procedure_id
       UNIQUE (procedure_id);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    ALTER TABLE issuer.status_list_index
       ADD CONSTRAINT uq_status_list_index_list_id_idx
       UNIQUE (status_list_id, idx);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_status_list_index_status_list_id
   ON issuer.status_list_index (status_list_id);


