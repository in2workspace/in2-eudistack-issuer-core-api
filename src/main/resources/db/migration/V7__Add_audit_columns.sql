ALTER TABLE issuer.credential_procedure
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS created_by VARCHAR(320),
  ADD COLUMN IF NOT EXISTS updated_by VARCHAR(320);

-- 2) Since update_at column already existed, we need to  modify it
-- Convert updated_at from TIMESTAMP to TIMESTAMPTZ assuming previous values are UTC
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'issuer'
      AND table_name   = 'credential_procedure'
      AND column_name  = 'updated_at'
      AND data_type    = 'timestamp without time zone'
  ) THEN
    EXECUTE $conv$
      ALTER TABLE issuer.credential_procedure
      ALTER COLUMN updated_at TYPE TIMESTAMPTZ
      USING updated_at AT TIME ZONE 'UTC'
    $conv$;
  END IF;
END$$;

COMMIT;
