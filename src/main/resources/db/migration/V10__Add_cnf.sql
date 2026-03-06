DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'issuer'
          AND table_name   = 'credential_procedure'
          AND column_name  = 'cnf'
    ) THEN
        ALTER TABLE issuer.credential_procedure
            ADD COLUMN cnf TEXT NULL;
    END IF;
END $$;