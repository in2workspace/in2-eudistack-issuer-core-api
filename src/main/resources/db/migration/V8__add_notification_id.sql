ALTER TABLE issuer.credential_procedure
ADD COLUMN IF NOT EXISTS notification_id uuid;
