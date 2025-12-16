ALTER TABLE identity_issuer.credential_procedure
ADD COLUMN operation_mode VARCHAR(20),
ADD COLUMN signature_mode VARCHAR(20);