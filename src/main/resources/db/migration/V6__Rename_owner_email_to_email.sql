-- Rename column owner_email to subject_email in credential_procedure table
ALTER TABLE identity_issuer.credential_procedure
RENAME COLUMN owner_email TO email;