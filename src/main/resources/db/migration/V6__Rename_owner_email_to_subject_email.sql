-- Rename column owner_email to subject_email in credential_procedure table
ALTER TABLE issuer.credential_procedure
RENAME COLUMN owner_email TO subject_email;