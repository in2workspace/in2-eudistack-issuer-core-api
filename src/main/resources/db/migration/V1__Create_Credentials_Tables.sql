CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
CREATE SCHEMA IF NOT EXISTS identity_issuer;

-- Create credential_management table if it doesn't exist
CREATE TABLE IF NOT EXISTS identity_issuer.credential_procedure (
    procedure_id uuid PRIMARY KEY UNIQUE DEFAULT public.uuid_generate_v4(),
    credential_id uuid,
    credential_format VARCHAR(20),
    credential_decoded TEXT,
    credential_encoded TEXT,
    credential_status VARCHAR(20),
    organization_identifier VARCHAR(255),
    updated_at TIMESTAMP,
    subject VARCHAR(255),
    valid_until TIMESTAMP,
    credential_type VARCHAR(50)
);

-- Create credential_deferred table if it doesn't exist
CREATE TABLE IF NOT EXISTS identity_issuer.deferred_credential_metadata (
    id uuid PRIMARY KEY UNIQUE DEFAULT public.uuid_generate_v4(),
    transaction_code VARCHAR(255),
    transaction_id VARCHAR(255),
    auth_server_nonce VARCHAR(255),
    procedure_id uuid,
    vc TEXT,
    vc_format VARCHAR(20),
    operation_mode VARCHAR(20),
    response_uri VARCHAR(255),
    CONSTRAINT fk_credential_procedure
        FOREIGN KEY (procedure_id)
        REFERENCES identity_issuer.credential_procedure (procedure_id)
        ON DELETE CASCADE
);
