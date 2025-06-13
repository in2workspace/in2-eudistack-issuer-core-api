-- Enable required extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Ensure schema exists
CREATE SCHEMA IF NOT EXISTS issuer;

-- Create table if not exist
CREATE TABLE IF NOT EXISTS issuer.credential_issuance_record (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_identifier VARCHAR(255),
    subject VARCHAR(255),
    email VARCHAR(255),
    credential_format VARCHAR(20),
    credential_type VARCHAR(50),
    credential_status VARCHAR(20),
    credential_data TEXT,
    refresh_token VARCHAR(255),
    transaction_id VARCHAR(255),
    operation_mode VARCHAR(20),
    signature_mode VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);