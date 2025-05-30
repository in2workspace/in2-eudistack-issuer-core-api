CREATE TABLE IF NOT EXISTS issuer.cloud_provider (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider VARCHAR(255) NOT NULL UNIQUE,
    url TEXT NOT NULL,
    auth_method VARCHAR(100) NOT NULL,
    auth_grant_type VARCHAR(100) NOT NULL,
    requires_totp BOOLEAN NOT NULL DEFAULT FALSE
    );

CREATE TABLE IF NOT EXISTS issuer.signature_configuration (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_identifier VARCHAR(255) NOT NULL,
    enable_remote_signature BOOLEAN NOT NULL DEFAULT FALSE,
    signature_mode VARCHAR(50) NOT NULL CHECK (signature_mode IN ('LOCAL', 'SERVER', 'CLOUD')),
    cloud_provider_id UUID NULL,
    client_id VARCHAR(255) NULL,
    secret_relative_path TEXT NULL,
    credential_id VARCHAR(255) NULL,
    credential_name VARCHAR(255) NULL,
    vault_hashed_secret_values TEXT NULL,
    FOREIGN KEY (cloud_provider_id) REFERENCES issuer.cloud_provider (id) ON DELETE SET NULL
    );

CREATE TABLE IF NOT EXISTS issuer.signature_configuration_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    signature_configuration_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(320) NOT NULL,
    organization_identifier VARCHAR(255) NOT NULL,
    instant TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    old_values TEXT NOT NULL,
    new_values TEXT NULL,
    rationale TEXT NULL,
    encrypted BOOLEAN NOT NULL DEFAULT TRUE
    );

CREATE TABLE IF NOT EXISTS issuer.configuration (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_identifier VARCHAR(255) NOT NULL,
    config_key VARCHAR(255) NOT NULL,
    config_value VARCHAR(255) NOT NULL,
    CONSTRAINT unique_org_key UNIQUE (organization_identifier, config_key)
);