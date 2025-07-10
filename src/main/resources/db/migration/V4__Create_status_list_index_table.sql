CREATE TABLE IF NOT EXISTS issuer.status_list_index (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nonce VARCHAR(255) NOT NULL UNIQUE,
    list_id INTEGER NOT NULL
    );