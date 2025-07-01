CREATE TABLE IF NOT EXISTS issuer.status_list_index (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    nonce UUID NOT NULL uuid_generate_v4(),
    list_id INTEGER NOT NULL
    );