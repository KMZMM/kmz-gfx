-- Main keys table
CREATE TABLE IF NOT EXISTS keys (
    id SERIAL PRIMARY KEY,
    key_string VARCHAR(255) UNIQUE NOT NULL,
    duration_hours INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active',
    used BOOLEAN DEFAULT false,
    owner_device_id TEXT,
    ip_address TEXT,
    last_verified TIMESTAMP
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS key_logs (
    id SERIAL PRIMARY KEY,
    key_id INTEGER REFERENCES keys(id),
    action VARCHAR(50) NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_keys_key_string ON keys(key_string);
CREATE INDEX IF NOT EXISTS idx_keys_owner_device ON keys(owner_device_id);
CREATE INDEX IF NOT EXISTS idx_keys_expires_at ON keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_logs_key_id ON key_logs(key_id);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON key_logs(created_at);