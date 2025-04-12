-- Adiciona tabela para armazenar conexões OAuth
CREATE TABLE IF NOT EXISTS oauth_connections (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    email TEXT,
    name TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (provider, provider_user_id)
);

-- Índices para melhorar a performance
CREATE INDEX IF NOT EXISTS idx_oauth_connections_user_id ON oauth_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_connections_provider_user_id ON oauth_connections(provider, provider_user_id);
