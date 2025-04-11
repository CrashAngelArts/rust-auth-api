-- Adicionar colunas para autenticação de dois fatores (2FA)
ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN backup_codes TEXT DEFAULT NULL;

-- Adicionar tabela para rotação de tokens JWT
CREATE TABLE token_blacklist (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    expiry DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Adicionar índice para melhorar a performance de consultas de tokens
CREATE INDEX idx_token_blacklist_token_id ON token_blacklist(token_id);
CREATE INDEX idx_token_blacklist_expiry ON token_blacklist(expiry);

-- Adicionar coluna para armazenar a família de tokens do usuário
ALTER TABLE users ADD COLUMN token_family TEXT DEFAULT NULL;
