-- Tabela para armazenar códigos de verificação por email
CREATE TABLE IF NOT EXISTS email_verification_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    code TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT 0,
    verified_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Índice para buscar códigos por usuário
CREATE INDEX IF NOT EXISTS idx_email_verification_user_id ON email_verification_codes(user_id);

-- Índice para limpar códigos expirados
CREATE INDEX IF NOT EXISTS idx_email_verification_expires_at ON email_verification_codes(expires_at);
