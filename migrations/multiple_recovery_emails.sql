-- Migração para suportar múltiplos emails de recuperação
-- Versão: 4
-- Descrição: Cria uma tabela para armazenar múltiplos emails de recuperação por usuário

-- Criar tabela de emails de recuperação
CREATE TABLE IF NOT EXISTS recovery_emails (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    email TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT 0,
    verification_token TEXT,
    verification_token_expires_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Criar índices para melhorar a performance
CREATE INDEX IF NOT EXISTS idx_recovery_emails_user_id ON recovery_emails(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_emails_email ON recovery_emails(email);

-- Migrar dados existentes da coluna recovery_email para a nova tabela
INSERT INTO recovery_emails (
    id, 
    user_id, 
    email, 
    is_verified, 
    created_at, 
    updated_at
)
SELECT 
    hex(randomblob(16)), -- Gerar ID único
    id, 
    recovery_email, 
    0, -- Não verificado inicialmente
    datetime('now'), 
    datetime('now')
FROM users 
WHERE recovery_email IS NOT NULL AND recovery_email != '';

-- Atualizar versão da migração
PRAGMA user_version = 4;
