-- Adiciona colunas para o código de recuperação único e sua expiração
ALTER TABLE users ADD COLUMN recovery_code TEXT;
ALTER TABLE users ADD COLUMN recovery_code_expires_at TIMESTAMP;

-- Cria um índice na coluna recovery_code para buscas eficientes
CREATE INDEX IF NOT EXISTS idx_users_recovery_code ON users (recovery_code);