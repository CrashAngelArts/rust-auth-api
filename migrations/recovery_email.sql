-- Adicionar coluna para email de recuperação
ALTER TABLE users ADD COLUMN recovery_email TEXT DEFAULT NULL;

-- Adicionar índice para melhorar a performance de consultas
CREATE INDEX idx_users_recovery_email ON users(recovery_email);

-- Comentário explicativo
PRAGMA table_info(users);
