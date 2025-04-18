-- Criação da tabela de códigos de recuperação conforme especificado
CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  code TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP,
  used INTEGER DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Criação de índices para melhorar o desempenho
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user_id ON recovery_codes (user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_code ON recovery_codes (code);

-- Comentário: Esta implementação permite que um usuário tenha vários códigos de recuperação
-- (embora na prática provavelmente apenas um será ativo por vez)
-- A coluna 'used' pode ser 0 (não usado) ou 1 (usado), permitindo manter histórico para auditoria 