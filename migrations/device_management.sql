-- Migração para adicionar suporte ao gerenciamento de dispositivos
-- Adiciona novos campos à tabela de sessões e cria índices

-- Adicionar novos campos à tabela de sessões
ALTER TABLE sessions ADD COLUMN device_name TEXT;
ALTER TABLE sessions ADD COLUMN device_type TEXT;
ALTER TABLE sessions ADD COLUMN last_active_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE sessions ADD COLUMN location TEXT;
ALTER TABLE sessions ADD COLUMN is_current BOOLEAN NOT NULL DEFAULT 0;

-- Adicionar índices para melhorar a performance
CREATE INDEX idx_sessions_device_name ON sessions(device_name);
CREATE INDEX idx_sessions_last_active_at ON sessions(last_active_at);
CREATE INDEX idx_sessions_is_current ON sessions(is_current);
