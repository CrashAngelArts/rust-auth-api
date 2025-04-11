-- Adicionar tabela para armazenar os dados de ritmo de digitação
CREATE TABLE keystroke_dynamics (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    typing_pattern TEXT NOT NULL, -- Padrão de digitação serializado como JSON
    similarity_threshold INTEGER NOT NULL DEFAULT 80, -- Limiar de similaridade em porcentagem (padrão: 80%)
    enabled BOOLEAN NOT NULL DEFAULT 1, -- Habilitado por padrão
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Adicionar índice para melhorar a performance de consultas
CREATE INDEX idx_keystroke_dynamics_user_id ON keystroke_dynamics(user_id);

-- Adicionar comentário explicativo na tabela
PRAGMA table_info(keystroke_dynamics);
