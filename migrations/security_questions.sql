-- Migração para perguntas de segurança
-- Versão: 6

-- Criar tabela para perguntas de segurança
CREATE TABLE IF NOT EXISTS security_questions (
    id TEXT PRIMARY KEY,
    text TEXT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Criar tabela para respostas dos usuários
CREATE TABLE IF NOT EXISTS user_security_answers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    answer_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES security_questions (id) ON DELETE RESTRICT
);

-- Criar índices para otimizar consultas
CREATE INDEX IF NOT EXISTS idx_security_questions_active ON security_questions (is_active);
CREATE INDEX IF NOT EXISTS idx_user_security_answers_user_id ON user_security_answers (user_id);
CREATE INDEX IF NOT EXISTS idx_user_security_answers_question_id ON user_security_answers (question_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_security_answers_user_question ON user_security_answers (user_id, question_id);

-- Inserir algumas perguntas padrão de segurança
INSERT INTO security_questions (id, text, is_active, created_at, updated_at)
VALUES 
    (lower(hex(randomblob(16))), 'Qual foi o nome do seu primeiro animal de estimação? 🐶', 1, datetime('now'), datetime('now')),
    (lower(hex(randomblob(16))), 'Qual era o nome da rua onde você cresceu? 🏠', 1, datetime('now'), datetime('now')),
    (lower(hex(randomblob(16))), 'Qual é o nome do seu filme favorito? 🎬', 1, datetime('now'), datetime('now')),
    (lower(hex(randomblob(16))), 'Qual era o modelo do seu primeiro carro? 🚗', 1, datetime('now'), datetime('now')),
    (lower(hex(randomblob(16))), 'Qual é a cidade natal da sua mãe? 🌆', 1, datetime('now'), datetime('now')),
    (lower(hex(randomblob(16))), 'Qual foi o nome da sua primeira escola? 🏫', 1, datetime('now'), datetime('now')),
    (lower(hex(randomblob(16))), 'Qual é o nome do seu melhor amigo de infância? 👫', 1, datetime('now'), datetime('now')),
    (lower(hex(randomblob(16))), 'Qual era o nome do seu professor favorito? 👨‍🏫', 1, datetime('now'), datetime('now'));

-- Atualizar versão do esquema
PRAGMA user_version = 6; 