-- Tabela para armazenar as perguntas de segurança do sistema
CREATE TABLE IF NOT EXISTS security_questions (
    id TEXT PRIMARY KEY,
    text TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Índice para consulta rápida de perguntas ativas
CREATE INDEX IF NOT EXISTS idx_security_questions_active ON security_questions(active);

-- Tabela para armazenar as respostas dos usuários
CREATE TABLE IF NOT EXISTS user_security_answers (
    user_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    answer_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, question_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES security_questions(id) ON DELETE CASCADE
);

-- Índice para consulta rápida das respostas de um usuário
CREATE INDEX IF NOT EXISTS idx_user_security_answers_user_id ON user_security_answers(user_id);

-- Adicionando colunas para recovery_code na tabela users
ALTER TABLE users ADD COLUMN recovery_code TEXT;
ALTER TABLE users ADD COLUMN recovery_code_expires_at TIMESTAMP;

-- Inserir algumas perguntas padrão (descomente e ajuste conforme necessário)
INSERT INTO security_questions (id, text, active, created_at, updated_at) 
VALUES 
('d290f1ee-6c54-4b01-90e6-d701748f0851', 'Qual é o nome do seu primeiro animal de estimação? 🐶', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('d290f1ee-6c54-4b01-90e6-d701748f0852', 'Qual é a sua cor favorita? 🎨', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('d290f1ee-6c54-4b01-90e6-d701748f0853', 'Em que cidade seus pais se conheceram? 🏙️', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('d290f1ee-6c54-4b01-90e6-d701748f0854', 'Qual era o nome do seu primeiro professor? 👨‍🏫', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('d290f1ee-6c54-4b01-90e6-d701748f0855', 'Qual é o nome da rua em que você cresceu? 🛣️', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP); 