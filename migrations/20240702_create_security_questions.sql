-- Tabela para armazenar perguntas de segurança pré-definidas
CREATE TABLE security_questions (
    id TEXT PRIMARY KEY NOT NULL,
    text TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Tabela para armazenar as respostas dos usuários às perguntas de segurança
CREATE TABLE user_security_answers (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    question_id TEXT NOT NULL,
    answer_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES security_questions(id) ON DELETE CASCADE
);

-- Índices para melhorar a performance
CREATE INDEX idx_user_security_answers_user_id ON user_security_answers(user_id);
CREATE INDEX idx_security_questions_active ON security_questions(active);

-- Adicionar perguntas padrão para o sistema
INSERT INTO security_questions (id, text, active, created_at, updated_at)
VALUES 
    (lower(hex(randomblob(16))), 'Qual é o nome do seu primeiro animal de estimação? 🐶', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    (lower(hex(randomblob(16))), 'Qual é o nome da rua onde você cresceu? 🏠', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    (lower(hex(randomblob(16))), 'Qual foi o nome da sua primeira escola? 🏫', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    (lower(hex(randomblob(16))), 'Qual é o nome de solteiro da sua mãe? 👩', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    (lower(hex(randomblob(16))), 'Qual é a sua comida favorita da infância? 🍕', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    (lower(hex(randomblob(16))), 'Em qual cidade você nasceu? 🏙️', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    (lower(hex(randomblob(16))), 'Qual foi o modelo do seu primeiro carro? 🚗', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
    (lower(hex(randomblob(16))), 'Qual é o nome da sua primeira professora? 👩‍🏫', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP); 