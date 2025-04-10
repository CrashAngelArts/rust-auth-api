-- Migração Inicial: Cria todas as tabelas e índices necessários

-- Tabela de usuários
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name TEXT,
    last_name TEXT,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    is_admin BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Campos para bloqueio de conta
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    unlock_token TEXT UNIQUE,
    unlock_token_expires_at TIMESTAMP
);

-- Tabela de refresh tokens
CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY,          -- ID único do token
    user_id TEXT NOT NULL,        -- ID do usuário associado
    token_hash TEXT NOT NULL UNIQUE, -- O hash SHA-256 do refresh token
    expires_at TIMESTAMP NOT NULL,  -- Data de expiração do token
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN NOT NULL DEFAULT 0, -- Flag para indicar se o token foi revogado
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Tabela de tokens de recuperação de senha
CREATE TABLE password_reset_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Tabela de sessões
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Tabela de logs de autenticação
CREATE TABLE auth_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
);

-- Índices para otimização
CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_username ON users (username);
CREATE INDEX idx_users_unlock_token ON users (unlock_token);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens (user_id);
CREATE INDEX idx_password_reset_tokens_token ON password_reset_tokens (token);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens (expires_at);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
CREATE INDEX idx_sessions_token ON sessions (token);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE INDEX idx_auth_logs_user_id ON auth_logs (user_id);
CREATE INDEX idx_auth_logs_event_type ON auth_logs (event_type);
CREATE INDEX idx_auth_logs_created_at ON auth_logs (created_at);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);