-- Migrations/V5__create_rbac_tables.sql

-- Tabela para armazenar permissões granulares
CREATE TABLE permissions (
    id TEXT PRIMARY KEY NOT NULL,           -- UUID da permissão
    name TEXT UNIQUE NOT NULL,              -- Nome único da permissão (ex: users:read)
    description TEXT,                       -- Descrição opcional da permissão
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')), -- Timestamp de criação
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))  -- Timestamp da última atualização
);

-- Tabela para armazenar papéis (roles)
CREATE TABLE roles (
    id TEXT PRIMARY KEY NOT NULL,           -- UUID do papel
    name TEXT UNIQUE NOT NULL,              -- Nome único do papel (ex: admin, editor)
    description TEXT,                       -- Descrição opcional do papel
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now')), -- Timestamp de criação
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%f', 'now'))  -- Timestamp da última atualização
);

-- Tabela de junção para relação muitos-para-muitos entre Roles e Permissions
CREATE TABLE role_permissions (
    role_id TEXT NOT NULL,                  -- ID do papel (FK para roles)
    permission_id TEXT NOT NULL,            -- ID da permissão (FK para permissions)
    PRIMARY KEY (role_id, permission_id),   -- Chave primária composta
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE, -- Se um papel for deletado, remove as associações
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE -- Se uma permissão for deletada, remove as associações
);

-- Tabela de junção para relação muitos-para-muitos entre Users e Roles
CREATE TABLE user_roles (
    user_id TEXT NOT NULL,                  -- ID do usuário (FK para users)
    role_id TEXT NOT NULL,                  -- ID do papel (FK para roles)
    PRIMARY KEY (user_id, role_id),         -- Chave primária composta
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, -- Se um usuário for deletado, remove as associações
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE  -- Se um papel for deletado, remove as associações
);

-- Índices opcionais para melhorar performance em joins (especialmente se houver muitos papéis/permissões)
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- Trigger para atualizar 'updated_at' automaticamente (exemplo para 'permissions')
CREATE TRIGGER update_permissions_updated_at
AFTER UPDATE ON permissions
FOR EACH ROW
BEGIN
    UPDATE permissions SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = OLD.id;
END;

-- Trigger para atualizar 'updated_at' automaticamente (exemplo para 'roles')
CREATE TRIGGER update_roles_updated_at
AFTER UPDATE ON roles
FOR EACH ROW
BEGIN
    UPDATE roles SET updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now') WHERE id = OLD.id;
END; 