use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Representa um Papel (Role) no sistema RBAC.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Role {
    pub id: String, // UUID v7 como String
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Role {
    /// Cria uma nova instância de Role.
    pub fn new(name: String, description: Option<String>) -> Self {
        let now = Utc::now();
        Role {
            id: Uuid::now_v7().to_string(), // Gera UUID v7
            name,
            description,
            created_at: now,
            updated_at: now,
        }
    }
}

/// DTO para criar um novo Papel.
#[derive(Debug, Deserialize, Validate)]
pub struct CreateRoleDto {
    #[validate(length(min = 3, message = "Nome do papel deve ter pelo menos 3 caracteres."))]
    pub name: String,
    pub description: Option<String>,
}

/// DTO para atualizar um Papel existente.
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateRoleDto {
    #[validate(length(min = 3, message = "Nome do papel deve ter pelo menos 3 caracteres."))]
    pub name: Option<String>,
    // A descrição pode ser atualizada para um novo valor ou não (se `None`).
    // Para remover a descrição, envie `Some(None)` ou um campo nulo no JSON.
    // O serviço tratará `None` como "não alterar".
    pub description: Option<Option<String>>,
}

/// Representa os dados para associar/desassociar permissões a um papel.
#[derive(Debug, Deserialize)]
pub struct RolePermissionDto {
     pub permission_ids: Vec<String>,
}

/// Representa os dados para associar/desassociar papéis a um usuário.
#[derive(Debug, Deserialize)]
pub struct UserRoleDto {
     pub role_ids: Vec<String>,
} 