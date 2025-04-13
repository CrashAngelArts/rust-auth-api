use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use super::permission::Permission; // Importa o modelo Permission

/// Representa um papel (role) no sistema, que agrupa permissões.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    pub id: String,         // ID único (UUID)
    pub name: String,       // Nome único do papel (ex: "admin", "editor")
    pub description: Option<String>, // Descrição opcional

    #[serde(skip_serializing_if = "Vec::is_empty", default)] // Não serializa se vazio, usa default
    pub permissions: Vec<Permission>, // Lista de permissões associadas (preenchida sob demanda)

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Role {
    /// Cria uma nova instância de Role (sem permissões inicialmente).
    pub fn new(name: String, description: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            permissions: Vec::new(), // Começa sem permissões carregadas
            created_at: now,
            updated_at: now,
        }
    }
}

/// Representa os dados para criar um novo Papel (DTO).
#[derive(Debug, Deserialize)]
pub struct CreateRoleDto {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)] // Permite que o campo esteja ausente no JSON/Form
    pub permission_ids: Vec<String>, // IDs das permissões a serem associadas
}

/// Representa os dados para atualizar um Papel (DTO).
#[derive(Debug, Deserialize)]
pub struct UpdateRoleDto {
    pub name: Option<String>,
    pub description: Option<String>,
    // Para atualizar permissões, geralmente se usa endpoints dedicados
    // (ex: POST /roles/{id}/permissions, DELETE /roles/{id}/permissions/{perm_id})
    // ou uma substituição completa:
    pub permission_ids: Option<Vec<String>>, // Se presente, substitui todas as permissões
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