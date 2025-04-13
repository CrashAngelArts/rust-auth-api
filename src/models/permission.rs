use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use validator::Validate;

/// Representa uma permissão granular no sistema.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)] // Adicionado Hash para uso em Sets/Maps
pub struct Permission {
    pub id: String,         // ID único (UUID)
    pub name: String,       // Nome único da permissão (ex: "users:read", "admin:access")
    pub description: Option<String>, // Descrição opcional
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Permission {
    /// Cria uma nova instância de Permissão.
    pub fn new(name: String, description: Option<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Representa os dados para criar uma nova Permissão (DTO).
#[derive(Debug, Deserialize, Validate)]
pub struct CreatePermissionDto {
    #[validate(length(min = 1, message = "Nome da permissão não pode ser vazio."))]
    pub name: String,
    pub description: Option<String>,
}

/// Representa os dados para atualizar uma Permissão (DTO).
#[derive(Debug, Deserialize, Validate)]
pub struct UpdatePermissionDto {
    #[validate(length(min = 1, message = "Nome da permissão não pode ser vazio."))]
    pub name: Option<String>,
    pub description: Option<String>,
} 