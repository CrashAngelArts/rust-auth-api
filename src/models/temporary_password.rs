use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Representa uma senha temporária no banco de dados 💾
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TemporaryPassword {
    pub id: String, // UUID
    pub user_id: String,
    pub password_hash: String,
    pub usage_limit: i32,
    pub usage_count: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl TemporaryPassword {
    /// Cria uma nova instância de senha temporária 🆕
    pub fn new(user_id: String, password_hash: String, usage_limit: i32) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            password_hash,
            usage_limit,
            usage_count: 0,
            is_active: true,
            created_at: Utc::now(),
            last_used_at: None,
        }
    }
}

/// DTO para criar uma nova senha temporária 📝
#[derive(Debug, Deserialize, Validate)]
pub struct CreateTemporaryPasswordDto {
    #[validate(length(min = 8, message = "A senha temporária deve ter pelo menos 8 caracteres 📏"), required)]
    pub password: Option<String>, // A senha em texto plano
    #[validate(range(min = 1, max = 10, message = "O limite de uso deve ser entre 1 e 10 🔢"))]
    pub usage_limit: i32,
}

/// DTO para a resposta de informações da senha temporária (exemplo) ✅
#[derive(Debug, Serialize)]
pub struct TemporaryPasswordResponse {
    pub id: String,
    pub usage_limit: i32,
    pub usage_count: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub remaining_uses: i32, // Campo calculado para conveniência
}

impl From<&TemporaryPassword> for TemporaryPasswordResponse {
    fn from(tp: &TemporaryPassword) -> Self {
        Self {
            id: tp.id.clone(),
            usage_limit: tp.usage_limit,
            usage_count: tp.usage_count,
            is_active: tp.is_active,
            created_at: tp.created_at,
            remaining_uses: std::cmp::max(0, tp.usage_limit - tp.usage_count), // Garante que não seja negativo
        }
    }
} 