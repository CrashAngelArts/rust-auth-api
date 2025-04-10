use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: bool,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Campos adicionados para bloqueio de conta
    #[serde(default)] // Garante que o padrão seja 0 se não presente na desserialização
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing)] // Não expor o token na serialização padrão
    pub unlock_token: Option<String>,
    #[serde(skip_serializing)] // Não expor a expiração do token
    pub unlock_token_expires_at: Option<DateTime<Utc>>,
}

impl User {
    pub fn new(
        email: String,
        username: String,
        password_hash: String,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            email,
            username,
            password_hash,
            first_name,
            last_name,
            is_active: true, // Contas novas devem estar ativas
            is_admin: false,
            created_at: now,
            updated_at: now,
            failed_login_attempts: 0, // Inicializa tentativas falhadas como 0
            locked_until: None,       // Inicializa como não bloqueado
            unlock_token: None,       // Inicializa sem token
            unlock_token_expires_at: None, // Inicializa sem expiração de token
        }
    }

    pub fn full_name(&self) -> String {
        match (&self.first_name, &self.last_name) {
            (Some(first), Some(last)) => format!("{} {}", first, last),
            (Some(first), None) => first.clone(),
            (None, Some(last)) => last.clone(),
            (None, None) => self.username.clone(),
        }
    }

    // Helper para verificar se a conta está atualmente bloqueada
    pub fn is_locked(&self) -> bool {
        match self.locked_until {
            Some(lock_time) => lock_time > Utc::now(),
            None => false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct CreateUserDto {
    #[validate(email(message = "Email inválido"))]
    pub email: String,

    #[validate(length(min = 3, max = 30, message = "Nome de usuário deve ter entre 3 e 30 caracteres"))]
    pub username: String,

    #[validate(length(min = 8, message = "Senha deve ter pelo menos 8 caracteres"))]
    pub password: String,

    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UpdateUserDto {
    #[validate(email(message = "Email inválido"))]
    pub email: Option<String>,

    #[validate(length(min = 3, max = 30, message = "Nome de usuário deve ter entre 3 e 30 caracteres"))]
    pub username: Option<String>,

    pub first_name: Option<String>,
    pub last_name: Option<String>,

    pub is_active: Option<bool>,
    // Não permitir atualização direta dos campos de bloqueio via DTO
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ChangePasswordDto {
    #[validate(length(min = 8, message = "Senha atual deve ter pelo menos 8 caracteres"))]
    pub current_password: String,

    #[validate(length(min = 8, message = "Nova senha deve ter pelo menos 8 caracteres"))]
    pub new_password: String,

    #[validate(must_match(other = "new_password", message = "As senhas não coincidem"))]
    pub confirm_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub username: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub is_active: bool,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    // Não incluir campos de bloqueio na resposta padrão
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            is_active: user.is_active,
            is_admin: user.is_admin,
            created_at: user.created_at,
        }
    }
}
