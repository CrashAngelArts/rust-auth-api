use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct LoginDto {
    #[validate(length(min = 1, message = "Nome de usuário ou email é obrigatório"))]
    pub username_or_email: String,

    #[validate(length(min = 1, message = "Senha é obrigatória"))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RegisterDto {
    #[validate(email(message = "Email inválido"))]
    pub email: String,

    #[validate(length(min = 3, max = 30, message = "Nome de usuário deve ter entre 3 e 30 caracteres"))]
    pub username: String,

    #[validate(length(min = 8, message = "Senha deve ter pelo menos 8 caracteres"))]
    pub password: String,

    #[validate(must_match(other = "password", message = "As senhas não coincidem"))]
    pub confirm_password: String,

    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ForgotPasswordDto {
    #[validate(email(message = "Email inválido"))]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct ResetPasswordDto {
    #[validate(length(min = 1, message = "Token é obrigatório"))]
    pub token: String,

    #[validate(length(min = 8, message = "Senha deve ter pelo menos 8 caracteres"))]
    pub password: String,

    #[validate(must_match(other = "password", message = "As senhas não coincidem"))]
    pub confirm_password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,        // ID do usuário
    pub username: String,   // Nome de usuário
    pub email: String,      // Email do usuário
    pub is_admin: bool,     // Flag de administrador
    pub exp: usize,         // Timestamp de expiração
    pub iat: usize,         // Timestamp de emissão
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64, // Em segundos
    pub refresh_token: String, // Adicionar refresh token
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordResetToken {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// --- Refresh Token ---

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub token_hash: String, // O hash SHA-256 do token
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
}

impl RefreshToken {
    pub fn new(user_id: String, duration_days: i64) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            // O token original não é armazenado aqui, apenas seu hash
            token_hash: String::new(), // Será preenchido após o hashing
            expires_at: now + Duration::days(duration_days),
            created_at: now,
            revoked: false,
        }
    }

    // Método não utilizado na lógica atual
    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RefreshTokenDto {
    #[validate(length(min = 1, message = "Refresh token é obrigatório"))]
    pub refresh_token: String,
}

impl PasswordResetToken {
    pub fn new(user_id: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            token: Uuid::new_v4().to_string(), // Token para reset de senha
            expires_at: now + Duration::hours(1),
            created_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String, // Token da sessão, não JWT
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Session {
    pub fn new(
        user_id: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        duration_hours: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            token: Uuid::new_v4().to_string(), // Token único para identificar a sessão
            ip_address,
            user_agent,
            expires_at: now + Duration::hours(duration_hours),
            created_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthLog {
    pub id: String,
    pub user_id: Option<String>,
    pub event_type: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl AuthLog {
    pub fn new(
        user_id: Option<String>,
        event_type: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            event_type,
            ip_address,
            user_agent,
            details,
            created_at: Utc::now(),
        }
    }
}

// DTO para a requisição de desbloqueio de conta
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UnlockAccountDto {
    #[validate(length(min = 1, message = "Token de desbloqueio é obrigatório"))]
    pub token: String,
}
