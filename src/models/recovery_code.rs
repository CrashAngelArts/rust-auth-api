use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// Modelo para códigos de recuperação únicos
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    pub id: String,
    pub user_id: String,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub used: bool,
}

impl RecoveryCode {
    /// Cria um novo código de recuperação para um usuário
    pub fn new(user_id: String, code: String, expiration_hours: Option<i64>) -> Self {
        let now = Utc::now();
        let expires_at = expiration_hours.map(|hours| now + chrono::Duration::hours(hours));
        
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            code,
            created_at: now,
            expires_at,
            used: false,
        }
    }
    
    /// Verifica se o código está expirado
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false // Se não tem data de expiração, nunca expira
        }
    }
    
    /// Marca o código como usado
    pub fn mark_as_used(&mut self) {
        self.used = true;
    }
}

/// DTO para criar um novo código de recuperação
#[derive(Debug, Deserialize, Validate)]
pub struct CreateRecoveryCodeDto {
    pub user_id: String,
    pub expiration_hours: Option<i64>,
}

/// DTO para verificar um código de recuperação
#[derive(Debug, Deserialize, Validate)]
pub struct VerifyRecoveryCodeDto {
    #[validate(length(min = 1, message = "Código de recuperação não pode estar vazio 🔑"))]
    pub code: String,
}

/// Resposta para um código de recuperação gerado
#[derive(Debug, Serialize)]
pub struct RecoveryCodeResponse {
    pub message: String,
    pub code: String,
    pub expires_at: Option<DateTime<Utc>>,
} 