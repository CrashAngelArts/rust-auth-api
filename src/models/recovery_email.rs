use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

// Modelo para email de recuperação
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryEmail {
    pub id: String,
    pub user_id: String,
    pub email: String,
    pub is_verified: bool,
    pub verification_token: Option<String>,
    pub verification_token_expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RecoveryEmail {
    pub fn new(user_id: String, email: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            email,
            is_verified: false,
            verification_token: None,
            verification_token_expires_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    // Gera um token de verificação
    pub fn generate_verification_token(&mut self) -> String {
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        
        self.verification_token = Some(token.clone());
        self.verification_token_expires_at = Some(expires_at);
        self.updated_at = Utc::now();
        
        token
    }

    // Verifica o email
    pub fn verify(&mut self) {
        self.is_verified = true;
        self.verification_token = None;
        self.verification_token_expires_at = None;
        self.updated_at = Utc::now();
    }
}

// DTO para adicionar um novo email de recuperação
#[derive(Debug, Deserialize, Validate)]
pub struct AddRecoveryEmailDto {
    #[validate(email(message = "Email de recuperação inválido 📧"))]
    pub email: String,
}

// DTO para verificar um email de recuperação
#[derive(Debug, Deserialize)]
pub struct VerifyRecoveryEmailDto {
    pub token: String,
}

// Resposta para listagem de emails de recuperação
#[derive(Debug, Serialize)]
pub struct RecoveryEmailResponse {
    pub id: String,
    pub email: String,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
}

impl From<RecoveryEmail> for RecoveryEmailResponse {
    fn from(email: RecoveryEmail) -> Self {
        Self {
            id: email.id,
            email: email.email,
            is_verified: email.is_verified,
            created_at: email.created_at,
        }
    }
}
