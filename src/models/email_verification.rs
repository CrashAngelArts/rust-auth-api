use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

// Modelo para armazenar códigos de verificação por email
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EmailVerificationCode {
    pub id: String,
    pub user_id: String,
    pub code: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
}

// DTO para verificar um código
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct VerifyEmailCodeDto {
    #[validate(length(min = 4, max = 8, message = "O código deve ter entre 4 e 8 caracteres"))]
    pub code: String,
}

// Resposta para o status de verificação
#[derive(Debug, Serialize, Deserialize)]
pub struct EmailVerificationResponse {
    pub verified: bool,
    pub message: String,
}

impl EmailVerificationCode {
    // Cria um novo código de verificação
    pub fn new(user_id: String, ip_address: Option<String>, user_agent: Option<String>, expiration_minutes: i64) -> Self {
        let now = Utc::now();
        let code = Self::generate_code();
        
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            user_id,
            code,
            ip_address,
            user_agent,
            created_at: now,
            expires_at: now + chrono::Duration::minutes(expiration_minutes),
            verified: false,
            verified_at: None,
        }
    }
    
    // Verifica se o código expirou
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
    
    // Gera um código aleatório de 6 dígitos
    fn generate_code() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let code: u32 = rng.gen_range(100000..999999);
        code.to_string()
    }
}
