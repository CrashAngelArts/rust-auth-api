use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Modelo para token na lista negra
#[derive(Debug, Serialize, Deserialize)]
pub struct BlacklistedToken {
    pub id: String,
    pub token_id: String,
    pub expiry: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl BlacklistedToken {
    pub fn new(token_id: String, expiry: DateTime<Utc>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            token_id,
            expiry,
            created_at: Utc::now(),
        }
    }
}

// Claims para o token JWT com suporte a rotação
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,         // ID do usuário
    pub exp: i64,            // Tempo de expiração
    pub iat: i64,            // Tempo de emissão
    pub jti: String,         // ID único do token
    pub fam: String,         // Família de tokens para rotação
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfv: Option<bool>,   // Verificação 2FA completada
}

// Resposta após login bem-sucedido com tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub requires_2fa: bool,
    pub user_id: String,
    pub username: String,
}

// DTO para refresh token
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenDto {
    pub refresh_token: String,
}
