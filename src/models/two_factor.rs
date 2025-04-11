use serde::{Deserialize, Serialize};
use validator::Validate;

// DTO para ativar 2FA
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Enable2FADto {
    #[validate(length(min = 6, max = 6, message = "Código TOTP deve ter 6 dígitos"))]
    pub totp_code: String,
}

// DTO para verificar 2FA durante login
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Verify2FADto {
    #[validate(length(min = 6, max = 6, message = "Código TOTP deve ter 6 dígitos"))]
    pub totp_code: String,
}

// DTO para desativar 2FA
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct Disable2FADto {
    #[validate(length(min = 6, max = 6, message = "Código TOTP deve ter 6 dígitos"))]
    pub totp_code: String,
    
    #[validate(length(min = 8, message = "Senha deve ter pelo menos 8 caracteres"))]
    pub password: String,
}

// DTO para usar código de backup
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UseBackupCodeDto {
    #[validate(length(min = 8, max = 8, message = "Código de backup deve ter 8 caracteres"))]
    pub backup_code: String,
}

// Resposta com informações de configuração 2FA
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorSetupResponse {
    pub secret: String,
    pub qr_code: String,
    pub manual_entry_key: String,
    pub issuer: String,
    pub account_name: String,
}

// Resposta após ativação bem-sucedida do 2FA
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorEnabledResponse {
    pub enabled: bool,
    pub backup_codes: Vec<String>,
    pub message: String,
}

// Resposta com status do 2FA
#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorStatusResponse {
    pub enabled: bool,
    pub created_at: Option<String>,
}
