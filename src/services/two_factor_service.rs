use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::user::User;
use crate::models::two_factor::{TwoFactorSetupResponse, TwoFactorEnabledResponse};
use chrono::Utc;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use totp_rs::{TOTP, Secret, Algorithm};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;
use base32;
use tracing::info;


pub struct TwoFactorService;

impl TwoFactorService {
    // Gera um novo segredo TOTP e retorna as informações para configuração
    pub fn generate_setup(user: &User) -> Result<TwoFactorSetupResponse, ApiError> {
        // Gerar um segredo aleatório
        let secret_bytes: Vec<u8> = (0..20).map(|_| thread_rng().gen::<u8>()).collect();
        
        // Codificar o segredo em base32
        let secret_base32 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);
        
        // Criar o objeto TOTP
        let _totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Raw(secret_bytes.clone()).to_bytes().unwrap(),
        ).map_err(|e| ApiError::InternalServerError(format!("Erro ao criar TOTP: {}", e)))?;
        
        // Gerar a URL para o QR code
        let issuer = "Rust Auth API 🔒";
        let totp_url = format!("otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
            issuer, user.email, secret_base32, issuer);
        
        // Gerar o QR code
        let qr_code = QrCode::new(totp_url.clone())
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao gerar QR code: {}", e)))?
            .render::<Dense1x2>()
            .build();
        
        Ok(TwoFactorSetupResponse {
            secret: secret_base32.clone(),
            qr_code: qr_code,
            manual_entry_key: secret_base32,
            issuer: "Rust Auth API".to_string(),
            account_name: user.email.clone(),
        })
    }
    
    // Ativa 2FA para o usuário após verificar o código TOTP
    pub fn enable_2fa(pool: &DbPool, user_id: &str, totp_code: &str, totp_secret: &str) -> Result<TwoFactorEnabledResponse, ApiError> {
        let conn = pool.get()?;
        
        // Verificar o código TOTP
        if !Self::verify_totp(totp_secret, totp_code)? {
            return Err(ApiError::AuthenticationError("Código TOTP inválido".to_string()));
        }
        
        // Gerar códigos de backup
        let backup_codes = Self::generate_backup_codes();
        let backup_codes_str = serde_json::to_string(&backup_codes)
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao serializar códigos de backup: {}", e)))?;
        
        // Atualizar o usuário no banco de dados
        conn.execute(
            "UPDATE users SET totp_secret = ?1, totp_enabled = 1, backup_codes = ?2, updated_at = ?3 WHERE id = ?4",
            (totp_secret, backup_codes_str, Utc::now(), user_id),
        )?;
        
        info!("🔐 2FA ativado com sucesso para o usuário ID: {}", user_id);
        
        Ok(TwoFactorEnabledResponse {
            enabled: true,
            backup_codes: backup_codes,
            message: "Autenticação de dois fatores ativada com sucesso".to_string(),
        })
    }
    
    // Desativa 2FA para o usuário
    pub fn disable_2fa(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Atualizar o usuário no banco de dados
        conn.execute(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0, backup_codes = NULL, updated_at = ?1 WHERE id = ?2",
            (Utc::now(), user_id),
        )?;
        
        info!("🔓 2FA desativado para o usuário ID: {}", user_id);
        
        Ok(())
    }
    
    // Verifica um código TOTP
    pub fn verify_totp(secret: &str, code: &str) -> Result<bool, ApiError> {
        // Decodificar o segredo de base32
        let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
            .ok_or_else(|| ApiError::InternalServerError("Erro ao decodificar segredo TOTP".to_string()))?;
        
        // Criar o objeto TOTP
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Raw(secret_bytes.clone()).to_bytes().unwrap(),
        ).map_err(|e| ApiError::InternalServerError(format!("Erro ao criar TOTP: {}", e)))?;
        
        // Verificar o código
        Ok(totp.check_current(code).unwrap_or(false))
    }
    
    // Verifica um código de backup
    pub fn verify_backup_code(pool: &DbPool, user_id: &str, backup_code: &str) -> Result<bool, ApiError> {
        let conn = pool.get()?;
        
        // Obter os códigos de backup do usuário
        let backup_codes_str: Option<String> = conn.query_row(
            "SELECT backup_codes FROM users WHERE id = ?1",
            [user_id],
            |row| row.get(0),
        )?;
        
        if let Some(backup_codes_json) = backup_codes_str {
            // Deserializar os códigos de backup
            let mut backup_codes: Vec<String> = serde_json::from_str(&backup_codes_json)
                .map_err(|e| ApiError::InternalServerError(format!("Erro ao deserializar códigos de backup: {}", e)))?;
            
            // Verificar se o código está na lista
            if let Some(index) = backup_codes.iter().position(|code| code == backup_code) {
                // Remover o código usado
                backup_codes.remove(index);
                
                // Atualizar os códigos de backup no banco de dados
                let new_backup_codes_json = serde_json::to_string(&backup_codes)
                    .map_err(|e| ApiError::InternalServerError(format!("Erro ao serializar códigos de backup: {}", e)))?;
                
                conn.execute(
                    "UPDATE users SET backup_codes = ?1, updated_at = ?2 WHERE id = ?3",
                    (new_backup_codes_json, Utc::now(), user_id),
                )?;
                
                info!("🔑 Código de backup utilizado com sucesso para o usuário ID: {}", user_id);
                
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    // Gera novos códigos de backup
    pub fn regenerate_backup_codes(pool: &DbPool, user_id: &str) -> Result<Vec<String>, ApiError> {
        let conn = pool.get()?;
        
        // Gerar novos códigos de backup
        let backup_codes = Self::generate_backup_codes();
        let backup_codes_str = serde_json::to_string(&backup_codes)
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao serializar códigos de backup: {}", e)))?;
        
        // Atualizar o usuário no banco de dados
        conn.execute(
            "UPDATE users SET backup_codes = ?1, updated_at = ?2 WHERE id = ?3",
            (backup_codes_str, Utc::now(), user_id),
        )?;
        
        info!("🔄 Códigos de backup regenerados para o usuário ID: {}", user_id);
        
        Ok(backup_codes)
    }
    
    // Função auxiliar para gerar códigos de backup
    fn generate_backup_codes() -> Vec<String> {
        let mut codes = Vec::new();
        let mut rng = thread_rng();
        
        // Gerar 10 códigos de backup de 8 caracteres
        for _ in 0..10 {
            let code: String = (0..8)
                .map(|_| rng.sample(Alphanumeric) as char)
                .collect();
            codes.push(code);
        }
        
        codes
    }
}
