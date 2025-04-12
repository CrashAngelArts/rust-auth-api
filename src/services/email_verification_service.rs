use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::email_verification::{EmailVerificationCode, EmailVerificationResponse};
use crate::models::user::User;
use crate::services::email_service::EmailService;
use chrono::Utc;
use tracing::{info, warn};

pub struct EmailVerificationService;

impl EmailVerificationService {
    // Gera um novo código e envia por email
    pub async fn generate_and_send_code(
        pool: &DbPool,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
        email_service: &EmailService,
        expiration_minutes: i64,
    ) -> Result<(), ApiError> {
        // Criar novo código de verificação
        let verification_code = EmailVerificationCode::new(
            user.id.clone(),
            ip_address,
            user_agent,
            expiration_minutes,
        );
        
        // Salvar no banco de dados
        let conn = pool.get()?;
        conn.execute(
            "INSERT INTO email_verification_codes (id, user_id, code, ip_address, user_agent, created_at, expires_at, verified, verified_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            (
                &verification_code.id,
                &verification_code.user_id,
                &verification_code.code,
                &verification_code.ip_address,
                &verification_code.user_agent,
                &verification_code.created_at,
                &verification_code.expires_at,
                &verification_code.verified,
                &verification_code.verified_at,
            ),
        )?;
        
        // Enviar email com o código
        Self::send_verification_email(email_service, user, &verification_code.code).await?;
        
        info!("🔑 Código de verificação gerado e enviado para: {}", user.email);
        Ok(())
    }
    
    // Verifica um código
    pub fn verify_code(
        pool: &DbPool,
        user_id: &str,
        code: &str,
    ) -> Result<EmailVerificationResponse, ApiError> {
        let conn = pool.get()?;
        
        // Buscar o código mais recente não verificado
        let result = conn.query_row(
            "SELECT id, user_id, code, ip_address, user_agent, created_at, expires_at, verified, verified_at
             FROM email_verification_codes
             WHERE user_id = ?1 AND verified = 0
             ORDER BY created_at DESC
             LIMIT 1",
            [user_id],
            |row| {
                Ok(EmailVerificationCode {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    code: row.get(2)?,
                    ip_address: row.get(3)?,
                    user_agent: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    verified: row.get(7)?,
                    verified_at: row.get(8)?,
                })
            },
        );
        
        let verification_code = match result {
            Ok(code) => code,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(ApiError::BadRequestError("Nenhum código de verificação pendente encontrado".to_string()));
            }
            Err(e) => return Err(ApiError::DatabaseError(e.to_string())),
        };
        
        // Verificar se o código expirou
        if verification_code.is_expired() {
            return Err(ApiError::BadRequestError("Código de verificação expirado".to_string()));
        }
        
        // Verificar se o código está correto
        if verification_code.code != code {
            warn!("⚠️ Tentativa de verificação com código incorreto para o usuário ID: {}", user_id);
            return Err(ApiError::BadRequestError("Código de verificação inválido".to_string()));
        }
        
        // Marcar código como verificado
        let now = Utc::now();
        let now_str = now.to_rfc3339(); // Converter para string no formato RFC3339
        conn.execute(
            "UPDATE email_verification_codes SET verified = 1, verified_at = ?1 WHERE id = ?2",
            (&now_str, &verification_code.id),
        )?;
        
        info!("✅ Código de verificação validado com sucesso para o usuário ID: {}", user_id);
        
        // Retornar resposta de sucesso
        Ok(EmailVerificationResponse {
            verified: true,
            message: "Código verificado com sucesso".to_string(),
        })
    }
    
    // Verifica se o usuário tem um código pendente
    pub fn has_pending_code(pool: &DbPool, user_id: &str) -> Result<bool, ApiError> {
        let conn = pool.get()?;
        
        let now = Utc::now();
        let now_str = now.to_rfc3339(); // Converter para string no formato RFC3339
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM email_verification_codes
             WHERE user_id = ?1 AND verified = 0 AND expires_at > ?2",
            [user_id, &now_str],
            |row| row.get(0),
        )?;
        
        Ok(count > 0)
    }
    
    // Limpa códigos expirados
    pub fn clean_expired_codes(pool: &DbPool) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        let now = Utc::now();
        let now_str = now.to_rfc3339(); // Converter para string no formato RFC3339
        let deleted = conn.execute(
            "DELETE FROM email_verification_codes WHERE expires_at < ?1",
            [&now_str],
        )?;
        
        if deleted > 0 {
            info!("🧹 {} códigos de verificação expirados foram removidos", deleted);
        }
        
        Ok(deleted)
    }
    
    // Envia email com código de verificação
    async fn send_verification_email(
        email_service: &EmailService,
        user: &User,
        code: &str,
    ) -> Result<(), ApiError> {
        let html_body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Verificação de Login</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }}
                    .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    .header {{ background-color: #4a86e8; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }}
                    .content {{ padding: 20px; }}
                    .code {{ font-size: 24px; font-weight: bold; text-align: center; margin: 20px 0; padding: 10px; background-color: #f5f5f5; border-radius: 5px; letter-spacing: 5px; }}
                    .footer {{ font-size: 12px; color: #777; text-align: center; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h2>Verificação de Login</h2></div>
                    <div class="content">
                        <p>Olá, <strong>{name}</strong>! 😊</p>
                        <p>Detectamos um novo login na sua conta. Para sua segurança, use o código abaixo para confirmar que é você:</p>
                        <div class="code">{code}</div>
                        <p>Este código expirará em 15 minutos. Se você não tentou fazer login, por favor, altere sua senha imediatamente.</p>
                        <p>Atenciosamente,<br>Equipe de Segurança 🔒</p>
                    </div>
                    <div class="footer"><p>Este é um email automático, por favor não responda.</p></div>
                </div>
            </body>
            </html>
            "#,
            name = user.full_name(),
            code = code
        );

        let text_body = format!(
            r#"
            Verificação de Login

            Olá, {}! 😊

            Detectamos um novo login na sua conta. Para sua segurança, use o código abaixo para confirmar que é você:

            {}

            Este código expirará em 15 minutos. Se você não tentou fazer login, por favor, altere sua senha imediatamente.

            Atenciosamente,
            Equipe de Segurança 🔒

            Este é um email automático, por favor não responda.
            "#,
            user.full_name(),
            code
        );

        email_service.send_email(
            &user.email,
            "Código de Verificação de Login",
            &text_body,
            &html_body,
        ).await
    }
}
