use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::recovery_email::{AddRecoveryEmailDto, RecoveryEmail, RecoveryEmailResponse};
use crate::services::email_service::EmailService;
use chrono::Utc;
use rusqlite::params;
use tracing::info;
use rusqlite::types::Type;

pub struct RecoveryEmailService;

impl RecoveryEmailService {
    // Adiciona um novo email de recuperação
    pub async fn add_recovery_email(
        pool: &DbPool,
        user_id: &str,
        dto: AddRecoveryEmailDto,
        email_service: &EmailService,
    ) -> Result<RecoveryEmail, ApiError> {
        let conn = pool.get()?;

        // Verificar se o email já está em uso
        let email_exists: bool = conn
            .query_row(
                "SELECT 1 FROM recovery_emails WHERE email = ?1 LIMIT 1",
                [&dto.email],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if email_exists {
            return Err(ApiError::ConflictError(
                "Este email já está em uso como email de recuperação 📧".to_string(),
            ));
        }

        // Criar novo email de recuperação
        let mut recovery_email = RecoveryEmail::new(user_id.to_string(), dto.email);
        
        // Gerar token de verificação
        let verification_token = recovery_email.generate_verification_token();

        // Inserir no banco de dados
        conn.execute(
            "INSERT INTO recovery_emails (id, user_id, email, is_verified, verification_token, verification_token_expires_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                &recovery_email.id,
                &recovery_email.user_id,
                &recovery_email.email,
                &recovery_email.is_verified,
                &recovery_email.verification_token,
                &recovery_email.verification_token_expires_at.map(|dt| dt.to_rfc3339()),
                &recovery_email.created_at,
                &recovery_email.updated_at,
            ],
        )?;

        // Enviar email de verificação
        if email_service.is_enabled() {
            Self::send_verification_email(email_service, &recovery_email, &verification_token).await?;
        }

        info!("✅ Email de recuperação adicionado: {}", recovery_email.email);
        Ok(recovery_email)
    }

    // Envia email de verificação
    async fn send_verification_email(
        email_service: &EmailService,
        recovery_email: &RecoveryEmail,
        token: &str,
    ) -> Result<(), ApiError> {
        let verification_link = format!(
            "{}/verify-recovery-email?token={}",
            email_service.get_base_url(),
            token
        );

        let text_content = format!(
            "Olá,\n\nVocê adicionou este email como email de recuperação para sua conta. \n\nClique no link abaixo para verificar este email:\n{}\n\nEste link expira em 24 horas.\n\nSe você não solicitou esta adição, ignore este email.\n\nAtenciosamente,\nEquipe de Segurança 🔒",
            verification_link
        );

        let html_content = format!(
            r#"
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                <h2 style="color: #4a6ee0;">Verificação de Email de Recuperação 📧</h2>
                <p>Olá,</p>
                <p>Você adicionou este email como <strong>email de recuperação</strong> para sua conta.</p>
                <p>Clique no botão abaixo para verificar este email:</p>
                <p style="text-align: center;">
                    <a href="{}" style="display: inline-block; background-color: #4a6ee0; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; font-weight: bold;">Verificar Email 🔐</a>
                </p>
                <p>Este link expira em <strong>24 horas</strong>.</p>
                <p>Se você não solicitou esta adição, ignore este email.</p>
                <p>Atenciosamente,<br>Equipe de Segurança 🔒</p>
            </div>
            "#,
            verification_link
        );

        email_service.send_email(
            &recovery_email.email,
            "Verificação de Email de Recuperação 📧",
            &text_content,
            &html_content,
        ).await?;

        info!(
            "✉️ Email de verificação enviado para: {}",
            recovery_email.email
        );
        Ok(())
    }

    // Verifica um email de recuperação
    pub fn verify_recovery_email(
        pool: &DbPool,
        token: &str,
    ) -> Result<RecoveryEmail, ApiError> {
        let conn = pool.get()?;

        // Buscar o email de recuperação pelo token
        let mut stmt = conn.prepare(
            "SELECT id, user_id, email, is_verified, verification_token, verification_token_expires_at, created_at, updated_at
             FROM recovery_emails 
             WHERE verification_token = ?1",
        )?;

        let recovery_email = stmt.query_row([token], |row| {
            let verification_token_expires_at: Option<String> = row.get(5)?;
            let expires_at = verification_token_expires_at
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
                .transpose()
                .map_err(|e| rusqlite::Error::InvalidColumnType(5, format!("Invalid date: {}", e), Type::Null))?;

            Ok(RecoveryEmail {
                id: row.get(0)?,
                user_id: row.get(1)?,
                email: row.get(2)?,
                is_verified: row.get(3)?,
                verification_token: row.get(4)?,
                verification_token_expires_at: expires_at,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        });

        let mut recovery_email = match recovery_email {
            Ok(email) => email,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(ApiError::NotFoundError(
                    "Token de verificação inválido ou expirado 🔒".to_string(),
                ));
            }
            Err(e) => return Err(ApiError::DatabaseError(e.to_string())),
        };

        // Verificar se o token expirou
        if let Some(expires_at) = recovery_email.verification_token_expires_at {
            if expires_at < Utc::now() {
                return Err(ApiError::ValidationError(
                    [("token".to_string(), vec!["Token expirado 🕒".to_string()])]
                        .iter()
                        .cloned()
                        .collect(),
                ));
            }
        }

        // Atualizar o status para verificado
        recovery_email.verify();

        // Atualizar no banco de dados
        conn.execute(
            "UPDATE recovery_emails 
             SET is_verified = ?1, 
                 verification_token = ?2, 
                 verification_token_expires_at = ?3, 
                 updated_at = ?4 
             WHERE id = ?5",
            params![
                recovery_email.is_verified,
                recovery_email.verification_token,
                recovery_email.verification_token_expires_at.map(|dt| dt.to_rfc3339()),
                recovery_email.updated_at,
                recovery_email.id,
            ],
        )?;

        info!("✅ Email de recuperação verificado: {}", recovery_email.email);
        Ok(recovery_email)
    }

    // Lista todos os emails de recuperação de um usuário
    pub fn list_recovery_emails(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<RecoveryEmailResponse>, ApiError> {
        let conn = pool.get()?;

        let mut stmt = conn.prepare(
            "SELECT id, user_id, email, is_verified, created_at, updated_at
             FROM recovery_emails 
             WHERE user_id = ?1
             ORDER BY created_at DESC",
        )?;

        let emails = stmt
            .query_map([user_id], |row| {
                Ok(RecoveryEmail {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    email: row.get(2)?,
                    is_verified: row.get(3)?,
                    verification_token: None,
                    verification_token_expires_at: None,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            })?
            .map(|result| result.map(RecoveryEmailResponse::from))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(emails)
    }

    // Remove um email de recuperação
    pub fn remove_recovery_email(
        pool: &DbPool,
        user_id: &str,
        email_id: &str,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;

        // Verificar se o email pertence ao usuário
        let email_exists: bool = conn
            .query_row(
                "SELECT 1 FROM recovery_emails WHERE id = ?1 AND user_id = ?2 LIMIT 1",
                params![email_id, user_id],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if !email_exists {
            return Err(ApiError::NotFoundError(
                "Email de recuperação não encontrado 🔍".to_string(),
            ));
        }

        // Remover o email
        conn.execute(
            "DELETE FROM recovery_emails WHERE id = ?1 AND user_id = ?2",
            params![email_id, user_id],
        )?;

        info!("🗑️ Email de recuperação removido: {}", email_id);
        Ok(())
    }

    // Reenviar email de verificação
    pub async fn resend_verification_email(
        pool: &DbPool,
        user_id: &str,
        email_id: &str,
        email_service: &EmailService,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;

        // Buscar o email de recuperação
        let mut stmt = conn.prepare(
            "SELECT id, user_id, email, is_verified, verification_token, verification_token_expires_at, created_at, updated_at
             FROM recovery_emails 
             WHERE id = ?1 AND user_id = ?2",
        )?;

        let recovery_email_result = stmt.query_row(params![email_id, user_id], |row| {
            let verification_token_expires_at: Option<String> = row.get(5)?;
            let expires_at = verification_token_expires_at
                .map(|s| DateTime::parse_from_rfc3339(&s).map(|dt| dt.with_timezone(&Utc)))
                .transpose()
                .map_err(|e| rusqlite::Error::InvalidColumnType(5, format!("Invalid date: {}", e), Type::Null))?;

            Ok(RecoveryEmail {
                id: row.get(0)?,
                user_id: row.get(1)?,
                email: row.get(2)?,
                is_verified: row.get(3)?,
                verification_token: row.get(4)?,
                verification_token_expires_at: expires_at,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        });

        let mut recovery_email = match recovery_email_result {
            Ok(email) => email,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(ApiError::NotFoundError(
                    "Email de recuperação não encontrado 🔍".to_string(),
                ));
            }
            Err(e) => return Err(ApiError::DatabaseError(e.to_string())),
        };

        // Verificar se já está verificado
        if recovery_email.is_verified {
            return Err(ApiError::BadRequestError(
                "Este email já foi verificado ✅".to_string(),
            ));
        }

        // Gerar novo token
        let verification_token = recovery_email.generate_verification_token();

        // Atualizar no banco de dados
        conn.execute(
            "UPDATE recovery_emails 
             SET verification_token = ?1, 
                 verification_token_expires_at = ?2, 
                 updated_at = ?3 
             WHERE id = ?4",
            params![
                recovery_email.verification_token,
                recovery_email.verification_token_expires_at.map(|dt| dt.to_rfc3339()),
                recovery_email.updated_at,
                recovery_email.id,
            ],
        )?;

        // Enviar email de verificação
        if email_service.is_enabled() {
            Self::send_verification_email(email_service, &recovery_email, &verification_token).await?;
        }

        info!(
            "📤 Email de verificação reenviado para: {}",
            recovery_email.email
        );
        Ok(())
    }

    // Busca usuário pelo email de recuperação
    pub fn get_user_id_by_recovery_email(
        pool: &DbPool,
        email: &str,
    ) -> Result<String, ApiError> {
        let conn = pool.get()?;

        let user_id = conn.query_row(
            "SELECT user_id FROM recovery_emails WHERE email = ?1 AND is_verified = 1",
            [email],
            |row| row.get(0),
        );

        match user_id {
            Ok(user_id) => Ok(user_id),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                Err(ApiError::NotFoundError(
                    format!("Usuário com email de recuperação {} não encontrado 📧", email)
                ))
            }
            Err(e) => Err(ApiError::DatabaseError(e.to_string())),
        }
    }
}

// Importação necessária para o parse de data
use chrono::DateTime;
