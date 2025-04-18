use crate::config::Config;
use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::{
    AuthLog, AuthResponse, ForgotPasswordDto, LoginDto, PasswordResetToken, RefreshToken,
    RefreshTokenDto, RegisterDto, ResetPasswordDto, Session, TokenClaims, UnlockAccountDto,
};
use crate::models::user::{CreateUserDto, User};
use crate::services::device_service::DeviceService;
use crate::services::email_service::EmailService;
use crate::services::user_service::UserService;
use chrono::{Duration, Utc, DateTime, TimeZone};
use hex;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use tracing::{error, info, warn};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use moka::future::Cache;
use std::collections::HashMap;
use std::sync::Arc;
use crate::repositories::temporary_password_repository;
use crate::utils::password_argon2;
use crate::models::temporary_password::TemporaryPassword;
// use rusqlite::OptionalExtension; // Removido - não usado aqui

pub struct AuthService;

impl AuthService {
    // Registra um novo usuário
    pub fn register(
        pool: &DbPool,
        register_dto: RegisterDto,
        salt_rounds: u32,
    ) -> Result<User, ApiError> {
        // Verifica se as senhas coincidem
        if register_dto.password != register_dto.confirm_password {
            let mut errors = HashMap::new();
            errors.insert("confirm_password".to_string(), vec!["As senhas não coincidem".to_string()]);
            return Err(ApiError::ValidationError(errors));
        }
        // Cria o DTO para criação de usuário
        let create_dto = CreateUserDto {
            email: register_dto.email,
            username: register_dto.username,
            password: register_dto.password,
            first_name: register_dto.first_name,
            last_name: register_dto.last_name,
            recovery_email: None, // Email de recuperação opcional 📧
        };

        // Cria o usuário
        let user = UserService::create_user(pool, create_dto, salt_rounds)?;

        info!("👤 Usuário registrado com sucesso: {}", user.username);
        Ok(user)
    }

    // Autentica um usuário
    pub async fn login(
        pool: &DbPool,
        login_dto: LoginDto,
        config: &Config,
        ip_address: Option<String>,
        user_agent: Option<String>,
        email_service: &EmailService,
    ) -> Result<AuthResponse, ApiError> {
        // Usar Arc<DbPool> para chamadas async dentro
        let pool_arc = Arc::new(pool.clone());

        // Obtém o usuário pelo email ou nome de usuário
        let mut user = UserService::get_user_by_email_or_username(pool, &login_dto.username_or_email)
            .map_err(|_| ApiError::AuthenticationError("Credenciais inválidas 🤷".to_string()))?;

        // 1. Verifica se a conta está bloqueada
        if user.is_locked() {
            let locked_until_str = user.locked_until.map_or("N/A".to_string(), |t| t.to_rfc3339());
            let message = format!("Conta bloqueada até {}. Verifique seu email para instruções de desbloqueio.", locked_until_str);
            warn!("🔒 Tentativa de login em conta bloqueada: {}", user.username);
             Self::log_auth_event(
                pool,
                Some(user.id.clone()),
                "login_failed_locked".to_string(),
                ip_address.clone(),
                user_agent.clone(),
                Some(message.clone()),
            )?;
            return Err(ApiError::AccountLockedError(message));
        }

        // 2. Verifica se o usuário está ativo
        if !user.is_active {
            Self::log_auth_event(
                pool,
                Some(user.id.clone()),
                "login_failed_inactive".to_string(),
                ip_address.clone(),
                user_agent.clone(),
                Some("Conta inativa".to_string()),
            )?;
            warn!("🚫 Tentativa de login em conta inativa: {}", user.username);
            return Err(ApiError::AuthenticationError("Conta inativa".to_string()));
        }

        // ✨ 3. TENTA VERIFICAR SENHA TEMPORÁRIA PRIMEIRO ✨
        let active_temp_password: Option<TemporaryPassword> = temporary_password_repository::find_active_by_user_id(pool_arc.clone(), &user.id).await?;

        if let Some(temp_pass) = active_temp_password {
            info!("🔑 Encontrada senha temporária ativa para {}", user.username);
            match password_argon2::verify_password(&login_dto.password, &temp_pass.password_hash) {
                Ok(true) => {
                    info!("✅ Senha temporária válida para {}", user.username);

                    // Incrementar uso e talvez desativar
                    let updated_temp_pass = temporary_password_repository::increment_usage_and_maybe_deactivate(
                        pool_arc.clone(),
                        &temp_pass.id,
                    ).await?;

                    let remaining_uses = std::cmp::max(0, updated_temp_pass.usage_limit - updated_temp_pass.usage_count);

                    // --- LOGIN BEM SUCEDIDO COM SENHA TEMPORÁRIA ---
                    // Resetar estado de bloqueio/tentativas da conta principal (importante!)
                    if user.failed_login_attempts > 0 || user.locked_until.is_some() {
                       user.failed_login_attempts = 0;
                       user.locked_until = None;
                       user.unlock_token = None;
                       user.unlock_token_expires_at = None;
                       let conn_sync = pool.get()?; // Obter conexão sync para update sync
                       conn_sync.execute(
                           "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, unlock_token = NULL, unlock_token_expires_at = NULL, updated_at = ?1 WHERE id = ?2",
                           (&Utc::now().timestamp(), &user.id),
                       )?;
                       info!("🔓 Estado de bloqueio resetado para o usuário: {}", user.username);
                   }

                    // Gerar tokens JWT
                    let token = Self::generate_jwt(&user, &config.jwt.secret, &config.jwt.expiration)?;
                    let original_refresh_token = Uuid::new_v4().to_string();
                    let refresh_token_hash = Self::hash_token(&original_refresh_token);
                    let mut refresh_token_db = RefreshToken::new(user.id.clone(), config.jwt.refresh_expiration_days);
                    refresh_token_db.token_hash = refresh_token_hash;

                    Self::revoke_all_user_refresh_tokens(pool, &user.id)?;
                    Self::save_refresh_token(pool, &refresh_token_db)?;

                    // Criar sessão com informações de dispositivo (chamada sync)
                    let _session = DeviceService::create_session_with_device_info(
                        pool, // Passar &DbPool original
                        &user.id,
                        &ip_address,
                        &user_agent,
                        24,
                    )?; // Chamada síncrona

                    // Logar evento de login com senha temporária
                     Self::log_auth_event(
                        pool, // Usar &DbPool original aqui para log sync
                        Some(user.id.clone()),
                        "login_success_temp_password".to_string(),
                        ip_address.clone(),
                        user_agent.clone(),
                        Some(format!("Usos restantes: {}", remaining_uses)),
                    )?;

                    // Enviar email de notificação (descomentado)
                    if config.email.enabled {
                        let _ = email_service.send_temporary_password_used_email(&user, remaining_uses).await;
                    } else {
                        warn!("📧 Envio de email desabilitado. Não foi possível notificar sobre uso de senha temporária para {}", user.email);
                    }

                    // Cria a resposta
                    let auth_response = AuthResponse {
                        access_token: token,
                        token_type: "Bearer".to_string(),
                        expires_in: Self::parse_expiration(&config.jwt.expiration)? * 3600,
                        refresh_token: original_refresh_token,
                        requires_email_verification: false, // Senha temporária não exige verificação de email adicional
                        user: user.clone(),
                    };

                    info!("🎉 Login bem-sucedido com senha temporária para {}", user.username);
                    return Ok(auth_response);
                }
                Ok(false) => {
                    info!("❌ Senha temporária incorreta fornecida para {}. Tentando senha principal.", user.username);
                    // Não faz nada, continua para verificar a senha principal
                }
                Err(e) => {
                    error!("🚨 Erro ao verificar hash da senha temporária para {}: {}. Tentando senha principal.", user.username, e);
                    // Loga o erro, mas continua para a senha principal como fallback seguro
                }
            }
        } // Fim da verificação da senha temporária ativa

        // 4. Verifica a senha PRINCIPAL
        match UserService::verify_password(&login_dto.password, &user.password_hash) {
            Ok(true) => { // Senha principal correta
               // --- LOGIN BEM SUCEDIDO COM SENHA PRINCIPAL ---
                // Resetar estado de bloqueio/tentativas
                 if user.failed_login_attempts > 0 || user.locked_until.is_some() {
                    user.failed_login_attempts = 0;
                    user.locked_until = None;
                    user.unlock_token = None;
                    user.unlock_token_expires_at = None;
                    let conn_sync = pool.get()?;
                    conn_sync.execute(
                        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, unlock_token = NULL, unlock_token_expires_at = NULL, updated_at = ?1 WHERE id = ?2",
                        (&Utc::now().timestamp(), &user.id),
                    )?;
                    info!("🔓 Estado de bloqueio resetado para o usuário: {}", user.username);
                 }

                 // Gerar tokens JWT
                 let token = Self::generate_jwt(&user, &config.jwt.secret, &config.jwt.expiration)?;
                 let original_refresh_token = Uuid::new_v4().to_string();
                 let refresh_token_hash = Self::hash_token(&original_refresh_token);
                 let mut refresh_token_db = RefreshToken::new(user.id.clone(), config.jwt.refresh_expiration_days);
                 refresh_token_db.token_hash = refresh_token_hash;

                 Self::revoke_all_user_refresh_tokens(pool, &user.id)?;
                 Self::save_refresh_token(pool, &refresh_token_db)?;

                 // Criar sessão com informações de dispositivo (chamada sync)
                 let _session = DeviceService::create_session_with_device_info(
                    pool, // Passar &DbPool original
                    &user.id,
                    &ip_address,
                    &user_agent,
                    24,
                 )?; // Chamada síncrona

                 // Logar evento de login com senha principal
                 Self::log_auth_event(
                    pool, // Usar &DbPool original aqui para log sync
                    Some(user.id.clone()),
                    "login_success".to_string(),
                    ip_address.clone(),
                    user_agent.clone(),
                    None,
                )?;

                 // Verificar se precisa de verificação de email
                 let requires_email_verification = config.security.email_verification_enabled;
                 if requires_email_verification {
                    use crate::services::email_verification_service::EmailVerificationService;
                    match EmailVerificationService::generate_and_send_code(
                        pool,
                        &user,
                        ip_address.clone(),
                        user_agent.clone(),
                        email_service,
                        15,
                    ).await {
                        Ok(_) => info!("📧 Código de verificação enviado para: {}", user.email),
                        Err(e) => error!("❌ Falha ao enviar código de verificação para {}: {}", user.email, e),
                    }
                 }

                 // Cria a resposta
                 let auth_response = AuthResponse {
                     access_token: token,
                     token_type: "Bearer".to_string(),
                     expires_in: Self::parse_expiration(&config.jwt.expiration)? * 3600,
                     refresh_token: original_refresh_token,
                     user: user.clone(),
                     requires_email_verification,
                 };

                 info!("🎉 Login bem-sucedido com senha principal para {}", user.username);
                 // Disparar webhook de login_success (assíncrono, não bloqueante)
                 let payload = serde_json::json!({
                     "user_id": user.id,
                     "username": user.username,
                     "ip_address": ip_address,
                     "user_agent": user_agent,
                     "timestamp": chrono::Utc::now().to_rfc3339(),
                 });
                 let payload = payload.to_string();
                 actix_web::rt::spawn(async move {
                     crate::services::webhook_service::WebhookService::trigger_event("login_success", &payload).await;
                 });
                 Ok(auth_response)
            }
            Ok(false) | Err(_) => { // Senha principal incorreta OU erro na verificação
                // --- FALHA NO LOGIN (APÓS TENTAR TEMP E PRINCIPAL) ---
                warn!("🔑 Falha no login (senha principal inválida) para: {}", user.username);

                 // ✨ Verificar se a senha fornecida corresponde a uma TEMPORÁRIA EXPIRADA ✨
                 match password_argon2::hash_password(&login_dto.password) {
                    Ok(provided_hash) => {
                        match temporary_password_repository::find_inactive_by_user_id_and_hash(pool_arc.clone(), &user.id, &provided_hash).await? {
                            Some(inactive_temp_pass) => {
                                warn!("🚨 Tentativa de login com senha temporária EXPIRADA detectada para {} (ID Senha: {})!", user.username, inactive_temp_pass.id);
                                // Enviar email de alerta (descomentado)
                                if config.email.enabled {
                                    let _ = email_service.send_expired_temporary_password_attempt_email(&user, &login_dto.password).await;
                                } else {
                                    warn!("📧 Envio de email desabilitado. Não foi possível alertar sobre tentativa com senha expirada para {}", user.email);
                                }
                                // Logar evento específico
                                 Self::log_auth_event(
                                    pool, // Usar &DbPool original aqui para log sync
                                    Some(user.id.clone()),
                                    "login_failed_expired_temp_password".to_string(),
                                    ip_address.clone(),
                                    user_agent.clone(),
                                    Some("Tentativa com senha temporária expirada.".to_string()),
                                )?;
                                // Retorna erro, mas NÃO incrementa tentativas de falha da conta principal
                                return Err(ApiError::AuthenticationError("Senha temporária expirada ou inválida 🤷".to_string()));
                            }
                            None => {
                                info!("ℹ️ Senha fornecida não corresponde a nenhuma senha temporária expirada para {}.", user.username);
                            }
                        }
                    }
                    Err(e) => {
                        error!("🚨 Erro ao gerar hash da senha fornecida durante a verificação de expiração para {}: {}. Procedendo com falha normal.", user.username, e);
                    }
                }

                // --- LÓGICA ORIGINAL DE FALHA (Incrementar tentativas / Bloquear) ---
                user.failed_login_attempts += 1;
                warn!(
                    "🔑 Falha de login (tentativa {}/{}): {}",
                    user.failed_login_attempts, config.security.max_login_attempts, user.username
                );
                let mut should_lock = false;
                if user.failed_login_attempts >= config.security.max_login_attempts as i32 {
                   should_lock = true;
                   let now = Utc::now();
                   let lockout_duration = Duration::seconds(config.security.lockout_duration_seconds as i64);
                   user.locked_until = Some(now + lockout_duration);
                   let token: String = thread_rng()
                       .sample_iter(&Alphanumeric)
                       .take(32)
                       .map(char::from)
                       .collect();
                   user.unlock_token = Some(token.clone());
                   let token_duration = Duration::minutes(config.security.unlock_token_duration_minutes as i64);
                   user.unlock_token_expires_at = Some(now + token_duration);
                   warn!("🚫 Conta bloqueada por excesso de tentativas: {}", user.username);
                   if config.email.enabled {
                        match email_service.send_account_unlock_email(&user, &token).await {
                            Ok(_) => info!("📧 Email de desbloqueio enviado para: {}", user.email),
                            Err(e) => error!("❌ Falha ao enviar email de desbloqueio para {}: {}", user.email, e),
                        }
                   } else {
                        warn!("📧 Envio de email desabilitado. Não foi possível enviar email de desbloqueio para {}", user.email);
                   }
                }

                // Atualizar usuário no banco (tentativas ou bloqueio)
                let conn_sync = pool.get()?;
                conn_sync.execute(
                    "UPDATE users SET failed_login_attempts = ?1, locked_until = ?2, unlock_token = ?3, unlock_token_expires_at = ?4, updated_at = ?5 WHERE id = ?6",
                    (
                        &user.failed_login_attempts,
                        &user.locked_until.map(|dt| dt.timestamp()),
                        &user.unlock_token,
                        &user.unlock_token_expires_at.map(|dt| dt.timestamp()),
                        &Utc::now().timestamp(),
                        &user.id,
                    ),
                )?;

                // Logar evento de falha
                let event_type = if should_lock { "login_failed_locked".to_string() } else { "login_failed_password".to_string() };
                let details = Some(if should_lock {
                        let locked_until_str = user.locked_until.map_or("N/A".to_string(), |t| t.to_rfc3339());
                        format!("Conta bloqueada até {}. (Tentativa {})", locked_until_str, user.failed_login_attempts)
                    } else {
                        format!("Senha principal incorreta (tentativa {}).", user.failed_login_attempts)
                    });
                Self::log_auth_event(
                    pool, // Usar &DbPool original aqui para log sync
                    Some(user.id.clone()),
                    event_type,
                    ip_address.clone(),
                    user_agent.clone(),
                    details,
                )?;

                // Retornar erro apropriado
                 if should_lock {
                     let locked_until_str = user.locked_until.map_or("N/A".to_string(), |t| t.to_rfc3339());
                     let message = format!("Conta bloqueada até {}. Verifique seu email para instruções de desbloqueio.", locked_until_str);
                     Err(ApiError::AccountLockedError(message))
                 } else {
                     Err(ApiError::AuthenticationError("Credenciais inválidas 🤷".to_string()))
                 }
            }
        }
    }

    // Solicita a recuperação de senha
    pub async fn forgot_password(
        pool: &DbPool,
        forgot_dto: ForgotPasswordDto,
        email_service: &EmailService,
    ) -> Result<(), ApiError> {
        // Não precisamos da conexão aqui, apenas do pool

        // Busca o usuário
        let user_result = UserService::get_user_by_email(pool, &forgot_dto.email);

        // Se não encontrar pelo email principal, tentar pelos emails de recuperação
        let user = match user_result {
            Ok(user) => user,
            Err(ApiError::NotFoundError(_)) => {
                // Tentar buscar pelo email de recuperação na nova tabela
                let user_id = crate::services::recovery_email_service::RecoveryEmailService::get_user_id_by_recovery_email(pool, &forgot_dto.email)?;
                UserService::get_user_by_id(pool, &user_id)?
            }
            Err(e) => return Err(e),
        };

        // Verifica se o usuário está ativo e não bloqueado (não permitir reset se bloqueado)
        if !user.is_active || user.is_locked() {
            warn!(" Tentativa de recuperação de senha para conta inativa ou bloqueada: {}", user.email);
            return Ok(()); // Não informar o status exato
        }

        // Cria o token de recuperação
        let token = PasswordResetToken::new(user.id.clone());

        // Salva o token no banco de dados
        let conn = pool.get()?;

        // Remove tokens antigos para o usuário
        conn.execute(
            "DELETE FROM password_reset_tokens WHERE user_id = ?1",
            [&user.id],
        )?;

        // Insere o novo token
        conn.execute(
            "INSERT INTO password_reset_tokens (id, user_id, token, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                &token.id,
                &token.user_id,
                &token.token,
                &token.expires_at,
                &token.created_at,
            ),
        )?;

        // Envia o email com o link de recuperação
        // Determinar para qual email enviar a recuperação
        let target_email = if user.email == forgot_dto.email {
            // Se o email fornecido é o principal, enviar para ele
            &user.email
        } else {
            // Se o email fornecido é um dos de recuperação, enviar para ele
            &forgot_dto.email
        };

        // Criar conteúdo do email
        let reset_link = format!("{}/reset-password?token={}", email_service.get_base_url(), token.token);

        let text_content = format!(
            "Olá {},\n\nVocê solicitou a redefinição de senha. \n\nClique no link abaixo para redefinir sua senha:\n{}\n\nEste link expira em 1 hora.\n\nSe você não solicitou esta redefinição, ignore este email.\n\nAtenciosamente,\nEquipe de Segurança 🔒",
            user.full_name(),
            reset_link
        );
        
        let html_content = format!(
            r#"<!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Recuperação de Senha</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }}
                    .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    .header {{ background-color: #4a86e8; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }}
                    .content {{ padding: 20px; }}
                    .button {{ display: inline-block; background-color: #4a86e8; color: white !important; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ font-size: 12px; color: #777; text-align: center; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h2>Recuperação de Senha 🔑</h2></div>
                    <div class="content">
                        <p>Olá, <strong>{}</strong>!</p>
                        <p>Recebemos uma solicitação para redefinir sua senha. Se você não fez essa solicitação, por favor ignore este email.</p>
                        <p>Para redefinir sua senha, clique no botão abaixo:</p>
                        <p style="text-align: center;"><a href="{}" class="button">Redefinir Senha</a></p>
                        <p>Ou copie e cole o link abaixo no seu navegador:</p>
                        <p>{}</p>
                        <p>Este link expirará em 1 hora.</p>
                        <p>Atenciosamente,<br>Equipe de Suporte 🔒</p>
                    </div>
                    <div class="footer"><p>Este é um email automático, por favor não responda.</p></div>
                </div>
            </body>
            </html>
            "#,
            user.full_name(),
            reset_link,
            reset_link
        );
        
        // Verificar se o serviço de email está habilitado
        if email_service.is_enabled() {
            // Enviar o email
            match email_service.send_email(
                target_email,
                "Redefinição de Senha 🔑",
                &text_content,
                &html_content,
            ).await {
                Ok(_) => info!("📧 Email de recuperação de senha enviado para: {}", target_email),
                Err(e) => error!("❌ Erro ao enviar email de recuperação de senha: {}", e),
            }
        } else {
            info!("ℹ️ Serviço de email desabilitado. Token de recuperação: {}", token.token);
        }

        Ok(())
    }

    // Redefine a senha usando token de email ou código de recuperação
    pub fn reset_password(
        pool: &DbPool,
        reset_dto: ResetPasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> {
        // Verifica se as senhas coincidem
        if reset_dto.password != reset_dto.confirm_password {
             let mut errors = HashMap::new();
             errors.insert("confirm_password".to_string(), vec!["As senhas não coincidem".to_string()]); // Corrigido aqui
             return Err(ApiError::ValidationError(errors));
        }

        let conn = pool.get()?;
        let mut user_id_to_reset: Option<String> = None;
        let mut token_id_to_delete: Option<String> = None;
        let mut used_recovery_code = false;

        // Tenta verificar usando o código de recuperação primeiro
        if let Some(code) = &reset_dto.recovery_code {
            match Self::verify_recovery_code(pool, code) {
                Ok(user) => {
                    user_id_to_reset = Some(user.id.clone());
                    used_recovery_code = true;
                    info!("🔑 Verificação por código de recuperação bem-sucedida para: {}", user.username);
                }
                Err(ApiError::AuthenticationError(msg)) => {
                    warn!("🔑 Falha na verificação do código de recuperação: {}", msg);
                    // Não retorna erro ainda, pode tentar o token de email
                }
                Err(e) => return Err(e), // Erro de banco ou outro erro interno
            }
        }

        // Se não usou código de recuperação ou falhou, tenta o token de email
        if user_id_to_reset.is_none() {
            if let Some(token_str) = &reset_dto.token {
                let token_result = conn.query_row(
                    "SELECT id, user_id, token, expires_at, created_at
                     FROM password_reset_tokens
                     WHERE token = ?1",
                    [token_str],
                    |row| {
                        Ok(PasswordResetToken {
                            id: row.get(0)?,
                            user_id: row.get(1)?,
                            token: row.get(2)?,
                            expires_at: row.get(3)?,
                            created_at: row.get(4)?,
                        })
                    },
                );

                match token_result {
                    Ok(token) => {
                        if token.is_expired() {
                            warn!("🔑 Token de redefinição de senha expirado: {}", token.token);
                            conn.execute("DELETE FROM password_reset_tokens WHERE id = ?1", [&token.id])?;
                            return Err(ApiError::AuthenticationError("Token expirado".to_string()));
                        }
                        user_id_to_reset = Some(token.user_id.clone());
                        token_id_to_delete = Some(token.id.clone()); // Marcar token para exclusão
                        info!("🔑 Verificação por token de email bem-sucedida para usuário ID: {}", token.user_id);
                    }
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        warn!("🔑 Token de redefinição de senha inválido: {}", token_str);
                        // Se ambos falharam, retorna erro
                        if reset_dto.recovery_code.is_some() {
                             return Err(ApiError::AuthenticationError("Código de recuperação ou token inválido/expirado".to_string()));
                        } else {
                             return Err(ApiError::AuthenticationError("Token inválido/expirado".to_string()));
                        }
                    }
                    Err(e) => return Err(ApiError::from(e)),
                }
            } else {
                // Se nenhum método foi fornecido (embora a validação do DTO deva pegar isso)
                 return Err(ApiError::BadRequest("Nenhum método de redefinição (token ou código) fornecido".to_string()));
            }
        }

        // Se chegamos aqui, temos um user_id válido
        let user_id = user_id_to_reset.ok_or_else(|| {
             // Este caso não deve acontecer devido às verificações anteriores, mas é bom ter
             ApiError::InternalServerError("Falha ao determinar o usuário para redefinição".to_string())
        })?;

        // Obtém o usuário (para log e invalidação)
        let user = UserService::get_user_by_id(pool, &user_id)?;

        // Atualiza a senha
        UserService::update_password(pool, &user_id, &reset_dto.password, salt_rounds)?;

        // Limpa o método de recuperação usado
        if used_recovery_code {
            // Limpa o código de recuperação do usuário
            conn.execute(
                "UPDATE users SET recovery_code = NULL, recovery_code_expires_at = NULL, updated_at = ?1 WHERE id = ?2",
                (&Utc::now(), &user_id),
            )?;
            info!("🔑 Código de recuperação consumido para o usuário: {}", user.username);
        } else if let Some(token_id) = token_id_to_delete {
            // Remove o token de email usado
            conn.execute("DELETE FROM password_reset_tokens WHERE id = ?1", [&token_id])?;
            info!("🔑 Token de redefinição de senha consumido para o usuário: {}", user.username);
        }

        // Invalida todas as sessões do usuário
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1",
            [&user_id],
        )?;

        // Revoga todos os refresh tokens do usuário
        Self::revoke_all_user_refresh_tokens(pool, &user_id)?;

        info!("🔑 Senha redefinida com sucesso para o usuário: {}", user.username);
        Ok(())
    }


    // Gera um novo access token usando um refresh token
    pub fn refresh_token(
        pool: &DbPool,
        refresh_dto: RefreshTokenDto,
        config: &Config,
    ) -> Result<AuthResponse, ApiError> {
        // 1. Encontra e valida o refresh token
        let refresh_token = Self::find_and_validate_refresh_token(pool, &refresh_dto.refresh_token)?;

        // 2. Obtém o usuário associado
        let user = UserService::get_user_by_id(pool, &refresh_token.user_id)?;

        // 3. Verifica se o usuário está ativo
        if !user.is_active {
            // Revoga o token se o usuário estiver inativo
            Self::revoke_refresh_token(pool, &refresh_token.id)?;
            return Err(ApiError::AuthenticationError("Usuário inativo".to_string()));
        }

        // 4. Gera um novo access token
        let access_token = Self::generate_jwt(&user, &config.jwt.secret, &config.jwt.expiration)?;

        // 5. Cria a resposta (sem gerar novo refresh token nesta versão simples)
        //    NOTA: Uma implementação mais segura geraria um novo refresh token aqui (rotação)
        //          e revogaria o antigo (`Self::revoke_refresh_token(pool, &refresh_token.id)?;`)
        let auth_response = AuthResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: Self::parse_expiration(&config.jwt.expiration)? * 3600,
            refresh_token: refresh_dto.refresh_token, // Retorna o mesmo refresh token
            requires_email_verification: false, // Não requer verificação por email no refresh
            user: user.clone(), // Adicionar o usuário na resposta 👤
        };

        info!("🔄 Token de acesso atualizado para o usuário: {}", user.username);
        Ok(auth_response)
    }

    // Desbloqueia a conta usando o token
    pub fn unlock_account(pool: &DbPool, unlock_dto: UnlockAccountDto) -> Result<(), ApiError> {
        let conn = pool.get()?;

        // 1. Encontra o usuário pelo token de desbloqueio
        let user_result = conn.query_row(
            "SELECT id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at, totp_secret, totp_enabled, backup_codes, token_family, recovery_email, hashed_recovery_code, token_family, recovery_email, recovery_code, recovery_code_expires_at
             FROM users
             WHERE unlock_token = ?1",
            [&unlock_dto.token],
            |row| {
                // Mapeamento interno para User dentro de unlock_account
                 let get_datetime = |i: usize| -> Result<Option<DateTime<Utc>>, rusqlite::Error> {
                    Ok(row.get::<_, Option<i64>>(i)?
                        .and_then(|ts| Utc.timestamp_opt(ts, 0).single()))
                 };
                Ok(User {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    username: row.get(2)?,
                    password_hash: row.get(3)?,
                    first_name: row.get(4)?,
                    last_name: row.get(5)?,
                    is_active: row.get(6)?,
                    is_admin: row.get(7)?,
                    created_at: get_datetime(8)?.unwrap_or_else(|| Utc::now()),
                    updated_at: get_datetime(9)?.unwrap_or_else(|| Utc::now()),
                    failed_login_attempts: row.get(10)?,
                    locked_until: get_datetime(11)?,
                    unlock_token: row.get(12)?,
                    unlock_token_expires_at: get_datetime(13)?,
                    totp_secret: row.get(14)?,
                    totp_enabled: row.get(15)?,
                    backup_codes: row.get(16)?,
                    token_family: row.get(17)?,
                    recovery_email: row.get(18)?,
                    hashed_recovery_code: row.get(19)?,
                    roles: Vec::new(),
                })
            },
        );

        let mut user = match user_result {
            Ok(user) => user,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                warn!("🔓 Tentativa de desbloqueio com token inválido: {}", unlock_dto.token);
                // Usar AuthenticationError ou NotFoundError
                let mut errors = HashMap::new();
                errors.insert("token".to_string(), vec!["Token inválido".to_string()]);
                return Err(ApiError::ValidationError(errors));
            }
            Err(e) => return Err(ApiError::from(e)),
        };

        // 2. Verifica se o token de desbloqueio expirou
        if let Some(expires_at) = user.unlock_token_expires_at {
            if expires_at < Utc::now() {
                 warn!("🔓 Tentativa de desbloqueio com token expirado para: {}", user.username);
                 // Limpar o token expirado do DB
                 conn.execute(
                    "UPDATE users SET unlock_token = NULL, unlock_token_expires_at = NULL, updated_at = ?1 WHERE id = ?2",
                    (&Utc::now(), &user.id),
                 )?;
                 // Usar AuthenticationError
                 let mut errors = HashMap::new();
                 errors.insert("token".to_string(), vec!["Token expirado".to_string()]);
                 return Err(ApiError::ValidationError(errors));
            }
        } else {
            // Se não há data de expiração, mas há token, algo está errado. Considerar inválido.
             warn!("🔓 Token de desbloqueio sem data de expiração para: {}", user.username);
             // Usar AuthenticationError
             let mut errors = HashMap::new();
             errors.insert("token".to_string(), vec!["Token inválido".to_string()]);
             return Err(ApiError::ValidationError(errors));
        }

        // 3. Desbloqueia a conta e limpa os campos relacionados
        user.failed_login_attempts = 0;
        user.locked_until = None;
        user.unlock_token = None;
        user.unlock_token_expires_at = None;

        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, unlock_token = NULL, unlock_token_expires_at = NULL, updated_at = ?1 WHERE id = ?2",
            (&Utc::now(), &user.id),
        )?;

         Self::log_auth_event(
            pool,
            Some(user.id.clone()),
            "account_unlocked".to_string(),
            None, // IP/UserAgent não disponíveis neste contexto
            None,
            Some("Conta desbloqueada com sucesso via token.".to_string()),
        )?;

        info!("🔓 Conta desbloqueada com sucesso para: {}", user.username);
        Ok(())
    }


    // Valida um token JWT
    pub async fn validate_token( // Tornar async
        token: &str, 
        jwt_secret: &str,
        pool: Option<&DbPool>, // Adicionar pool como opcional para verificar blacklist 
        cache: &Cache<String, TokenClaims> // Adicionar parâmetro do cache
    ) -> Result<TokenClaims, ApiError> {
        // 1. Verificar cache primeiro
        if let Some(claims) = cache.get(token).await { // Usar .await
            info!("✅ Token validado via cache");
            return Ok(claims);
        }

        // 2. Se não estiver no cache, decodificar e validar
        let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
        
        // Configurar validação com audiência e issuer
        let mut validation = Validation::default();
        validation.set_audience(&["rust-auth-api-users"]); // Definir a audiência esperada
        validation.set_issuer(&["rust-auth-api"]); // Definir o emissor esperado

        // Decodifica o token
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                warn!("🔒 Falha na decodificação do token: {}", e);
                ApiError::AuthenticationError(format!("Falha na decodificação: {}", e)) // Usar AuthenticationError
            })?;

        // Verificar se o token está na blacklist (se o pool for fornecido)
        if let Some(db_pool) = pool {
            use crate::services::token_service::TokenService;
            
            if token_data.claims.jti.is_empty() {
                warn!("🔒 Token sem JTI (ID) para verificação de blacklist");
                return Err(ApiError::AuthenticationError("Token inválido: sem ID".to_string()));
            }
            
            if TokenService::is_token_blacklisted(db_pool, &token_data.claims.jti)? {
                warn!("🚫 Token na blacklist: {}", token_data.claims.jti);
                return Err(ApiError::AuthenticationError("Token revogado".to_string()));
            }
        }

        // 3. Inserir no cache após validação bem-sucedida
        // Usamos token.to_string() porque a chave precisa ser 'Owned'
        cache.insert(token.to_string(), token_data.claims.clone()).await; // Usar .await
        info!("🔑 Token validado e inserido no cache");

        Ok(token_data.claims) // Retorna as claims do token válido
    }

    // Gera um token JWT
    fn generate_jwt(user: &User, jwt_secret: &str, jwt_expiration: &str) -> Result<String, ApiError> {
        let expiration = Self::parse_expiration(jwt_expiration)?;
        let now = Utc::now();
        let exp = (now + Duration::hours(expiration)).timestamp() as usize;
        let iat = now.timestamp() as usize;

        // Gerar um token_id único (JTI)
        let token_id = Uuid::now_v7().to_string();
        
        // Obter a família de tokens do usuário ou criar uma nova
        let token_family = "default_family".to_string(); // Idealmente, obter do banco de dados
        
        let claims = TokenClaims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            exp,
            iat,
            aud: Some(vec!["rust-auth-api-users".to_string()]), // Definir audiência
            iss: Some("rust-auth-api".to_string()), // Definir emissor
            jti: token_id, // ID único do token
            fam: token_family, // Família de tokens
            tfv: Some(false), // Inicialmente não verificado por 2FA
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )?;

        Ok(token)
    }

    // Cria uma sessão
    pub fn create_session(
        pool: &DbPool,
        user_id: &str,
        _refresh_token: &str,
        user_agent: &str,
        ip_address: &str,
    ) -> Result<Session, ApiError> {
        let conn = pool.get()?;
        
        let session = Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24), // Sessão expira em 24 horas
            last_activity_at: Utc::now(),
            is_active: true,
        };

        // Insere a sessão no banco de dados
        conn.execute(
            "INSERT INTO sessions (id, user_id, ip_address, user_agent, created_at, expires_at, last_activity_at, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                &session.id,
                &session.user_id,
                &session.ip_address,
                &session.user_agent,
                &session.created_at,
                &session.expires_at,
                &session.last_activity_at,
                &session.is_active,
            ),
        )?;
        
        // Associar a sessão com o refresh token (opcional)
        // Isso pode ser feito em uma tabela separada ou adicionando uma coluna na tabela de sessões
        
        Ok(session)
    }

    // Registra um evento de autenticação
    fn log_auth_event(
        pool: &DbPool,
        user_id: Option<String>,
        event_type: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;

        // Cria o log
        let log = AuthLog::new(user_id, event_type, ip_address, user_agent, details);

        // Insere o log no banco de dados
        conn.execute(
            "INSERT INTO auth_logs (id, user_id, event_type, ip_address, user_agent, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                &log.id,
                &log.user_id,
                &log.event_type,
                &log.ip_address,
                &log.user_agent,
                &log.details,
                &log.created_at,
            ),
        )?;

        Ok(())
    }

    // Converte a string de expiração para horas
    fn parse_expiration(expiration: &str) -> Result<i64, ApiError> {
        let expiration = expiration.trim().to_lowercase();

        if expiration.ends_with('h') {
            let hours = expiration[..expiration.len() - 1]
                .parse::<i64>()
                .map_err(|_| {
                    ApiError::InternalServerError("Formato de expiração inválido".to_string())
                })?;

            Ok(hours)
        } else {
            // Tenta converter diretamente para horas
            expiration.parse::<i64>().map_err(|_| {
                ApiError::InternalServerError("Formato de expiração inválido".to_string())
            })
        }
    }

    // --- Funções Auxiliares ---

    // Salva um refresh token no banco
    fn save_refresh_token(pool: &DbPool, token: &RefreshToken) -> Result<(), ApiError> {
        let conn = pool.get()?;
        conn.execute(
            "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            (
                &token.id,
                &token.user_id,
                &token.token_hash, // Salvar o hash
                &token.expires_at,
                &token.created_at,
                &token.revoked,
            ),
        )?;
        Ok(())
    }

    // Encontra e valida um refresh token
    fn find_and_validate_refresh_token(pool: &DbPool, token_value: &str) -> Result<RefreshToken, ApiError> {
        let conn = pool.get()?;
        let token_hash = Self::hash_token(token_value); // Calcular hash do token recebido

        let token_result = conn.query_row(
            "SELECT id, user_id, token_hash, expires_at, created_at, revoked
             FROM refresh_tokens
             WHERE token_hash = ?1", // Buscar pelo hash
            [token_hash],
            |row| {
                Ok(RefreshToken {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    token_hash: row.get(2)?, // Ler o hash
                    expires_at: row.get(3)?,
                    created_at: row.get(4)?,
                    revoked: row.get(5)?,
                })
            },
        );

        // A função inteira retorna Result<RefreshToken, ApiError>
        let token = match token_result {
            Ok(token) => token,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(ApiError::AuthenticationError("Refresh token inválido".to_string()));
            }
            Err(e) => return Err(ApiError::DatabaseError(e.to_string())),
        };

        // Validar o token encontrado
        if token.revoked {
            Err(ApiError::AuthenticationError("Refresh token revogado".to_string()))
        } else if token.is_expired() {
            // Opcional: Remover token expirado do banco
            // let _ = conn.execute("DELETE FROM refresh_tokens WHERE id = ?1", [&token.id]);
            Err(ApiError::AuthenticationError("Refresh token expirado".to_string()))
        } else {
            Ok(token) // Retorna o token válido
        }
    }


    // Revoga um refresh token específico
    fn revoke_refresh_token(pool: &DbPool, token_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        conn.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1",
            [token_id],
        )?;
        Ok(())
    }

    // --- Funções Auxiliares para Hashing ---

    // Gera o hash SHA-256 de um token
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let result = hasher.finalize();
        hex::encode(result) // Retorna o hash como string hexadecimal
    }

    // Revoga todos os refresh tokens de um usuário
    fn revoke_all_user_refresh_tokens(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let count = conn.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1 AND revoked = 0",
            [user_id],
        )?;
        if count > 0 {
            info!("🔄 {} refresh tokens revogados para o usuário ID: {}", count, user_id);
        }
        Ok(())
    }
    
    // Gera tokens de autenticação para um usuário
    pub fn generate_auth_tokens(pool: &DbPool, user: &User) -> Result<AuthResponse, ApiError> { // Manter síncrono por enquanto
        // Obtém a configuração
        let conn = pool.get()?;
        let config_result = conn.query_row(
            "SELECT value FROM config WHERE key = 'jwt_secret' OR key = 'jwt_expiration' OR key = 'refresh_token_expiration'",
            [],
            |_| Ok(()),
        );
        
        // Verifica se as configurações existem
        if config_result.is_err() {
            return Err(ApiError::InternalServerError("Configurações JWT não encontradas 😞".to_string()));
        }
        
        // Obtém as configurações individualmente
        let jwt_secret: String = conn.query_row(
            "SELECT value FROM config WHERE key = 'jwt_secret'",
            [],
            |row| row.get(0),
        )?;
        
        let jwt_expiration: String = conn.query_row(
            "SELECT value FROM config WHERE key = 'jwt_expiration'",
            [],
            |row| row.get(0),
        )?;
        
        let refresh_expiration: String = conn.query_row(
            "SELECT value FROM config WHERE key = 'refresh_token_expiration'",
            [],
            |row| row.get(0),
        )?;
        
        // Gera o token JWT
        let access_token = Self::generate_jwt(user, &jwt_secret, &jwt_expiration)?;
        
        // Gera o refresh token
        let refresh_token_value = Uuid::new_v4().to_string();
        let token_hash = Self::hash_token(&refresh_token_value);
        
        // Calcula a expiração do refresh token
        let hours = Self::parse_expiration(&refresh_expiration)?;
        let expires_at = Utc::now() + Duration::hours(hours);
        
        // Cria o objeto RefreshToken
        let refresh_token = RefreshToken {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            token_hash,
            expires_at,
            created_at: Utc::now(),
            revoked: false,
        };
        
        // Salva o refresh token no banco
        Self::save_refresh_token(pool, &refresh_token)?;
        
        // Retorna a resposta de autenticação
        let auth_response = AuthResponse {
            access_token,
            refresh_token: refresh_token_value,
            token_type: "Bearer".to_string(),
            expires_in: hours * 3600, // Converte horas para segundos
            user: user.clone(),
            requires_email_verification: false, // Por padrão não requer verificação de email 📫
        };
        Ok(auth_response)
    }

    /// Generates a unique recovery code for a user and updates the database.
    /// Returns the generated code.
    pub fn generate_and_set_recovery_code(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<String, ApiError> {
        let conn = pool.get()?;

        // 1. Generate the code
        let code_length = 24; // Consider making this configurable
        let recovery_code = Self::generate_recovery_code_internal(code_length);

        // 2. Update the user record - Set expiration to NULL (never expires until used/regenerated)
        let rows_affected = conn.execute(
            "UPDATE users SET recovery_code = ?1, recovery_code_expires_at = NULL, updated_at = ?2 WHERE id = ?3",
            (
                &recovery_code,
                &Utc::now(),
                user_id,
            ),
        )?;

        if rows_affected == 0 {
            error!("Failed to set recovery code for user ID: {}. User not found.", user_id);
            return Err(ApiError::NotFoundError(format!("User not found: {}", user_id)));
        }

        info!("🔑 Recovery code generated and set for user ID: {}", user_id);

        // 3. Return the generated code
        Ok(recovery_code)
    }

    /// Verifies a recovery code and returns the associated user if valid.
    /// Does not consume the code.
    pub fn verify_recovery_code(
        pool: &DbPool,
        recovery_code: &str,
    ) -> Result<User, ApiError> {
        let conn = pool.get()?;

        let user_result = conn.query_row(
            "SELECT id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at, totp_secret, totp_enabled, backup_codes, token_family, recovery_email, hashed_recovery_code, token_family, recovery_email, recovery_code, recovery_code_expires_at
             FROM users
             WHERE recovery_code = ?1",
            [recovery_code],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    email: row.get(1)?,
                    username: row.get(2)?,
                    password_hash: row.get(3)?,
                    first_name: row.get(4)?,
                    last_name: row.get(5)?,
                    is_active: row.get(6)?,
                    is_admin: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                    failed_login_attempts: row.get(10)?,
                    locked_until: row.get(11)?,
                    unlock_token: row.get(12)?,
                    unlock_token_expires_at: row.get(13)?,
                    totp_secret: row.get(14)?,
                    totp_enabled: row.get(15)?,
                    backup_codes: row.get(16)?,
                    token_family: row.get(17)?,
                    recovery_email: row.get(18)?,
                    hashed_recovery_code: row.get(19)?,
                    roles: Vec::new(),
                })
            },
        );

        match user_result {
            Ok(user) => {
                // Optionally, check if the code has an expiration date and if it's expired
                // if let Some(expires_at) = user.recovery_code_expires_at {
                //     if expires_at < Utc::now() {
                //         warn!("🔑 Recovery code expired for user: {}", user.username);
                //         return Err(ApiError::AuthenticationError("Recovery code expired".to_string()));
                //     }
                // }
                info!("✅ Recovery code verified successfully for user: {}", user.username);
                Ok(user)
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                warn!("🔑 Invalid recovery code provided: {}", recovery_code);
                Err(ApiError::AuthenticationError("Invalid recovery code".to_string()))
            }
            Err(e) => {
                error!("❌ Database error verifying recovery code: {}", e);
                Err(ApiError::from(e))
            }
        }
    }

    // Helper function to generate the recovery code string
    fn generate_recovery_code_internal(length: usize) -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
    
    // Método removido pois agora usamos a tabela recovery_emails
} // Fecha o bloco impl AuthService
