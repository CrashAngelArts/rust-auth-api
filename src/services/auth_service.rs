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
use chrono::{Duration, Utc};
use hex;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use tracing::{error, info, warn};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use uuid::Uuid; // Importar Uuid
use moka::future::Cache; // Importar Moka Cache

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
            // Usar BadRequestError ou criar uma variante específica seria melhor
            return Err(ApiError::ValidationError(std::collections::HashMap::new()));
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
        let conn = pool.get()?;

        // Obtém o usuário pelo email ou nome de usuário
        let mut user = UserService::get_user_by_email_or_username(pool, &login_dto.username_or_email)
            .map_err(|_| ApiError::AuthenticationError("Credenciais inválidas".to_string()))?;

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

        // 3. Verifica a senha
        if !UserService::verify_password(&login_dto.password, &user.password_hash)? {
            // Senha incorreta - Incrementar tentativas e potencialmente bloquear
            user.failed_login_attempts += 1;
            warn!(
                "🔑 Falha de login (tentativa {}/{}): {}",
                user.failed_login_attempts, config.security.max_login_attempts, user.username
            );

            let mut should_lock = false;
            if user.failed_login_attempts >= config.security.max_login_attempts as i32 {
                // Bloquear conta
                should_lock = true;
                let now = Utc::now();
                let lockout_duration = Duration::seconds(config.security.lockout_duration_seconds as i64);
                user.locked_until = Some(now + lockout_duration);

                // Gerar token de desbloqueio
                let token: String = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(32) // Tamanho do token
                    .map(char::from)
                    .collect();
                user.unlock_token = Some(token.clone());
                let token_duration = Duration::minutes(config.security.unlock_token_duration_minutes as i64);
                user.unlock_token_expires_at = Some(now + token_duration);

                warn!("🚫 Conta bloqueada por excesso de tentativas: {}", user.username);

                // Enviar email de desbloqueio (ignorar erro de email para não impedir o bloqueio)
                if config.email.enabled {
                    match email_service.send_account_unlock_email(&user, &token).await {
                        Ok(_) => info!("📧 Email de desbloqueio enviado para: {}", user.email),
                        Err(e) => error!("❌ Falha ao enviar email de desbloqueio para {}: {}", user.email, e),
                    }
                } else {
                     warn!("📧 Envio de email desabilitado. Não foi possível enviar email de desbloqueio para {}", user.email);
                }
            }

            // Atualizar usuário no banco de dados (tentativas ou bloqueio)
            conn.execute(
                "UPDATE users SET failed_login_attempts = ?1, locked_until = ?2, unlock_token = ?3, unlock_token_expires_at = ?4, updated_at = ?5 WHERE id = ?6",
                (
                    &user.failed_login_attempts,
                    &user.locked_until,
                    &user.unlock_token,
                    &user.unlock_token_expires_at,
                    &Utc::now(),
                    &user.id,
                ),
            )?;

             Self::log_auth_event(
                pool,
                Some(user.id.clone()),
                if should_lock { "login_failed_locked".to_string() } else { "login_failed_password".to_string() },
                ip_address.clone(),
                user_agent.clone(),
                Some(if should_lock {
                    format!("Conta bloqueada após {} tentativas.", user.failed_login_attempts)
                } else {
                    format!("Senha incorreta (tentativa {}).", user.failed_login_attempts)
                }),
            )?;

            // Retornar erro apropriado
            if should_lock {
                 let locked_until_str = user.locked_until.map_or("N/A".to_string(), |t| t.to_rfc3339());
                 let message = format!("Conta bloqueada até {}. Verifique seu email para instruções de desbloqueio.", locked_until_str);
                 return Err(ApiError::AccountLockedError(message));
            } else {
                 return Err(ApiError::AuthenticationError("Credenciais inválidas".to_string()));
            }
        }

        // 4. Login bem-sucedido - Resetar estado de bloqueio/tentativas
        if user.failed_login_attempts > 0 || user.locked_until.is_some() {
            user.failed_login_attempts = 0;
            user.locked_until = None;
            user.unlock_token = None;
            user.unlock_token_expires_at = None;
            conn.execute(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, unlock_token = NULL, unlock_token_expires_at = NULL, updated_at = ?1 WHERE id = ?2",
                (&Utc::now(), &user.id),
            )?;
            info!("🔓 Estado de bloqueio resetado para o usuário: {}", user.username);
        }

        // 5. Gera o token JWT
        let token = Self::generate_jwt(&user, &config.jwt.secret, &config.jwt.expiration)?;

        // Criar sessão com informações de dispositivo
        let _session = DeviceService::create_session_with_device_info(
            pool,
            &user.id,
            &ip_address,
            &user_agent,
            24, // Duração da sessão em horas
        )?;

        // 7. Registra o evento de login
        Self::log_auth_event(
            pool,
            Some(user.id.clone()),
            "login_success".to_string(),
            ip_address.clone(),
            user_agent.clone(),
            None,
        )?;

        // 8. Gera o refresh token (valor original e hash)
        let original_refresh_token = Uuid::new_v4().to_string(); // Gerar token original
        let refresh_token_hash = Self::hash_token(&original_refresh_token); // Calcular hash
        let mut refresh_token_db = RefreshToken::new(user.id.clone(), config.jwt.refresh_expiration_days);
        refresh_token_db.token_hash = refresh_token_hash; // Armazenar o hash

        // TODO: Opcional: Revogar tokens antigos antes de salvar o novo
        // Self::revoke_all_user_refresh_tokens(pool, &user.id)?;
        Self::save_refresh_token(pool, &refresh_token_db)?; // Salvar o token com hash no DB

        // 9. Gera e envia código de verificação por email
        let requires_email_verification = config.security.email_verification_enabled;
        
        if requires_email_verification {
            // Importar o serviço de verificação por email
            use crate::services::email_verification_service::EmailVerificationService;
            
            // Gerar e enviar código de verificação
            match EmailVerificationService::generate_and_send_code(
                pool,
                &user,
                ip_address.clone(),
                user_agent.clone(),
                email_service,
                15, // 15 minutos de expiração
            ).await {
                Ok(_) => info!("📧 Código de verificação enviado para: {}", user.email),
                Err(e) => error!("❌ Falha ao enviar código de verificação para {}: {}", user.email, e),
            }
        }
        
        // 10. Cria a resposta
        let auth_response = AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: Self::parse_expiration(&config.jwt.expiration)? * 3600, // Converte horas para segundos
            refresh_token: original_refresh_token, // Retornar o token original para o cliente
            requires_email_verification: requires_email_verification, // Indica se o login requer verificação por email 📫
            user: user.clone(), // Adicionar o usuário na resposta 👤
        };

        info!("✅ Login bem-sucedido para o usuário: {}", user.username);
        Ok(auth_response)
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

    // Redefine a senha
    pub fn reset_password(
        pool: &DbPool,
        reset_dto: ResetPasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> {
        // Verifica se as senhas coincidem
        if reset_dto.password != reset_dto.confirm_password {
            // Usar BadRequestError ou criar uma variante específica seria melhor
            return Err(ApiError::ValidationError(std::collections::HashMap::new()));
        }

        // Obtém o token de recuperação
        let conn = pool.get()?;

        let token_result = conn.query_row(
            "SELECT id, user_id, token, expires_at, created_at
             FROM password_reset_tokens
             WHERE token = ?1",
            [&reset_dto.token],
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

        let token = match token_result {
            Ok(token) => token,
            Err(_) => {
                // Usar AuthenticationError ou NotFoundError seria mais apropriado
                return Err(ApiError::ValidationError(std::collections::HashMap::new()));
            }
        };

        // Verifica se o token está expirado
        if token.is_expired() {
            // Remove o token expirado
            conn.execute("DELETE FROM password_reset_tokens WHERE id = ?1", [&token.id])?;

            // Usar AuthenticationError seria mais apropriado
            return Err(ApiError::ValidationError(std::collections::HashMap::new()));
        }

        // Obtém o usuário
        let user = UserService::get_user_by_id(pool, &token.user_id)?;

        // Atualiza a senha
        UserService::update_password(pool, &user.id, &reset_dto.password, salt_rounds)?;

        // Remove o token usado
        conn.execute("DELETE FROM password_reset_tokens WHERE id = ?1", [&token.id])?;

        // Invalida todas as sessões do usuário
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1",
            [&user.id],
        )?;

        // Revoga todos os refresh tokens do usuário
        Self::revoke_all_user_refresh_tokens(pool, &user.id)?;

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
            "SELECT id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at, totp_secret, totp_enabled, backup_codes, token_family, recovery_email
             FROM users
             WHERE unlock_token = ?1",
            [&unlock_dto.token],
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
                    totp_secret: row.get(14)?,          // Campo para 2FA
                    totp_enabled: row.get(15)?,         // Campo para 2FA
                    backup_codes: row.get(16)?,         // Campo para 2FA
                    token_family: row.get(17)?,         // Campo para rotação de tokens
                    recovery_email: row.get(18)?,       // Campo para email de recuperação
                })
            },
        );

        let mut user = match user_result {
            Ok(user) => user,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                warn!("🔓 Tentativa de desbloqueio com token inválido: {}", unlock_dto.token);
                // Usar AuthenticationError ou NotFoundError
                return Err(ApiError::ValidationError(std::collections::HashMap::new()));
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
                 return Err(ApiError::ValidationError(std::collections::HashMap::new()));
            }
        } else {
            // Se não há data de expiração, mas há token, algo está errado. Considerar inválido.
             warn!("🔓 Token de desbloqueio sem data de expiração para: {}", user.username);
             // Usar AuthenticationError
             return Err(ApiError::ValidationError(std::collections::HashMap::new()));
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
        cache: &Cache<String, TokenClaims> // Adicionar parâmetro do cache
    ) -> Result<TokenClaims, ApiError> {
        // 1. Verificar cache primeiro
        if let Some(claims) = cache.get(token).await { // Usar .await
            info!("✅ Token validado via cache");
            return Ok(claims);
        }

        // 2. Se não estiver no cache, decodificar e validar
        let decoding_key = DecodingKey::from_secret(jwt_secret.as_bytes());
        let validation = Validation::default(); // TODO: Adicionar validação de audiência/issuer se necessário

        // Decodifica o token
        let token_data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                warn!("🔒 Falha na decodificação do token: {}", e);
                ApiError::AuthenticationError(format!("Falha na decodificação: {}", e)) // Usar AuthenticationError
            })?;

        // TODO: Verificar se o token está na blacklist aqui
        // Exemplo: if is_token_blacklisted(pool, &token_data.claims.jti).await { return Err(...) }

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

        let claims = TokenClaims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            exp,
            iat,
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
    
    // Método removido pois agora usamos a tabela recovery_emails
} // Fecha o bloco impl AuthService
