use crate::config::Config;
use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::{
    AuthLog, AuthResponse, ForgotPasswordDto, LoginDto, PasswordResetToken, RefreshToken,
    RefreshTokenDto, RegisterDto, ResetPasswordDto, Session, TokenClaims, UnlockAccountDto,
};
use crate::models::user::{CreateUserDto, User};
use crate::services::email_service::EmailService;
use crate::services::user_service::UserService;
use chrono::{Duration, Utc};
use hex;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use log::{error, info, warn};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use uuid::Uuid; // Importar Uuid

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

        // 6. Registra a sessão
        Self::create_session(
            pool,
            user.id.clone(),
            ip_address.clone(),
            user_agent.clone(),
            Self::parse_expiration(&config.jwt.expiration)?,
        )?;

        // 7. Registra o evento de login
        Self::log_auth_event(
            pool,
            Some(user.id.clone()),
            "login_success".to_string(),
            ip_address,
            user_agent,
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

        // 9. Cria a resposta
        let auth_response = AuthResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: Self::parse_expiration(&config.jwt.expiration)? * 3600, // Converte horas para segundos
            refresh_token: original_refresh_token, // Retornar o token original para o cliente
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
        // Obtém o usuário pelo email
        let user = match UserService::get_user_by_email(pool, &forgot_dto.email) {
            Ok(user) => user,
            Err(_) => {
                // Não informamos ao cliente se o email existe ou não por segurança
                info!("⚠️ Tentativa de recuperação de senha para email não cadastrado: {}", forgot_dto.email);
                return Ok(());
            }
        };

        // Verifica se o usuário está ativo e não bloqueado (não permitir reset se bloqueado)
        if !user.is_active || user.is_locked() {
            warn!("⚠️ Tentativa de recuperação de senha para conta inativa ou bloqueada: {}", user.email);
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
        email_service.send_password_reset_email(&user, &token.token).await?;

        info!("📧 Email de recuperação de senha enviado para: {}", user.email);
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
        };

        info!("🔄 Token de acesso atualizado para o usuário: {}", user.username);
        Ok(auth_response)
    }

    // Desbloqueia a conta usando o token
    pub fn unlock_account(pool: &DbPool, unlock_dto: UnlockAccountDto) -> Result<(), ApiError> {
        let conn = pool.get()?;

        // 1. Encontra o usuário pelo token de desbloqueio
        let user_result = conn.query_row(
            "SELECT id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at
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
    pub fn validate_token(token: &str, jwt_secret: &str) -> Result<TokenClaims, ApiError> {
        let validation = Validation::default();

        let token_data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &validation,
        )?;

        Ok(token_data.claims)
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
    fn create_session(
        pool: &DbPool,
        user_id: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        duration_hours: i64,
    ) -> Result<Session, ApiError> {
        let conn = pool.get()?;

        // Cria a sessão
        let session = Session::new(user_id, ip_address, user_agent, duration_hours);

        // Insere a sessão no banco de dados
        conn.execute(
            "INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                &session.id,
                &session.user_id,
                &session.token,
                &session.ip_address,
                &session.user_agent,
                &session.expires_at,
                &session.created_at,
            ),
        )?;

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
} // Fecha o bloco impl AuthService
