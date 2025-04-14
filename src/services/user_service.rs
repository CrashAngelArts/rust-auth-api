use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::user::{ChangePasswordDto, CreateUserDto, UpdateUserDto, User, UserResponse};
use crate::utils::password::check_password_strength;
use bcrypt::{hash, verify};
use crate::utils::password_argon2;
use chrono::{Utc, TimeZone, DateTime};
use std::env;
use std::sync::Arc;
use tracing::{error, info};
use rusqlite::{params, OptionalExtension, Result as SqlResult, Row};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub struct UserService;

// Colunas base para buscar um usuário completo - Atualizado para hashed_recovery_code
// Removido recovery_code_expires_at
pub const USER_COLUMNS: &str = "id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at, totp_secret, totp_enabled, backup_codes, token_family, recovery_email, hashed_recovery_code";

fn map_row_to_user(row: &Row<'_>) -> SqlResult<User> {
    // Helper para converter Option<i64> para Option<DateTime<Utc>>
    let get_datetime = |i: usize| -> SqlResult<Option<DateTime<Utc>>> {
        // Envolver a expressão em Ok() para corresponder ao tipo de retorno esperado
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
}

impl UserService {
    // Cria um novo usuário
    pub fn create_user(
        pool: &DbPool,
        user_dto: CreateUserDto,
        salt_rounds: u32,
    ) -> Result<User, ApiError> {
        // Verifica se deve usar Argon2 ou bcrypt
        let use_argon2 = env::var("USE_ARGON2")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);
        let conn = pool.get()?;

        // Verifica se o email já está em uso
        let email_exists: bool = conn.query_row(
            "SELECT 1 FROM users WHERE email = ?1 LIMIT 1",
            [&user_dto.email],
            |_| Ok(true),
        ).optional()?.is_some();

        if email_exists {
            return Err(ApiError::ConflictError("Email já está em uso 📧".to_string()));
        }

        // Verifica se o nome de usuário já está em uso
        let username_exists: bool = conn.query_row(
            "SELECT 1 FROM users WHERE username = ?1 LIMIT 1",
            [&user_dto.username],
            |_| Ok(true),
        ).optional()?.is_some();

        if username_exists {
            return Err(ApiError::ConflictError("Nome de usuário já está em uso 🧑".to_string()));
        }

        // Verifica a força da senha
        if let Err(unmet_requirements) = check_password_strength(&user_dto.password) {
            let error_message = format!("A senha não atende aos requisitos ❌: {}", unmet_requirements.join(", "));
            return Err(ApiError::BadRequestError(error_message));
        }

        // Cria o hash da senha usando Argon2 ou bcrypt
        let password_hash = if use_argon2 {
            password_argon2::hash_password(&user_dto.password)
                .map_err(|e| ApiError::InternalServerError(format!("Erro ao hashear senha com Argon2: {}", e)))?
        } else {
            hash(user_dto.password, salt_rounds)?
        };

        // Cria o usuário (com valores padrão para os novos campos)
        let user = User::new(
            user_dto.email,
            user_dto.username,
            password_hash,
            user_dto.first_name,
            user_dto.last_name,
        );

        // Insere o usuário no banco de dados (incluindo valores padrão para novos campos)
        conn.execute(
            "INSERT INTO users (id, email, username, password_hash, first_name, last_name, is_active, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at, recovery_email, token_family, totp_enabled, hashed_recovery_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                &user.id,
                &user.email,
                &user.username,
                &user.password_hash,
                &user.first_name,
                &user.last_name,
                &user.is_active,
                user.created_at.timestamp(), // Salvar como timestamp
                user.updated_at.timestamp(), // Salvar como timestamp
                &user.failed_login_attempts, // 0
                user.locked_until.map(|dt| dt.timestamp()), // Salvar como timestamp
                &user.unlock_token,          // None
                user.unlock_token_expires_at.map(|dt| dt.timestamp()), // Salvar como timestamp
                &user_dto.recovery_email,    // Usar o do DTO
                &user.token_family,          // Gerado no User::new
                &user.totp_enabled,          // false
                &user.hashed_recovery_code   // None (inicialmente)
            ],
        )?;

        info!("✅ Usuário criado com sucesso: {}", user.username);
        Ok(user)
    }

    // Obtém um usuário pelo ID
    pub fn get_user_by_id(pool: &DbPool, user_id: &str) -> Result<User, ApiError> {
        let conn = pool.get()?;
        let user = conn.query_row(
            &format!("SELECT {} FROM users WHERE id = ?1", USER_COLUMNS), // Usar constante de colunas atualizada
            [user_id],
            map_row_to_user, // Usar helper de mapeamento
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário com ID {} não encontrado ❓", user_id)),
            _ => ApiError::DatabaseError(format!("Erro ao buscar usuário por ID: {}", e)),
        })?;
        Ok(user)
    }

    // Obtém um usuário pelo email
    pub fn get_user_by_email(pool: &DbPool, email: &str) -> Result<User, ApiError> {
        let conn = pool.get()?;
        let user = conn.query_row(
            &format!("SELECT {} FROM users WHERE email = ?1", USER_COLUMNS), // Usar constante de colunas atualizada
            [email],
            map_row_to_user, // Usar helper de mapeamento
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário com email {} não encontrado ❓", email)),
            _ => ApiError::DatabaseError(format!("Erro ao buscar usuário por email: {}", e)),
        })?;
        Ok(user)
    }

    // Obtém um usuário pelo email ou nome de usuário
    pub fn get_user_by_email_or_username(pool: &DbPool, username_or_email: &str) -> Result<User, ApiError> {
        let conn = pool.get()?;
        let user = conn.query_row(
            &format!("SELECT {} FROM users WHERE email = ?1 OR username = ?1", USER_COLUMNS), // Usar constante atualizada
            [username_or_email],
            map_row_to_user, // Usar helper de mapeamento
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário {} não encontrado ❓", username_or_email)),
            _ => ApiError::DatabaseError(format!("Erro ao buscar usuário: {}", e)),
        })?;
        Ok(user)
    }

    // Lista todos os usuários
    pub fn list_users(pool: &DbPool, page: u64, page_size: u64) -> Result<(Vec<UserResponse>, u64), ApiError> {
        let conn = pool.get()?;
        let offset = (page.saturating_sub(1)) * page_size;

        let total: u64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;

        let mut stmt = conn.prepare(
            // Selecionar colunas necessárias para UserResponse
            "SELECT id, email, username, first_name, last_name, is_active, is_admin, created_at, recovery_email, updated_at
             FROM users
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;

        let user_iter = stmt.query_map(params![page_size, offset], |row| {
            // Mapear diretamente para UserResponse
            Ok(UserResponse {
                id: row.get(0)?,
                email: row.get(1)?,
                username: row.get(2)?,
                first_name: row.get(3)?,
                last_name: row.get(4)?,
                is_active: row.get(5)?,
                is_admin: row.get(6)?,
                created_at: row.get::<_, Option<i64>>(7)?
                    .map(|ts| Utc.timestamp_opt(ts, 0).single()).flatten().unwrap_or_else(|| Utc::now()),
                recovery_email: row.get(8)?,
                updated_at: row.get::<_, Option<i64>>(9)?
                    .map(|ts| Utc.timestamp_opt(ts, 0).single()).flatten().unwrap_or_else(|| Utc::now()),
                roles: None, // Roles não são carregados aqui
            })
        })?;

        let users: Vec<UserResponse> = user_iter.collect::<Result<_, _>>()?;

        Ok((users, total))
    }

    // Atualiza um usuário
    pub fn update_user(pool: &DbPool, user_id: &str, update_dto: UpdateUserDto) -> Result<User, ApiError> {
        let conn = pool.get()?;
        let mut user = Self::get_user_by_id(pool, user_id)?;

        let mut updated = false;

        if let Some(email) = update_dto.email {
            if email != user.email {
                // Verifica se o novo email já existe
                let email_exists: bool = conn.query_row(
                    "SELECT 1 FROM users WHERE email = ?1 AND id != ?2 LIMIT 1",
                    params![&email, &user_id],
                    |_| Ok(true),
                ).optional()?.is_some();
                if email_exists {
                    return Err(ApiError::ConflictError("Novo email já está em uso 📧".to_string()));
                }
                user.email = email;
                updated = true;
            }
        }
        if let Some(username) = update_dto.username {
            if username != user.username {
                 // Verifica se o novo username já existe
                 let username_exists: bool = conn.query_row(
                    "SELECT 1 FROM users WHERE username = ?1 AND id != ?2 LIMIT 1",
                    params![&username, &user_id],
                    |_| Ok(true),
                ).optional()?.is_some();
                 if username_exists {
                    return Err(ApiError::ConflictError("Novo nome de usuário já está em uso 🧑".to_string()));
                }
                user.username = username;
                updated = true;
            }
        }
        if update_dto.first_name != user.first_name {
            user.first_name = update_dto.first_name;
            updated = true;
        }
        if update_dto.last_name != user.last_name {
            user.last_name = update_dto.last_name;
            updated = true;
        }
        if update_dto.recovery_email != user.recovery_email {
            user.recovery_email = update_dto.recovery_email;
            updated = true;
        }
        if let Some(is_active) = update_dto.is_active {
            if is_active != user.is_active {
                user.is_active = is_active;
                updated = true;
            }
        }

        if updated {
            user.updated_at = Utc::now();
            conn.execute(
                "UPDATE users SET email = ?1, username = ?2, first_name = ?3, last_name = ?4, recovery_email = ?5, is_active = ?6, updated_at = ?7 WHERE id = ?8",
                params![
                    &user.email,
                    &user.username,
                    &user.first_name,
                    &user.last_name,
                    &user.recovery_email,
                    &user.is_active,
                    user.updated_at.timestamp(), // Salvar como timestamp
                    &user_id
                ],
            )?;
            info!("✅ Usuário {} atualizado com sucesso", user_id);
        } else {
            info!("ℹ️ Nenhuma atualização necessária para o usuário {}", user_id);
        }

        Ok(user)
    }

    // Muda a senha do usuário (verifica a senha atual)
    pub fn change_password(
        pool: &DbPool,
        user_id: &str,
        change_dto: ChangePasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> {
        let user = Self::get_user_by_id(pool, user_id)?;

        // Verifica a senha atual
        if !Self::verify_password(&change_dto.current_password, &user.password_hash)? {
            return Err(ApiError::AuthenticationError("Senha atual incorreta ❌".to_string()));
        }

        // Verifica se a nova senha é diferente da atual
        if Self::verify_password(&change_dto.new_password, &user.password_hash)? {
             return Err(ApiError::BadRequestError("A nova senha deve ser diferente da senha atual 🤷".to_string()));
        }

        // Atualiza a senha
        Self::update_password(pool, user_id, &change_dto.new_password, salt_rounds)
    }

    // Atualiza a senha do usuário (sem verificar a atual - usado para reset)
    pub fn update_password(
        pool: &DbPool,
        user_id: &str,
        new_password: &str,
        salt_rounds: u32,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let use_argon2 = env::var("USE_ARGON2")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        // Verifica a força da nova senha
        if let Err(unmet_requirements) = check_password_strength(new_password) {
            let error_message = format!("A nova senha não atende aos requisitos ❌: {}", unmet_requirements.join(", "));
            return Err(ApiError::BadRequestError(error_message));
        }

        // Cria o hash da nova senha
        let new_password_hash = if use_argon2 {
            password_argon2::hash_password(new_password)
                .map_err(|e| ApiError::InternalServerError(format!("Erro ao hashear nova senha com Argon2: {}", e)))?
        } else {
            hash(new_password, salt_rounds)?
        };

        let now_ts = Utc::now().timestamp();

        // Atualiza o hash da senha e a data de atualização no banco
        conn.execute(
            "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
            params![new_password_hash, now_ts, user_id],
        )?;

        info!("🔑 Senha do usuário {} atualizada com sucesso", user_id);
        Ok(())
    }

    // Deleta um usuário
    pub fn delete_user(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let changes = conn.execute("DELETE FROM users WHERE id = ?1", [user_id])?;
        if changes == 0 {
            Err(ApiError::NotFoundError(format!("Usuário {} não encontrado para exclusão ❓", user_id)))
        } else {
            info!("🗑️ Usuário {} deletado com sucesso", user_id);
            Ok(())
        }
    }

    // Verifica a senha
    pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, ApiError> {
        // Tenta verificar com Argon2 primeiro, se falhar, tenta com bcrypt
        if password_argon2::is_argon2_hash(password_hash) {
             match password_argon2::verify_password(password, password_hash) {
                 Ok(valid) => Ok(valid),
                 Err(e) => {
                    error!("Erro ao verificar senha com Argon2: {}", e);
                    // Não retorna erro aqui, pois pode ser um hash bcrypt
                    Ok(false)
                 }
             }
        } else {
            // Assumir que é bcrypt se não for Argon2
            match verify(password, password_hash) {
                Ok(valid) => Ok(valid),
                Err(bcrypt::BcryptError::InvalidHash(_)) => {
                    // Se o hash não é válido nem Argon2 nem bcrypt
                    error!("Hash de senha inválido ou não suportado: {}", password_hash);
                    Err(ApiError::InternalServerError("Formato de hash de senha inválido ou não suportado 🤔".to_string()))
                },
                Err(e) => {
                    // Outros erros de bcrypt (ex: custo inválido)
                    error!("Erro ao verificar senha com bcrypt: {}", e);
                    Err(ApiError::InternalServerError("Erro interno ao verificar senha 🤯".to_string()))
                }
            }
        }
    }

    // --- Funções para Código Único de Recuperação --- //

    /// Gera um novo código de recuperação persistente, faz o hash e o salva no banco.
    /// Retorna o código original em texto plano (para ser exibido ao usuário APENAS uma vez).
    pub fn generate_and_set_recovery_code(pool: Arc<DbPool>, user_id: &str) -> Result<String, ApiError> {
        let conn = pool.get()?;

        // Gerar código aleatório seguro (24 caracteres)
        let recovery_code: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();

        // Hash do código usando Argon2
        let hashed_code = password_argon2::hash_password(&recovery_code)
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao hashear código de recuperação: {}", e)))?;

        let now_ts = Utc::now().timestamp();

        // Atualizar o banco de dados com o HASH do código
        let changes = conn.execute(
            "UPDATE users SET hashed_recovery_code = ?1, updated_at = ?2 WHERE id = ?3",
            params![hashed_code, now_ts, user_id],
        )?;

        if changes == 0 {
            return Err(ApiError::NotFoundError(format!("Usuário {} não encontrado para definir código de recuperação ❓", user_id)));
        }

        info!("🔑 Código de recuperação gerado e definido para o usuário {}", user_id);
        // Retorna o código original EM TEXTO PLANO - exibir ao usuário e instruir a guardar!
        Ok(recovery_code)
    }

    /// Verifica se o código de recuperação fornecido corresponde ao hash armazenado.
    pub fn verify_recovery_code(pool: Arc<DbPool>, user_id: &str, provided_code: &str) -> Result<bool, ApiError> {
        let user = Self::get_user_by_id(&pool, user_id)?;

        match user.hashed_recovery_code {
            Some(ref hashed_code) => {
                // Verificar usando Argon2
                password_argon2::verify_password(provided_code, hashed_code)
                    .map_err(|e| ApiError::InternalServerError(format!("Erro ao verificar código de recuperação: {}", e)))
            }
            None => {
                // Nenhum código de recuperação definido para este usuário
                Ok(false)
            }
        }
    }

    /// Limpa (remove) o código de recuperação do usuário.
    pub fn clear_recovery_code(pool: Arc<DbPool>, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let now_ts = Utc::now().timestamp();

        let changes = conn.execute(
            "UPDATE users SET hashed_recovery_code = NULL, updated_at = ?1 WHERE id = ?2",
            params![now_ts, user_id],
        )?;

        if changes == 0 {
            return Err(ApiError::NotFoundError(format!("Usuário {} não encontrado para limpar código de recuperação ❓", user_id)));
        }

        info!("🗑️ Código de recuperação limpo para o usuário {}", user_id);
        Ok(())
    }
}
