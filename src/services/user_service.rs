use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::user::{ChangePasswordDto, CreateUserDto, UpdateUserDto, User, UserResponse};
use crate::utils::password::check_password_strength;
use bcrypt::{hash, verify};
use crate::utils::password_argon2;
use chrono::Utc;
use std::env;
use tracing::info;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

pub struct UserService;

// Colunas base para buscar um usuário completo
pub const USER_COLUMNS: &str = "id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at, totp_secret, totp_enabled, backup_codes, token_family, recovery_email";

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
        ).unwrap_or(false);

        if email_exists {
            return Err(ApiError::ConflictError("Email já está em uso".to_string()));
        }

        // Verifica se o nome de usuário já está em uso
        let username_exists: bool = conn.query_row(
            "SELECT 1 FROM users WHERE username = ?1 LIMIT 1",
            [&user_dto.username],
            |_| Ok(true),
        ).unwrap_or(false);

        if username_exists {
            return Err(ApiError::ConflictError("Nome de usuário já está em uso".to_string()));
        }

        // Verifica a força da senha
        // Verifica a força da senha
        if let Err(unmet_requirements) = check_password_strength(&user_dto.password) {
            let error_message = format!("A senha não atende aos requisitos: {}", unmet_requirements.join(", "));
            return Err(ApiError::BadRequestError(error_message));
        }

        // Cria o hash da senha usando Argon2 ou bcrypt
        let password_hash = if use_argon2 {
            password_argon2::hash_password(&user_dto.password)
                .map_err(|e| ApiError::InternalServerError(e))?
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
            "INSERT INTO users (id, email, username, password_hash, first_name, last_name, is_active, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at, recovery_email)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            (
                &user.id,
                &user.email,
                &user.username,
                &user.password_hash,
                &user.first_name,
                &user.last_name,
                &user.is_active,
                &user.created_at,
                &user.updated_at,
                &user.failed_login_attempts, // 0
                &user.locked_until,          // None
                &user.unlock_token,          // None
                &user.unlock_token_expires_at, // None
                &user.recovery_email,        // Email de recuperação
            ),
        )?;

        info!("✅ Usuário criado com sucesso: {}", user.username);
        Ok(user)
    }

    // Obtém um usuário pelo ID
    pub fn get_user_by_id(pool: &DbPool, user_id: &str) -> Result<User, ApiError> {
        let conn = pool.get()?;

        let user = conn.query_row(
            &format!("SELECT {} FROM users WHERE id = ?1", USER_COLUMNS), // Usar constante de colunas
            [user_id],
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
                    failed_login_attempts: row.get(10)?, // Mapear novo campo
                    locked_until: row.get(11)?,          // Mapear novo campo
                    unlock_token: row.get(12)?,          // Mapear novo campo
                    unlock_token_expires_at: row.get(13)?, // Mapear novo campo
                    totp_secret: row.get(14)?,          // Campo para 2FA
                    totp_enabled: row.get(15)?,         // Campo para 2FA
                    backup_codes: row.get(16)?,         // Campo para 2FA
                    token_family: row.get(17)?,         // Campo para rotação de tokens
                    recovery_email: row.get(18)?,       // Campo para email de recuperação 📧
                    roles: Vec::new(),
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário com ID {} não encontrado", user_id)),
            _ => ApiError::DatabaseError(e.to_string()),
        })?;

        Ok(user)
    }

    // Obtém um usuário pelo email
    pub fn get_user_by_email(pool: &DbPool, email: &str) -> Result<User, ApiError> {
        let conn = pool.get()?;

        let user = conn.query_row(
             &format!("SELECT {} FROM users WHERE email = ?1", USER_COLUMNS), // Usar constante de colunas
            [email],
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
                    recovery_email: row.get(18)?,       // Campo para recuperação de senha
                    roles: Vec::new(),
                })
            },
        ).map_err(|e| match e {
             rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário com email {} não encontrado", email)),
             _ => ApiError::DatabaseError(e.to_string()),
        })?;

        Ok(user)
    }

    // Obtém um usuário pelo email ou nome de usuário
    pub fn get_user_by_email_or_username(pool: &DbPool, username_or_email: &str) -> Result<User, ApiError> {
        let conn = pool.get()?;

        let user = conn.query_row(
             &format!("SELECT {} FROM users WHERE email = ?1 OR username = ?1", USER_COLUMNS), // Usar constante de colunas
            [username_or_email],
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
                    recovery_email: row.get(18)?,       // Campo para recuperação de senha
                    roles: Vec::new(),
                })
            },
        ).map_err(|e| match e {
             rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário com email ou nome de usuário {} não encontrado", username_or_email)),
             _ => ApiError::DatabaseError(e.to_string()),
        })?;

        Ok(user)
    }

    // Lista todos os usuários (não precisa dos campos de bloqueio aqui, usa UserResponse)
    pub fn list_users(pool: &DbPool, page: u64, page_size: u64) -> Result<(Vec<UserResponse>, u64), ApiError> {
        let conn = pool.get()?;

        // Calcula o offset
        let offset = (page.saturating_sub(1)) * page_size; // Usar saturating_sub para evitar underflow

        // Obtém o total de usuários
        let total: u64 = conn.query_row(
            "SELECT COUNT(*) FROM users",
            [],
            |row| row.get(0),
        )?;

        // Obtém os usuários paginados
        let mut stmt = conn.prepare(
            "SELECT id, email, username, first_name, last_name, is_active, is_admin, created_at, recovery_email, updated_at
             FROM users
             ORDER BY created_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;

        let user_iter = stmt.query_map([page_size, offset], |row| {
            Ok(UserResponse {
                id: row.get(0)?,
                email: row.get(1)?,
                username: row.get(2)?,
                first_name: row.get(3)?,
                last_name: row.get(4)?,
                is_active: row.get(5)?,
                is_admin: row.get(6)?,
                created_at: row.get(7)?,
                recovery_email: row.get(8)?,
                updated_at: row.get(9)?,
                roles: None,
            })
        })?;

        let users = user_iter.collect::<Result<Vec<_>, _>>()?;

        Ok((users, total))
    }

    // Atualiza um usuário
    pub fn update_user(pool: &DbPool, user_id: &str, update_dto: UpdateUserDto) -> Result<User, ApiError> {
        let conn = pool.get()?;

        // Verifica se o usuário existe
        let user = Self::get_user_by_id(pool, user_id)?;

        // Verifica se o email já está em uso (se for alterado)
        if let Some(email) = &update_dto.email {
            if email != &user.email {
                let email_exists: bool = conn.query_row(
                    "SELECT 1 FROM users WHERE email = ?1 AND id != ?2 LIMIT 1",
                    [email, user_id],
                    |_| Ok(true),
                ).unwrap_or(false);

                if email_exists {
                    return Err(ApiError::ConflictError("Email já está em uso".to_string()));
                }
            }
        }

        // Verifica se o nome de usuário já está em uso (se for alterado)
        if let Some(username) = &update_dto.username {
            if username != &user.username {
                let username_exists: bool = conn.query_row(
                    "SELECT 1 FROM users WHERE username = ?1 AND id != ?2 LIMIT 1",
                    [username, user_id],
                    |_| Ok(true),
                ).unwrap_or(false);

                if username_exists {
                    return Err(ApiError::ConflictError("Nome de usuário já está em uso".to_string()));
                }
            }
        }

        // Constrói a consulta de atualização
        let mut query = String::from("UPDATE users SET updated_at = ?1");
        let now = Utc::now();
        // Usar Vec<&dyn ToSql> para simplificar a passagem de parâmetros
        let mut params_values: Vec<&dyn rusqlite::ToSql> = vec![&now];

        let mut param_index = 2; // Começa em 2 porque ?1 é updated_at

        // Adiciona campos opcionais à query e aos parâmetros
        macro_rules! add_param {
            ($field:expr, $value:expr) => {
                if let Some(val) = $value {
                    query.push_str(&format!(", {} = ?{}", $field, param_index));
                    params_values.push(val);
                    param_index += 1;
                }
            };
        }

        add_param!("email", update_dto.email.as_ref());
        add_param!("username", update_dto.username.as_ref());
        add_param!("first_name", update_dto.first_name.as_ref());
        add_param!("last_name", update_dto.last_name.as_ref());
        add_param!("is_active", update_dto.is_active.as_ref());
        // Não permitir atualização direta dos campos de bloqueio aqui

        query.push_str(&format!(" WHERE id = ?{}", param_index));
        params_values.push(&user_id);

        // Executa a atualização
        conn.execute(&query, &params_values[..])?;

        // Obtém o usuário atualizado
        Self::get_user_by_id(pool, user_id)
    }

    // Altera a senha de um usuário
    pub fn change_password(
        pool: &DbPool,
        user_id: &str,
        change_dto: ChangePasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> {
        // Verifica se deve usar Argon2 ou bcrypt
        let use_argon2 = env::var("USE_ARGON2")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);
        let conn = pool.get()?;

        // Obtém o usuário
        let user = Self::get_user_by_id(pool, user_id)?;

        // Verifica a senha atual
        if !verify(&change_dto.current_password, &user.password_hash)? {
            return Err(ApiError::AuthenticationError("Senha atual incorreta".to_string()));
        }

         // Verifica a força da nova senha
         // Verifica a força da nova senha
        if let Err(unmet_requirements) = check_password_strength(&change_dto.new_password) {
            let error_message = format!("A nova senha não atende aos requisitos: {}", unmet_requirements.join(", "));
            return Err(ApiError::BadRequestError(error_message));
        }

        // Cria o hash da nova senha usando Argon2 ou bcrypt
        let password_hash = if use_argon2 {
            password_argon2::hash_password(&change_dto.new_password)
                .map_err(|e| ApiError::InternalServerError(e))?
        } else {
            hash(&change_dto.new_password, salt_rounds)?
        };

        // Atualiza a senha
        conn.execute(
            "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
            (&password_hash, Utc::now(), user_id),
        )?;

        info!("🔑 Senha alterada com sucesso para o usuário: {}", user.username);
        Ok(())
    }

    // Atualiza a senha de um usuário (sem verificar a senha atual, usado no reset)
    pub fn update_password(
        pool: &DbPool,
        user_id: &str,
        new_password: &str,
        salt_rounds: u32,
    ) -> Result<(), ApiError> {
        // Verifica se deve usar Argon2 ou bcrypt
        let use_argon2 = env::var("USE_ARGON2")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);
        let conn = pool.get()?;

        // Obtém o usuário
        let user = Self::get_user_by_id(pool, user_id)?;

         // Verifica a força da nova senha
         // Verifica a força da nova senha
        if let Err(unmet_requirements) = check_password_strength(new_password) {
            let error_message = format!("A nova senha não atende aos requisitos: {}", unmet_requirements.join(", "));
            return Err(ApiError::BadRequestError(error_message));
        }

        // Cria o hash da nova senha usando Argon2 ou bcrypt
        let password_hash = if use_argon2 {
            password_argon2::hash_password(new_password)
                .map_err(|e| ApiError::InternalServerError(e))?
        } else {
            hash(new_password, salt_rounds)?
        };

        // Atualiza a senha
        conn.execute(
            "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE id = ?3",
            (&password_hash, Utc::now(), user_id),
        )?;

        info!("🔑 Senha redefinida com sucesso para o usuário: {}", user.username);
        Ok(())
    }

    // Remove um usuário
    pub fn delete_user(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;

        // Verifica se o usuário existe
        let user = Self::get_user_by_id(pool, user_id)?;

        // Remove o usuário
        conn.execute("DELETE FROM users WHERE id = ?1", [user_id])?;

        info!("🗑️ Usuário removido com sucesso: {}", user.username);
        Ok(())
    }

    // Verifica se a senha é válida
    pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, ApiError> {
        // Verifica se o hash é do tipo Argon2
        if password_argon2::is_argon2_hash(password_hash) {
            // Usa verificação Argon2
            password_argon2::verify_password(password, password_hash)
                .map_err(|e| ApiError::InternalServerError(e))
        } else {
            // Usa verificação bcrypt
            Ok(verify(password, password_hash)?)
        }
    }

    // ----- Métodos adicionais para recuperação de senha -----

    // Método para gerar hash da senha
    pub fn hash_password(password: &str, salt_rounds: u32) -> Result<String, ApiError> {
        Ok(hash(password, salt_rounds)?)
    }

    // Gera um código de recuperação único para o usuário
    pub fn generate_recovery_code(
        pool: &DbPool,
        user_id: &str,
        expiration_hours: i64,
    ) -> Result<String, ApiError> {
        let conn = pool.get()?;
        
        // Gerar código alfanumérico único
        let recovery_code: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24) // Código com 24 caracteres
            .map(char::from)
            .collect();
        
        // Calcular data de expiração
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(expiration_hours);
        
        // Salvar o código no banco de dados
        conn.execute(
            "UPDATE users SET 
             recovery_code = ?1,
             recovery_code_expires_at = ?2,
             updated_at = ?3
             WHERE id = ?4",
            (
                &recovery_code,
                &expires_at,
                &now,
                &user_id,
            ),
        )?;
        
        info!("🔑 Código de recuperação gerado para usuário ID {}", user_id);
        
        Ok(recovery_code)
    }

    // Verifica se um código de recuperação é válido
    pub fn verify_recovery_code(
        pool: &DbPool,
        user_id: &str,
        code: &str,
    ) -> Result<bool, ApiError> {
        let conn = pool.get()?;
        
        // Buscar o código e a data de expiração
        let result = conn.query_row(
            "SELECT recovery_code, recovery_code_expires_at 
             FROM users
             WHERE id = ?1",
            [user_id],
            |row| {
                let stored_code: Option<String> = row.get(0)?;
                let expires_at: Option<chrono::DateTime<Utc>> = row.get(1)?;
                Ok((stored_code, expires_at))
            },
        );
        
        match result {
            Ok((Some(stored_code), Some(expires_at))) => {
                // Verificar se o código corresponde e não expirou
                let now = Utc::now();
                if stored_code == code && expires_at > now {
                    Ok(true)
                } else if expires_at <= now {
                    info!("🕒 Código de recuperação expirado para usuário ID {}", user_id);
                    Ok(false)
                } else {
                    info!("❌ Código de recuperação inválido para usuário ID {}", user_id);
                    Ok(false)
                }
            },
            Ok(_) => {
                // Código não definido ou data de expiração ausente
                info!("❓ Nenhum código de recuperação definido para usuário ID {}", user_id);
                Ok(false)
            },
            Err(e) => {
                Err(ApiError::DatabaseError(e.to_string()))
            }
        }
    }

    // Limpa o código de recuperação após uso
    pub fn clear_recovery_code(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        conn.execute(
            "UPDATE users SET 
             recovery_code = NULL,
             recovery_code_expires_at = NULL,
             updated_at = ?1
             WHERE id = ?2",
            (
                &Utc::now(),
                &user_id,
            ),
        )?;
        
        info!("🧹 Código de recuperação limpo para usuário ID {}", user_id);
        
        Ok(())
    }
}