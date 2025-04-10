use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::user::{ChangePasswordDto, CreateUserDto, UpdateUserDto, User, UserResponse};
use crate::utils::password::check_password_strength;
use bcrypt::{hash, verify};
use chrono::Utc;
use log::info;

pub struct UserService;

// Colunas base para buscar um usuário completo
const USER_COLUMNS: &str = "id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at";

impl UserService {
    // Cria um novo usuário
    pub fn create_user(
        pool: &DbPool,
        user_dto: CreateUserDto,
        salt_rounds: u32,
    ) -> Result<User, ApiError> {
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

        // Cria o hash da senha
        let password_hash = hash(user_dto.password, salt_rounds)?;

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
            "INSERT INTO users (id, email, username, password_hash, first_name, last_name, is_active, is_admin, created_at, updated_at, failed_login_attempts, locked_until, unlock_token, unlock_token_expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            (
                &user.id,
                &user.email,
                &user.username,
                &user.password_hash,
                &user.first_name,
                &user.last_name,
                &user.is_active,
                &user.is_admin,
                &user.created_at,
                &user.updated_at,
                &user.failed_login_attempts, // 0
                &user.locked_until,          // None
                &user.unlock_token,          // None
                &user.unlock_token_expires_at, // None
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
                })
            },
        ).map_err(|e| match e {
             rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário com email {} não encontrado", email)),
             _ => ApiError::DatabaseError(e.to_string()),
        })?;

        Ok(user)
    }

    // // Função não utilizada (AuthService usa get_user_by_email_or_username)
    // pub fn get_user_by_username(pool: &DbPool, username: &str) -> Result<User, ApiError> {
    //     let conn = pool.get()?;
    //
    //     let user = conn.query_row(
    //          &format!("SELECT {} FROM users WHERE username = ?1", USER_COLUMNS), // Usar constante de colunas
    //         [username],
    //         |row| {
    //              Ok(User {
    //                 id: row.get(0)?,
    //                 email: row.get(1)?,
    //                 username: row.get(2)?,
    //                 password_hash: row.get(3)?,
    //                 first_name: row.get(4)?,
    //                 last_name: row.get(5)?,
    //                 is_active: row.get(6)?,
    //                 is_admin: row.get(7)?,
    //                 created_at: row.get(8)?,
    //                 updated_at: row.get(9)?,
    //                 failed_login_attempts: row.get(10)?,
    //                 locked_until: row.get(11)?,
    //                 unlock_token: row.get(12)?,
    //                 unlock_token_expires_at: row.get(13)?,
    //             })
    //         },
    //     ).map_err(|e| match e {
    //          rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Usuário com nome de usuário {} não encontrado", username)),
    //          _ => ApiError::DatabaseError(e.to_string()),
    //     })?;
    //
    //     Ok(user)
    // }

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
            "SELECT id, email, username, first_name, last_name, is_active, is_admin, created_at
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

        // Cria o hash da nova senha
        let password_hash = hash(&change_dto.new_password, salt_rounds)?;

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
        let conn = pool.get()?;

        // Obtém o usuário
        let user = Self::get_user_by_id(pool, user_id)?;

         // Verifica a força da nova senha
         // Verifica a força da nova senha
        if let Err(unmet_requirements) = check_password_strength(new_password) {
            let error_message = format!("A nova senha não atende aos requisitos: {}", unmet_requirements.join(", "));
            return Err(ApiError::BadRequestError(error_message));
        }

        // Cria o hash da nova senha
        let password_hash = hash(new_password, salt_rounds)?;

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
        Ok(verify(password, password_hash)?)
    }
}
