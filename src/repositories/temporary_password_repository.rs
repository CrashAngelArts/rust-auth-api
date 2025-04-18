use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::temporary_password::TemporaryPassword;
use chrono::Utc;
use rusqlite::{params, OptionalExtension, Row, Error as SqliteError};
use std::sync::Arc;
use tracing::{error, instrument};

/// Mapeia uma linha do banco de dados para a struct TemporaryPassword 💾
fn map_row_to_temporary_password(row: &Row) -> Result<TemporaryPassword, SqliteError> {
    Ok(TemporaryPassword {
        id: row.get("id")?,
        user_id: row.get("user_id")?,
        password_hash: row.get("password_hash")?,
        usage_limit: row.get("usage_limit")?,
        usage_count: row.get("usage_count")?,
        is_active: row.get("is_active")?,
        created_at: row.get("created_at")?,
        last_used_at: row.get("last_used_at")?,
    })
}

/// Repositório para operações com senhas temporárias 🗄️
#[instrument(skip(pool))]
pub async fn create(
    pool: Arc<DbPool>,
    temp_password: &TemporaryPassword,
) -> Result<(), ApiError> {
    let conn = pool.get()?;
    conn.execute(
        "INSERT INTO temporary_passwords (id, user_id, password_hash, usage_limit, usage_count, is_active, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            temp_password.id,
            temp_password.user_id,
            temp_password.password_hash,
            temp_password.usage_limit,
            temp_password.usage_count,
            temp_password.is_active,
            temp_password.created_at,
        ],
    )?;
    Ok(())
}

/// Encontra uma senha temporária ativa para um usuário específico 🟢
#[instrument(skip(pool))]
pub async fn find_active_by_user_id(
    pool: Arc<DbPool>,
    user_id: &str,
) -> Result<Option<TemporaryPassword>, ApiError> {
    let conn = pool.get()?;
    let result = conn.query_row(
        "SELECT * FROM temporary_passwords WHERE user_id = ?1 AND is_active = TRUE LIMIT 1",
        params![user_id],
        map_row_to_temporary_password,
    ).optional()?;
    Ok(result)
}

/// Encontra uma senha temporária inativa pelo hash (para alerta de vazamento) 🔴
#[instrument(skip(pool))]
pub async fn find_inactive_by_user_id_and_hash(
    pool: Arc<DbPool>,
    user_id: &str,
    password_hash: &str,
) -> Result<Option<TemporaryPassword>, ApiError> {
    let conn = pool.get()?;
    let result = conn.query_row(
        "SELECT * FROM temporary_passwords WHERE user_id = ?1 AND password_hash = ?2 AND is_active = FALSE LIMIT 1",
        params![user_id, password_hash],
        map_row_to_temporary_password,
    ).optional()?;
    Ok(result)
}

/// Incrementa a contagem de uso e desativa a senha se o limite for atingido 📈
#[instrument(skip(pool))]
pub async fn increment_usage_and_maybe_deactivate(
    pool: Arc<DbPool>,
    temp_password_id: &str,
) -> Result<TemporaryPassword, ApiError> {
    let mut conn = pool.get()?;
    // Usamos uma transaction para garantir atomicidade
    let tx = conn.transaction()?;

    // 1. Buscar a senha atual para obter o limite e contagem
    let current_password = tx.query_row(
        "SELECT * FROM temporary_passwords WHERE id = ?1 FOR UPDATE", // Bloqueia a linha
        params![temp_password_id],
        map_row_to_temporary_password,
    )?;

    if !current_password.is_active {
        error!("Tentativa de usar senha temporária inativa: {}", temp_password_id);
        // Retorna o estado atual inalterado, mas poderia ser um erro específico
        return Ok(current_password);
    }

    let new_usage_count = current_password.usage_count + 1;
    let should_deactivate = new_usage_count >= current_password.usage_limit;
    let new_last_used_at = Utc::now();

    // 2. Atualizar a contagem, last_used_at e status (se necessário)
    tx.execute(
        "UPDATE temporary_passwords SET usage_count = ?1, is_active = ?2, last_used_at = ?3 WHERE id = ?4",
        params![
            new_usage_count,
            !should_deactivate, // is_active é o oposto de should_deactivate
            new_last_used_at,
            temp_password_id,
        ],
    )?;

    // Commit da transação
    tx.commit()?;

    // Retorna o estado atualizado
    Ok(TemporaryPassword {
        usage_count: new_usage_count,
        is_active: !should_deactivate,
        last_used_at: Some(new_last_used_at),
        ..current_password // Mantém os outros campos
    })
}

/// Deleta a senha temporária ativa de um usuário específico (se existir) ❌
#[instrument(skip(pool))]
pub async fn delete_active_by_user_id(pool: Arc<DbPool>, user_id: &str) -> Result<usize, ApiError> {
    let conn = pool.get()?;
    let rows_affected = conn.execute(
        "DELETE FROM temporary_passwords WHERE user_id = ?1 AND is_active = TRUE",
        params![user_id],
    )?;
    Ok(rows_affected)
}

/// Deleta todas as senhas temporárias de um usuário específico 🗑️
#[instrument(skip(pool))]
pub async fn delete_all_by_user_id(pool: Arc<DbPool>, user_id: &str) -> Result<usize, ApiError> {
    let conn = pool.get()?;
    let rows_affected = conn.execute(
        "DELETE FROM temporary_passwords WHERE user_id = ?1",
        params![user_id],
    )?;
    Ok(rows_affected)
}

// (Opcional) Adicionar funções para interagir com temporary_password_history se implementado. 