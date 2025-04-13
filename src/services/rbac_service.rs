use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::{
    permission::{CreatePermissionDto, Permission, UpdatePermissionDto},
    // role::{CreateRoleDto, Role, UpdateRoleDto}, // Adicionaremos depois
};
use chrono::Utc;
use chrono::DateTime;
use rusqlite::{params, OptionalExtension}; // Importar OptionalExtension
use tracing::{error, info};
use uuid::Uuid; // Importar Uuid

pub struct RbacService;

impl RbacService {
    // --- Funções de Permissão ---

    /// Cria uma nova permissão no sistema.
    pub fn create_permission(pool: &DbPool, dto: CreatePermissionDto) -> Result<Permission, ApiError> {
        let conn = pool.get()?;
        let permission = Permission::new(dto.name.clone(), dto.description);

        // Verifica se permissão com mesmo nome já existe
        let exists: bool = conn.query_row(
            "SELECT 1 FROM permissions WHERE name = ?1 LIMIT 1",
            params![&permission.name],
            |_| Ok(true),
        ).optional()? // Usa optional() para não dar erro se não encontrar
         .is_some();

        if exists {
            error!("Tentativa de criar permissão duplicada: {}", permission.name);
            return Err(ApiError::ConflictError(format!(
                "Permissão com nome '{}' já existe.",
                permission.name
            )));
        }

        conn.execute(
            "INSERT INTO permissions (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &permission.id,
                &permission.name,
                &permission.description,
                &permission.created_at.to_rfc3339(), // Salvar como string RFC3339
                &permission.updated_at.to_rfc3339(), // Salvar como string RFC3339
            ],
        )?;

        info!("📄 Permissão criada: {}", permission.name);
        Ok(permission)
    }

    /// Busca uma permissão pelo seu ID.
    pub fn get_permission_by_id(pool: &DbPool, permission_id: &str) -> Result<Permission, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM permissions WHERE id = ?1",
            params![permission_id],
            |row| {
                // Ler timestamps como string e fazer parse
                let created_at_str: String = row.get(3)?;
                let updated_at_str: String = row.get(4)?;
                let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e)))?
                    .with_timezone(&Utc);
                let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?
                    .with_timezone(&Utc);
                Ok(Permission {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    created_at,
                    updated_at,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Permissão com ID {} não encontrada.", permission_id)),
            rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 // Log do erro original de parse, se necessário
                 error!("Erro ao fazer parse da data do banco de dados: {:?}", err);
                 ApiError::DatabaseError(format!("Erro ao processar data da permissão: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

     /// Busca uma permissão pelo seu nome único.
     pub fn get_permission_by_name(pool: &DbPool, name: &str) -> Result<Permission, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM permissions WHERE name = ?1",
            params![name],
            |row| {
                let created_at_str: String = row.get(3)?;
                let updated_at_str: String = row.get(4)?;
                let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e)))?
                    .with_timezone(&Utc);
                let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?
                    .with_timezone(&Utc);
                Ok(Permission {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    created_at,
                    updated_at,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Permissão com nome '{}' não encontrada.", name)),
             rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 error!("Erro ao fazer parse da data do banco de dados: {:?}", err);
                 ApiError::DatabaseError(format!("Erro ao processar data da permissão: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

    /// Lista todas as permissões (sem paginação por simplicidade inicial).
    pub fn list_permissions(pool: &DbPool) -> Result<Vec<Permission>, ApiError> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare("SELECT id, name, description, created_at, updated_at FROM permissions ORDER BY name")?;
        let permission_iter = stmt.query_map([], |row| {
            let created_at_str: String = row.get(3)?;
            let updated_at_str: String = row.get(4)?;
             let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e)))?
                .with_timezone(&Utc);
            let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?
                .with_timezone(&Utc);
            Ok(Permission {
                 id: row.get(0)?,
                 name: row.get(1)?,
                 description: row.get(2)?,
                 created_at,
                 updated_at,
            })
        })?;

        let permissions = permission_iter.collect::<Result<Vec<_>, rusqlite::Error>>()
            .map_err(|e| match e { // Mapear o erro da coleção também
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    error!("Erro ao fazer parse da data do banco de dados durante a listagem: {:?}", err);
                    ApiError::DatabaseError(format!("Erro ao processar data de uma permissão: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })?;
        Ok(permissions)
    }

    /// Atualiza uma permissão existente.
    pub fn update_permission(pool: &DbPool, permission_id: &str, dto: UpdatePermissionDto) -> Result<Permission, ApiError> {
        let conn = pool.get()?;
        // Verifica se a permissão existe antes de tentar atualizar
        let current_permission = Self::get_permission_by_id(pool, permission_id)?;

        // Clona o nome atual antes de usá-lo em unwrap_or para evitar mover o valor
        let new_name = dto.name.unwrap_or_else(|| current_permission.name.clone());
        let new_description = dto.description; // Permite definir a descrição como None

        // Verifica se o novo nome já existe para outra permissão
        if new_name != current_permission.name {
            let exists: bool = conn.query_row(
                "SELECT 1 FROM permissions WHERE name = ?1 AND id != ?2 LIMIT 1",
                params![&new_name, permission_id],
                |_| Ok(true),
            ).optional()?.is_some();
            if exists {
                error!("Tentativa de atualizar permissão para nome duplicado: {}", new_name);
                return Err(ApiError::ConflictError(format!("Permissão com nome '{}' já existe.", new_name)));
            }
        }

        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE permissions SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                new_name,
                new_description,
                now,
                permission_id
            ],
        )?;

        info!("📄 Permissão atualizada: {}", permission_id);

        // Retorna a permissão atualizada (buscando novamente)
        Self::get_permission_by_id(pool, permission_id)
    }

    /// Deleta uma permissão pelo seu ID.
    /// CUIDADO: Isso removerá a permissão de todos os papéis associados devido ao ON DELETE CASCADE.
    pub fn delete_permission(pool: &DbPool, permission_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let changes = conn.execute("DELETE FROM permissions WHERE id = ?1", params![permission_id])?;

        if changes == 0 {
            Err(ApiError::NotFoundError(format!("Permissão com ID {} não encontrada para deletar.", permission_id)))
        } else {
            info!("🗑️ Permissão deletada: {}", permission_id);
            Ok(())
        }
    }

    // --- Funções de Papel (Role) --- TODO ---
    // TODO: Implementar create_role, get_role_by_id, get_role_by_name, list_roles, update_role, delete_role

    // --- Funções de Associação --- TODO ---
    // TODO: Implementar assign_permission_to_role, revoke_permission_from_role
    // TODO: Implementar assign_role_to_user, revoke_role_from_user
    // TODO: Implementar get_user_roles, get_role_permissions
    // TODO: Implementar check_user_permission (a função principal de verificação)

} 