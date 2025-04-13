use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::{
    permission::{CreatePermissionDto, Permission},
    role::{CreateRoleDto, Role},
    // permission::{CreatePermissionDto, Permission, UpdatePermissionDto}, // Linha original comentada
};
use r2d2_sqlite::rusqlite::{params, OptionalExtension};
use chrono::{DateTime, Utc};
// use tracing::{error, info}; // Remover
// use uuid::Uuid; // Remover

// Estrutura do Repositório
pub struct SqliteRbacRepository;

impl SqliteRbacRepository {
    // --- Funções de Permissão ---

    /// Cria uma nova permissão no banco de dados.
    pub fn create_permission(pool: &DbPool, dto: CreatePermissionDto) -> Result<Permission, ApiError> {
        let conn = pool.get()?;
        // Gerar a permissão completa aqui, incluindo ID e timestamps
        let permission = Permission::new(dto.name.clone(), dto.description);

        // Verifica se permissão com mesmo nome já existe
        let exists: bool = conn.query_row(
            "SELECT 1 FROM permissions WHERE name = ?1 LIMIT 1",
            params![&permission.name],
            |_| Ok(true),
        ).optional()? // Usa optional() para não dar erro se não encontrar
         .is_some();

        if exists {
            // Não logar erro aqui, apenas retornar o erro de conflito
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
                &permission.created_at.to_rfc3339(),
                &permission.updated_at.to_rfc3339(),
            ],
        )?;

        // Não logar info aqui, o serviço fará isso se necessário
        Ok(permission) // Retorna a permissão criada
    }

    /// Busca uma permissão pelo seu ID no banco de dados.
    pub fn get_permission_by_id(pool: &DbPool, permission_id: &str) -> Result<Permission, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM permissions WHERE id = ?1",
            params![permission_id],
            Self::map_row_to_permission, // Usar função auxiliar para mapear
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Permissão com ID {} não encontrada.", permission_id)),
            rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 ApiError::DatabaseError(format!("Erro ao processar data da permissão: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

     /// Busca uma permissão pelo seu nome único no banco de dados.
     pub fn get_permission_by_name(pool: &DbPool, name: &str) -> Result<Permission, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM permissions WHERE name = ?1",
            params![name],
            Self::map_row_to_permission, // Usar função auxiliar
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Permissão com nome '{}' não encontrada.", name)),
             rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 ApiError::DatabaseError(format!("Erro ao processar data da permissão: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

    /// Lista todas as permissões do banco de dados.
    pub fn list_permissions(pool: &DbPool) -> Result<Vec<Permission>, ApiError> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare("SELECT id, name, description, created_at, updated_at FROM permissions ORDER BY name")?;
        let permission_iter = stmt.query_map([], Self::map_row_to_permission)?;

        permission_iter.collect::<Result<Vec<_>, rusqlite::Error>>()
            .map_err(|e| match e {
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    ApiError::DatabaseError(format!("Erro ao processar data de uma permissão: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })
    }

    /// Atualiza uma permissão existente no banco de dados.
    pub fn update_permission(
        pool: &DbPool,
        permission_id: &str,
        new_name: &str,
        new_description: &Option<String>,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let now = Utc::now().to_rfc3339();
        let changes = conn.execute(
            "UPDATE permissions SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                new_name,
                new_description,
                now,
                permission_id
            ],
        )?;

        if changes == 0 {
            Err(ApiError::NotFoundError(format!(
                "Permissão com ID {} não encontrada para atualizar.",
                permission_id
            )))
        } else {
            Ok(())
        }
    }

    /// Deleta uma permissão pelo seu ID no banco de dados.
    pub fn delete_permission(pool: &DbPool, permission_id: &str) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        let changes = conn.execute("DELETE FROM permissions WHERE id = ?1", params![permission_id])?;
        // Retorna o número de linhas afetadas (0 ou 1)
        Ok(changes)
    }

    // --- Funções Auxiliares --- 

    /// Mapeia uma linha do banco de dados para a struct Permission.
    fn map_row_to_permission(row: &rusqlite::Row) -> Result<Permission, rusqlite::Error> {
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
    }

    // --- Funções de Papel (Role) ---

    /// Cria um novo papel no banco de dados.
    pub fn create_role(pool: &DbPool, dto: CreateRoleDto) -> Result<Role, ApiError> {
        let conn = pool.get()?;
        let role = Role::new(dto.name.clone(), dto.description);

        // Verifica se papel com mesmo nome já existe
        let exists: bool = conn.query_row(
            "SELECT 1 FROM roles WHERE name = ?1 LIMIT 1",
            params![&role.name],
            |_| Ok(true),
        ).optional()? .is_some();

        if exists {
            return Err(ApiError::ConflictError(format!(
                "Papel com nome '{}' já existe.",
                role.name
            )));
        }

        conn.execute(
            "INSERT INTO roles (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &role.id,
                &role.name,
                &role.description,
                &role.created_at.to_rfc3339(),
                &role.updated_at.to_rfc3339(),
            ],
        )?;

        Ok(role)
    }

    /// Busca um papel pelo seu ID no banco de dados.
    pub fn get_role_by_id(pool: &DbPool, role_id: &str) -> Result<Role, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM roles WHERE id = ?1",
            params![role_id],
            Self::map_row_to_role, // Usar função auxiliar
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Papel com ID {} não encontrado.", role_id)),
            rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 ApiError::DatabaseError(format!("Erro ao processar data do papel: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

    /// Busca um papel pelo seu nome único no banco de dados.
    pub fn get_role_by_name(pool: &DbPool, name: &str) -> Result<Role, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM roles WHERE name = ?1",
            params![name],
            Self::map_row_to_role, // Usar função auxiliar
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Papel com nome '{}' não encontrado.", name)),
            rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 ApiError::DatabaseError(format!("Erro ao processar data do papel: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

    /// Lista todos os papéis do banco de dados.
    pub fn list_roles(pool: &DbPool) -> Result<Vec<Role>, ApiError> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare("SELECT id, name, description, created_at, updated_at FROM roles ORDER BY name")?;
        let role_iter = stmt.query_map([], Self::map_row_to_role)?;

        role_iter.collect::<Result<Vec<_>, rusqlite::Error>>()
            .map_err(|e| match e {
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    ApiError::DatabaseError(format!("Erro ao processar data de um papel: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })
    }

    /// Atualiza um papel existente no banco de dados.
    pub fn update_role(
        pool: &DbPool,
        role_id: &str,
        new_name: &str,
        new_description: &Option<String>,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let now = Utc::now().to_rfc3339();
        let changes = conn.execute(
            "UPDATE roles SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                new_name,
                new_description,
                now,
                role_id
            ],
        )?;

        if changes == 0 {
            Err(ApiError::NotFoundError(format!(
                "Papel com ID {} não encontrado para atualizar.",
                role_id
            )))
        } else {
            Ok(())
        }
    }

    /// Deleta um papel pelo seu ID no banco de dados.
    pub fn delete_role(pool: &DbPool, role_id: &str) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        let changes = conn.execute("DELETE FROM roles WHERE id = ?1", params![role_id])?;
        Ok(changes)
    }

    /// Mapeia uma linha do banco de dados para a struct Role.
    fn map_row_to_role(row: &rusqlite::Row) -> Result<Role, rusqlite::Error> {
        let created_at_str: String = row.get(3)?;
        let updated_at_str: String = row.get(4)?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(3, rusqlite::types::Type::Text, Box::new(e)))?
            .with_timezone(&Utc);
        let updated_at = DateTime::parse_from_rfc3339(&updated_at_str)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e)))?
            .with_timezone(&Utc);
        Ok(Role {
            id: row.get(0)?,
            name: row.get(1)?,
            description: row.get(2)?,
            created_at,
            updated_at,
        })
    }

    // --- Funções de Associação ---

    /// Associa uma permissão a um papel.
    pub fn assign_permission_to_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        conn.execute(
            "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?1, ?2)",
            params![role_id, permission_id],
        ).map_err(|e| {
            // Mapear erro específico de FK, se possível.
            if let rusqlite::Error::SqliteFailure(err, _) = &e {
                if err.extended_code == 787 { // FOREIGN KEY constraint failed
                     return ApiError::NotFoundError(format!("Papel ID {} ou Permissão ID {} não encontrado.", role_id, permission_id));
                }
            }
            ApiError::DatabaseError(format!("Erro ao associar permissão: {}", e))
        })
    }

    /// Remove a associação entre uma permissão e um papel.
    pub fn revoke_permission_from_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        conn.execute(
            "DELETE FROM role_permissions WHERE role_id = ?1 AND permission_id = ?2",
            params![role_id, permission_id],
        ).map_err(ApiError::from)
    }

    /// Lista todas as permissões associadas a um papel específico.
    pub fn get_role_permissions(pool: &DbPool, role_id: &str) -> Result<Vec<Permission>, ApiError> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.name, p.description, p.created_at, p.updated_at 
             FROM permissions p
             JOIN role_permissions rp ON p.id = rp.permission_id
             WHERE rp.role_id = ?1
             ORDER BY p.name" )?;
        
        let permission_iter = stmt.query_map(params![role_id], Self::map_row_to_permission)?;

        permission_iter.collect::<Result<Vec<_>, rusqlite::Error>>()
            .map_err(|e| match e {
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    ApiError::DatabaseError(format!("Erro ao processar data de uma permissão: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })
    }

    /// Associa um papel a um usuário.
    pub fn assign_role_to_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        conn.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
            params![user_id, role_id],
        ).map_err(|e| {
             if let rusqlite::Error::SqliteFailure(err, _) = &e {
                if err.extended_code == 787 { // FOREIGN KEY constraint failed
                     // Assumindo que a tabela users existe e tem FK
                     return ApiError::NotFoundError(format!("Usuário ID {} ou Papel ID {} não encontrado.", user_id, role_id));
                }
            }
            ApiError::DatabaseError(format!("Erro ao associar papel: {}", e))
        })
    }

    /// Remove a associação entre um usuário e um papel.
    pub fn revoke_role_from_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        conn.execute(
            "DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2",
            params![user_id, role_id],
        ).map_err(ApiError::from)
    }

    /// Lista todos os papéis associados a um usuário específico.
    pub fn get_user_roles(pool: &DbPool, user_id: &str) -> Result<Vec<Role>, ApiError> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT r.id, r.name, r.description, r.created_at, r.updated_at 
             FROM roles r
             JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_id = ?1
             ORDER BY r.name")?;
        
        let role_iter = stmt.query_map(params![user_id], Self::map_row_to_role)?;

        role_iter.collect::<Result<Vec<_>, rusqlite::Error>>()
             .map_err(|e| match e {
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    ApiError::DatabaseError(format!("Erro ao processar data de um papel: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })
    }

    /// Verifica se um usuário possui uma permissão específica (através dos papéis associados).
    pub fn check_user_permission(pool: &DbPool, user_id: &str, permission_name: &str) -> Result<bool, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT EXISTS (
                SELECT 1
                FROM user_roles ur
                JOIN role_permissions rp ON ur.role_id = rp.role_id
                JOIN permissions p ON rp.permission_id = p.id
                WHERE ur.user_id = ?1 AND p.name = ?2
                LIMIT 1
            )",
            params![user_id, permission_name],
            |row| row.get(0), // Pega o resultado do EXISTS (0 ou 1)
        ).map_err(ApiError::from)
    }
}
