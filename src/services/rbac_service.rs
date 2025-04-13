use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::{
    permission::{CreatePermissionDto, Permission, UpdatePermissionDto},
    role::{CreateRoleDto, Role, UpdateRoleDto},
};
use chrono::Utc;
use chrono::DateTime;
use rusqlite::{params, OptionalExtension}; // Importar OptionalExtension
use tracing::{error, info};
 // Importar Uuid

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

    // --- Funções de Papel (Role) ---

    /// Cria um novo papel (role) no sistema.
    pub fn create_role(pool: &DbPool, dto: CreateRoleDto) -> Result<Role, ApiError> {
        let conn = pool.get()?;
        let role = Role::new(dto.name.clone(), dto.description);

        // Verifica se papel com mesmo nome já existe
        let exists: bool = conn.query_row(
            "SELECT 1 FROM roles WHERE name = ?1 LIMIT 1",
            params![&role.name],
            |_| Ok(true),
        ).optional()?
         .is_some();

        if exists {
            error!("🎭 Tentativa de criar papel duplicado: {}", role.name);
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

        info!("🎭 Papel criado: {}", role.name);
        Ok(role)
    }

    /// Busca um papel pelo seu ID.
    pub fn get_role_by_id(pool: &DbPool, role_id: &str) -> Result<Role, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM roles WHERE id = ?1",
            params![role_id],
            |row| {
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
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Papel com ID {} não encontrado.", role_id)),
            rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 error!("🎭 Erro ao fazer parse da data do banco de dados para papel: {:?}", err);
                 ApiError::DatabaseError(format!("Erro ao processar data do papel: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

     /// Busca um papel pelo seu nome único.
     pub fn get_role_by_name(pool: &DbPool, name: &str) -> Result<Role, ApiError> {
        let conn = pool.get()?;
        conn.query_row(
            "SELECT id, name, description, created_at, updated_at FROM roles WHERE name = ?1",
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
                Ok(Role {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    created_at,
                    updated_at,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::NotFoundError(format!("Papel com nome '{}' não encontrado.", name)),
            rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                 error!("🎭 Erro ao fazer parse da data do banco de dados para papel: {:?}", err);
                 ApiError::DatabaseError(format!("Erro ao processar data do papel: {}", err))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })
    }

    /// Lista todos os papéis (sem paginação).
    pub fn list_roles(pool: &DbPool) -> Result<Vec<Role>, ApiError> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare("SELECT id, name, description, created_at, updated_at FROM roles ORDER BY name")?;
        let role_iter = stmt.query_map([], |row| {
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
        })?;

        let roles = role_iter.collect::<Result<Vec<_>, rusqlite::Error>>()
            .map_err(|e| match e { // Mapear o erro da coleção também
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    error!("🎭 Erro ao fazer parse da data do banco de dados durante a listagem de papéis: {:?}", err);
                    ApiError::DatabaseError(format!("Erro ao processar data de um papel: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })?;
        Ok(roles)
    }

    /// Atualiza um papel existente.
    pub fn update_role(pool: &DbPool, role_id: &str, dto: UpdateRoleDto) -> Result<Role, ApiError> {
        let conn = pool.get()?;
        let current_role = Self::get_role_by_id(pool, role_id)?;

        let new_name = dto.name.unwrap_or_else(|| current_role.name.clone());

        // Trata Option<Option<String>> para description
        // None -> não muda
        // Some(None) -> define como NULL no DB
        // Some(Some(value)) -> define como novo valor
        let new_description = match dto.description {
            None => current_role.description, // Não muda
            Some(desc_option) => desc_option, // Define como Some(value) ou None (NULL)
        };

        if new_name != current_role.name {
            let exists: bool = conn.query_row(
                "SELECT 1 FROM roles WHERE name = ?1 AND id != ?2 LIMIT 1",
                params![&new_name, role_id],
                |_| Ok(true),
            ).optional()?.is_some();
            if exists {
                error!("🎭 Tentativa de atualizar papel para nome duplicado: {}", new_name);
                return Err(ApiError::ConflictError(format!("Papel com nome '{}' já existe.", new_name)));
            }
        }

        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE roles SET name = ?1, description = ?2, updated_at = ?3 WHERE id = ?4",
            params![
                new_name,
                new_description,
                now,
                role_id
            ],
        )?;

        info!("🎭 Papel atualizado: {}", role_id);
        Self::get_role_by_id(pool, role_id)
    }

    /// Deleta um papel pelo seu ID.
    /// CUIDADO: Isso removerá o papel de todos os usuários associados devido ao ON DELETE CASCADE.
    pub fn delete_role(pool: &DbPool, role_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let changes = conn.execute("DELETE FROM roles WHERE id = ?1", params![role_id])?;

        if changes == 0 {
            Err(ApiError::NotFoundError(format!("Papel com ID {} não encontrado para deletar.", role_id)))
        } else {
            info!("🗑️ Papel deletado: {}", role_id);
            Ok(())
        }
    }

    // --- Funções de Associação ---

    /// Associa uma permissão a um papel.
    pub fn assign_permission_to_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<(), ApiError> {
        // Opcional: Verificar se role_id e permission_id existem antes de inserir.
        // Por simplicidade e performance, podemos confiar nas constraints FK do DB,
        // mas isso retornaria um erro genérico de DB em vez de NotFound.
        // Para retornar NotFound específico, teríamos que fazer SELECTs antes.
        // Exemplo: Self::get_role_by_id(pool, role_id)?; Self::get_permission_by_id(pool, permission_id)?;

        let conn = pool.get()?;
        match conn.execute(
            "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?1, ?2)",
            params![role_id, permission_id],
        ) {
            Ok(changes) => {
                if changes > 0 {
                    info!("🔗 Permissão {} associada ao Papel {}", permission_id, role_id);
                } else {
                    info!("🔗 Associação entre Papel {} e Permissão {} já existia.", role_id, permission_id);
                }
                Ok(())
            }
            Err(e) => {
                // Se não confiarmos no FK, podemos ter erros diferentes.
                // Se confiarmos, um erro aqui provavelmente é de constraint (ex: ID não existe)
                error!("🎭📄 Erro ao associar permissão {} ao papel {}: {}", permission_id, role_id, e);
                // Mapear erro específico de FK se possível, senão erro genérico.
                // Rusqlite pode retornar Error::SqliteFailure(.., Some(extended_code))
                // extended_code 787 é FOREIGN KEY constraint failed
                if let rusqlite::Error::SqliteFailure(err, _) = &e {
                    if err.extended_code == 787 { // FOREIGN KEY constraint failed
                         // Poderia verificar qual ID não existe, mas é complexo. Retornar um erro genérico.
                         return Err(ApiError::NotFoundError(format!("Papel ID {} ou Permissão ID {} não encontrado.", role_id, permission_id)));
                    }
                }
                Err(ApiError::DatabaseError(format!("Erro ao associar permissão: {}", e)))
            }
        }
    }

    /// Remove a associação entre uma permissão e um papel.
    pub fn revoke_permission_from_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let changes = conn.execute(
            "DELETE FROM role_permissions WHERE role_id = ?1 AND permission_id = ?2",
            params![role_id, permission_id],
        )?;

        if changes == 0 {
            // Isso pode significar que a associação não existia, ou que os IDs não existem.
            // Para ser mais preciso, poderíamos verificar a existência dos IDs antes.
            Err(ApiError::NotFoundError(format!(
                "Associação entre Papel {} e Permissão {} não encontrada para revogar.",
                role_id, permission_id
            )))
        } else {
            info!("🗑️ Associação entre Papel {} e Permissão {} revogada.", role_id, permission_id);
            Ok(())
        }
    }

    /// Lista todas as permissões associadas a um papel específico.
    pub fn get_role_permissions(pool: &DbPool, role_id: &str) -> Result<Vec<Permission>, ApiError> {
         // Primeiro, verificar se o papel existe
        Self::get_role_by_id(pool, role_id)?;

        let conn = pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.name, p.description, p.created_at, p.updated_at 
             FROM permissions p
             JOIN role_permissions rp ON p.id = rp.permission_id
             WHERE rp.role_id = ?1
             ORDER BY p.name" )?;
        
        let permission_iter = stmt.query_map(params![role_id], |row| {
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
            .map_err(|e| match e {
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    error!("📄 Erro ao fazer parse da data de permissão ao buscar permissões do papel {}: {:?}", role_id, err);
                    ApiError::DatabaseError(format!("Erro ao processar data de uma permissão: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })?;
        Ok(permissions)
    }

    /// Associa um papel a um usuário.
    pub fn assign_role_to_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<(), ApiError> {
        // Opcional: Verificar se user_id e role_id existem.
        // Para retornar NotFound específico: 
        // UserService::get_user_by_id(pool, user_id)?; // Precisaria injetar ou acessar UserService
        // Self::get_role_by_id(pool, role_id)?;
        // Por ora, confiaremos na FK constraint do DB.

        let conn = pool.get()?;
        match conn.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
            params![user_id, role_id],
        ) {
            Ok(changes) => {
                if changes > 0 {
                    info!("👤🎭 Papel {} associado ao Usuário {}", role_id, user_id);
                } else {
                    info!("👤🎭 Associação entre Usuário {} e Papel {} já existia.", user_id, role_id);
                }
                Ok(())
            }
            Err(e) => {
                error!("👤🎭 Erro ao associar papel {} ao usuário {}: {}", role_id, user_id, e);
                 if let rusqlite::Error::SqliteFailure(err, _) = &e {
                    if err.extended_code == 787 { // FOREIGN KEY constraint failed
                         return Err(ApiError::NotFoundError(format!("Usuário ID {} ou Papel ID {} não encontrado.", user_id, role_id)));
                    }
                }
                Err(ApiError::DatabaseError(format!("Erro ao associar papel: {}", e)))
            }
        }
    }

    /// Remove a associação entre um usuário e um papel.
    pub fn revoke_role_from_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let changes = conn.execute(
            "DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2",
            params![user_id, role_id],
        )?;

        if changes == 0 {
             Err(ApiError::NotFoundError(format!(
                "Associação entre Usuário {} e Papel {} não encontrada para revogar.",
                user_id, role_id
            )))
        } else {
            info!("🗑️ Associação entre Usuário {} e Papel {} revogada.", user_id, role_id);
            Ok(())
        }
    }

    /// Lista todos os papéis associados a um usuário específico.
    pub fn get_user_roles(pool: &DbPool, user_id: &str) -> Result<Vec<Role>, ApiError> {
        // Opcional: Verificar se o usuário existe primeiro.
        // UserService::get_user_by_id(pool, user_id)?;

        let conn = pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT r.id, r.name, r.description, r.created_at, r.updated_at 
             FROM roles r
             JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_id = ?1
             ORDER BY r.name")?;
        
        let role_iter = stmt.query_map(params![user_id], |row| {
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
        })?;

        let roles = role_iter.collect::<Result<Vec<_>, rusqlite::Error>>()
             .map_err(|e| match e {
                rusqlite::Error::FromSqlConversionFailure(_, _, err) => {
                    error!("🎭 Erro ao fazer parse da data de papel ao buscar papéis do usuário {}: {:?}", user_id, err);
                    ApiError::DatabaseError(format!("Erro ao processar data de um papel: {}", err))
                }
                _ => ApiError::DatabaseError(e.to_string()),
            })?;
        Ok(roles)
    }

    /// Verifica se um usuário possui uma permissão específica (através dos papéis associados).
    pub fn check_user_permission(pool: &DbPool, user_id: &str, permission_name: &str) -> Result<bool, ApiError> {
        // Opcional: Verificar se usuário e permissão existem.
        // UserService::get_user_by_id(pool, user_id)?;
        // Self::get_permission_by_name(pool, permission_name)?;

        let conn = pool.get()?;

        // A consulta verifica se existe ALGUMA linha que conecte o user_id à permission_name
        // através das tabelas de junção user_roles e role_permissions.
        let has_permission: bool = conn.query_row(
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
        )?;

        if has_permission {
             info!("✅ Verificação de permissão: Usuário {} TEM a permissão '{}'.", user_id, permission_name);
        } else {
             info!("❌ Verificação de permissão: Usuário {} NÃO TEM a permissão '{}'.", user_id, permission_name);
        }

        Ok(has_permission)
        // Em caso de erro na query (ex: problema de conexão), o ? propagará o ApiError::DatabaseError.
    }

} 