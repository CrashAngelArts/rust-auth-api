use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::{
    permission::{CreatePermissionDto, Permission, UpdatePermissionDto},
    role::{CreateRoleDto, Role, UpdateRoleDto},
};
// Usando o nome completo do caminho para evitar confusão com a resolução de módulos
use crate::repositories::rbac_repository::SqliteRbacRepository;
use tracing::{error, info, warn};

/// Serviço para gerenciar Lógica de Negócio de RBAC.
#[derive(Clone)] // Adicionar Clone se o serviço for compartilhado (comum em web frameworks)
pub struct RbacService {
    pool: DbPool,
}

impl RbacService {
    /// Cria uma nova instância do RbacService.
    pub fn new(pool: DbPool) -> Self {
        RbacService { pool }
    }

    // --- Funções de Permissão ---

    /// Cria uma nova permissão.
    pub fn create_permission(&self, dto: CreatePermissionDto) -> Result<Permission, ApiError> {
        info!(name = %dto.name, "Tentando criar nova permissão 📜");
        match SqliteRbacRepository::create_permission(&self.pool, dto) {
            Ok(permission) => {
                info!(id = %permission.id, name = %permission.name, "Permissão criada com sucesso ✅");
                Ok(permission)
            }
            Err(e) => {
                error!("Erro ao criar permissão: {}", e);
                Err(e)
            }
        }
    }

    /// Busca uma permissão pelo seu ID.
    pub fn get_permission_by_id(&self, permission_id: &str) -> Result<Permission, ApiError> {
        info!(id = %permission_id, "Buscando permissão por ID 🆔");
        match SqliteRbacRepository::get_permission_by_id(&self.pool, permission_id) {
            Ok(permission) => Ok(permission),
            Err(ApiError::NotFoundError(msg)) => {
                warn!("{}", msg);
                Err(ApiError::NotFoundError(msg))
            },
            Err(e) => {
                error!("Erro ao buscar permissão por ID {}: {}", permission_id, e);
                Err(e)
            }
        }
    }

    /// Busca uma permissão pelo seu nome.
    pub fn get_permission_by_name(&self, name: &str) -> Result<Permission, ApiError> {
        info!(name = %name, "Buscando permissão por nome 🏷️");
        match SqliteRbacRepository::get_permission_by_name(&self.pool, name) {
             Ok(permission) => Ok(permission),
            Err(ApiError::NotFoundError(msg)) => {
                warn!("{}", msg);
                Err(ApiError::NotFoundError(msg))
            },
            Err(e) => {
                error!("Erro ao buscar permissão por nome {}: {}", name, e);
                Err(e)
            }
        }
    }

    /// Lista todas as permissões.
    pub fn list_permissions(&self) -> Result<Vec<Permission>, ApiError> {
        info!("Listando todas as permissões 📜");
         match SqliteRbacRepository::list_permissions(&self.pool) {
             Ok(permissions) => Ok(permissions),
             Err(e) => {
                error!("Erro ao listar permissões: {}", e);
                Err(e)
             }
        }
    }

    /// Atualiza uma permissão existente.
    pub fn update_permission(&self, permission_id: &str, dto: UpdatePermissionDto) -> Result<Permission, ApiError> {
        info!(id = %permission_id, name = ?dto.name, description = ?dto.description, "Tentando atualizar permissão 🔄");
        let current_permission = self.get_permission_by_id(permission_id)?;

        let name_to_update: String;
        if let Some(new_name) = &dto.name {
             if *new_name != current_permission.name {
                match self.get_permission_by_name(new_name) {
                    Ok(_) => {
                        let err_msg = format!("Erro ao atualizar: Permissão com nome '{}' já existe.", new_name);
                        warn!(err_msg);
                        return Err(ApiError::ConflictError(err_msg));
                    }
                    Err(ApiError::NotFoundError(_)) => { /* Nome disponível */ }
                    Err(e) => return Err(e),
                }
                name_to_update = new_name.clone();
            } else {
                name_to_update = current_permission.name;
            }
        } else {
            name_to_update = current_permission.name;
        }

        let description_to_update: Option<String>;
        if let Some(inner_string) = dto.description {
            description_to_update = Some(inner_string);
        } else {
            description_to_update = current_permission.description;
        }

        match SqliteRbacRepository::update_permission(&self.pool, permission_id, &name_to_update, &description_to_update) {
             Ok(_) => {
                 info!(id = %permission_id, "Permissão atualizada com sucesso. Buscando novamente... ✅");
                 self.get_permission_by_id(permission_id)
             }
             Err(ApiError::NotFoundError(msg)) => {
                 warn!("{}", msg);
                 Err(ApiError::NotFoundError(msg))
             }
             Err(e) => {
                 error!("Erro ao atualizar permissão {}: {}", permission_id, e);
                 Err(e)
             }
        }
    }

    /// Deleta uma permissão.
    pub fn delete_permission(&self, permission_id: &str) -> Result<(), ApiError> {
        info!(id = %permission_id, "Tentando deletar permissão 🗑️");
        match SqliteRbacRepository::delete_permission(&self.pool, permission_id) {
            Ok(0) => {
                let msg = format!("Permissão com ID {} não encontrada para deletar.", permission_id);
                warn!(msg);
                Err(ApiError::NotFoundError(msg))
            }
            Ok(_) => {
                 info!(id = %permission_id, "Permissão deletada com sucesso ✅");
                 Ok(())
            }
             Err(e) => {
                error!("Erro ao deletar permissão {}: {}", permission_id, e);
                Err(e)
            }
        }
    }

    // --- Funções de Papel (Role) ---

    /// Cria um novo papel.
    pub fn create_role(&self, dto: CreateRoleDto) -> Result<Role, ApiError> {
        info!(name = %dto.name, "Tentando criar novo papel 🗂️");
        match SqliteRbacRepository::create_role(&self.pool, dto) {
            Ok(role) => {
                info!(id = %role.id, name = %role.name, "Papel criado com sucesso ✅");
                Ok(role)
            }
            Err(e) => {
                error!("Erro ao criar papel: {}", e);
                Err(e)
            }
        }
    }

    /// Busca um papel pelo seu ID.
    pub fn get_role_by_id(&self, role_id: &str) -> Result<Role, ApiError> {
        info!(id = %role_id, "Buscando papel por ID 🆔");
        match SqliteRbacRepository::get_role_by_id(&self.pool, role_id) {
            Ok(role) => Ok(role),
            Err(ApiError::NotFoundError(msg)) => {
                warn!("{}", msg);
                Err(ApiError::NotFoundError(msg))
            },
            Err(e) => {
                error!("Erro ao buscar papel por ID {}: {}", role_id, e);
                Err(e)
            }
        }
    }

    /// Busca um papel pelo seu nome.
    pub fn get_role_by_name(&self, name: &str) -> Result<Role, ApiError> {
        info!(name = %name, "Buscando papel por nome 🏷️");
        match SqliteRbacRepository::get_role_by_name(&self.pool, name) {
            Ok(role) => Ok(role),
            Err(ApiError::NotFoundError(msg)) => {
                warn!("{}", msg);
                Err(ApiError::NotFoundError(msg))
            },
            Err(e) => {
                error!("Erro ao buscar papel por nome {}: {}", name, e);
                Err(e)
            }
        }
    }

    /// Lista todos os papéis.
    pub fn list_roles(&self) -> Result<Vec<Role>, ApiError> {
        info!("Listando todos os papéis 📜");
        match SqliteRbacRepository::list_roles(&self.pool) {
             Ok(roles) => Ok(roles),
             Err(e) => {
                error!("Erro ao listar papéis: {}", e);
                Err(e)
             }
        }
    }

    /// Atualiza um papel existente.
    pub fn update_role(&self, role_id: &str, dto: UpdateRoleDto) -> Result<(), ApiError> {
        info!(id = %role_id, name = ?dto.name, description = ?dto.description, "Tentando atualizar papel 🔄");
        let current_role = self.get_role_by_id(role_id)?;

        let name_to_update: String;
        if let Some(new_name) = &dto.name {
             if *new_name != current_role.name {
                match self.get_role_by_name(new_name) {
                    Ok(_) => {
                        let err_msg = format!("Erro ao atualizar: Papel com nome '{}' já existe.", new_name);
                        warn!(err_msg);
                        return Err(ApiError::ConflictError(err_msg));
                    }
                    Err(ApiError::NotFoundError(_)) => { /* Nome disponível */ }
                    Err(e) => return Err(e),
                }
                 name_to_update = new_name.clone();
            } else {
                 name_to_update = current_role.name;
            }
        } else {
            name_to_update = current_role.name;
        }

        let description_to_update: Option<String>;
        if let Some(inner_option) = dto.description {
            description_to_update = inner_option;
        } else {
            description_to_update = current_role.description;
        }

        match SqliteRbacRepository::update_role(&self.pool, role_id, &name_to_update, &description_to_update) {
            Ok(_) => {
                info!(id = %role_id, "Papel atualizado com sucesso ✅");
                Ok(())
            }
            Err(ApiError::NotFoundError(msg)) => {
                 warn!("{}", msg);
                 Err(ApiError::NotFoundError(msg))
            }
            Err(e) => {
                error!("Erro ao atualizar papel {}: {}", role_id, e);
                Err(e)
            }
        }
    }

    /// Deleta um papel.
    pub fn delete_role(&self, role_id: &str) -> Result<(), ApiError> {
        info!(id = %role_id, "Tentando deletar papel 🗑️");
        match SqliteRbacRepository::delete_role(&self.pool, role_id) {
            Ok(0) => {
                let msg = format!("Papel com ID {} não encontrado para deletar.", role_id);
                warn!(msg);
                Err(ApiError::NotFoundError(msg))
            }
            Ok(_) => {
                info!(id = %role_id, "Papel deletado com sucesso ✅");
                Ok(())
            }
            Err(e) => {
                error!("Erro ao deletar papel {}: {}", role_id, e);
                Err(e)
            }
        }
    }

    // --- Funções de Associação ---

    /// Associa uma permissão a um papel.
    pub fn assign_permission_to_role(&self, role_id: &str, permission_id: &str) -> Result<(), ApiError> {
        info!(role_id = %role_id, permission_id = %permission_id, "Associando permissão a papel 🔗");
        match SqliteRbacRepository::assign_permission_to_role(&self.pool, role_id, permission_id) {
            Ok(0) => {
                info!("Associação entre Papel {} e Permissão {} já existia.", role_id, permission_id);
                Ok(())
            }
            Ok(_) => {
                info!("Permissão {} associada ao Papel {} com sucesso.", permission_id, role_id);
                Ok(())
            }
            Err(ApiError::NotFoundError(msg)) => {
                warn!("Falha ao associar: {}", msg);
                Err(ApiError::NotFoundError(msg))
            }
            Err(e) => {
                error!("Erro ao associar permissão {} ao papel {}: {}", permission_id, role_id, e);
                Err(e)
            }
        }
    }

    /// Remove a associação entre uma permissão e um papel.
    pub fn revoke_permission_from_role(&self, role_id: &str, permission_id: &str) -> Result<(), ApiError> {
        info!(role_id = %role_id, permission_id = %permission_id, "Revogando permissão de papel 🗑️🔗");
        match SqliteRbacRepository::revoke_permission_from_role(&self.pool, role_id, permission_id) {
            Ok(0) => {
                let msg = format!("Associação entre Papel {} e Permissão {} não encontrada para revogar.", role_id, permission_id);
                warn!(msg);
                Err(ApiError::NotFoundError(msg))
            }
            Ok(_) => {
                info!("Associação entre Papel {} e Permissão {} revogada com sucesso.", role_id, permission_id);
                Ok(())
            }
             Err(e) => {
                error!("Erro ao revogar permissão {} do papel {}: {}", permission_id, role_id, e);
                Err(e)
            }
        }
    }

    /// Lista todas as permissões associadas a um papel específico.
    pub fn get_role_permissions(&self, role_id: &str) -> Result<Vec<Permission>, ApiError> {
         info!(role_id = %role_id, "Listando permissões do papel 📜");
        self.get_role_by_id(role_id)?;

        match SqliteRbacRepository::get_role_permissions(&self.pool, role_id) {
            Ok(permissions) => Ok(permissions),
            Err(e) => {
                 error!("Erro ao listar permissões do papel {}: {}", role_id, e);
                 Err(e)
            }
        }
    }

    /// Associa um papel a um usuário.
    pub fn assign_role_to_user(&self, user_id: &str, role_id: &str) -> Result<(), ApiError> {
        info!(user_id = %user_id, role_id = %role_id, "Associando papel a usuário 👤🎭");
        match SqliteRbacRepository::assign_role_to_user(&self.pool, user_id, role_id) {
             Ok(0) => {
                info!("Associação entre Usuário {} e Papel {} já existia.", user_id, role_id);
                Ok(())
            }
            Ok(_) => {
                info!("Papel {} associado ao Usuário {} com sucesso.", role_id, user_id);
                Ok(())
            }
            Err(ApiError::NotFoundError(msg)) => {
                 warn!("Falha ao associar: {}", msg);
                 Err(ApiError::NotFoundError(msg))
            }
            Err(e) => {
                error!("Erro ao associar papel {} ao usuário {}: {}", role_id, user_id, e);
                Err(e)
            }
        }
    }

    /// Remove a associação entre um usuário e um papel.
    pub fn revoke_role_from_user(&self, user_id: &str, role_id: &str) -> Result<(), ApiError> {
        info!(user_id = %user_id, role_id = %role_id, "Revogando papel de usuário 🗑️👤🎭");
        match SqliteRbacRepository::revoke_role_from_user(&self.pool, user_id, role_id) {
            Ok(0) => {
                 let msg = format!("Associação entre Usuário {} e Papel {} não encontrada para revogar.", user_id, role_id);
                 warn!(msg);
                 Err(ApiError::NotFoundError(msg))
            }
            Ok(_) => {
                info!("Associação entre Usuário {} e Papel {} revogada com sucesso.", user_id, role_id);
                Ok(())
            }
             Err(e) => {
                error!("Erro ao revogar papel {} do usuário {}: {}", role_id, user_id, e);
                Err(e)
            }
        }
    }

    /// Lista todos os papéis associados a um usuário específico.
    pub fn get_user_roles(&self, user_id: &str) -> Result<Vec<Role>, ApiError> {
        info!(user_id = %user_id, "Listando papéis do usuário 🧑‍🤝‍🧑");
        match SqliteRbacRepository::get_user_roles(&self.pool, user_id) {
            Ok(roles) => Ok(roles),
            Err(e) => {
                 error!("Erro ao listar papéis do usuário {}: {}", user_id, e);
                 Err(e)
            }
        }
    }

    /// Verifica se um usuário possui uma permissão específica (através dos papéis associados).
    pub fn check_user_permission(&self, user_id: &str, permission_name: &str) -> Result<bool, ApiError> {
        info!(user_id = %user_id, permission_name = %permission_name, "Verificando permissão do usuário 🤔");
        match SqliteRbacRepository::check_user_permission(&self.pool, user_id, permission_name) {
            Ok(has_permission) => {
                if has_permission {
                     info!("Resultado verificação: Usuário {} TEM a permissão '{}'. ✅", user_id, permission_name);
                } else {
                     info!("Resultado verificação: Usuário {} NÃO TEM a permissão '{}'. ❌", user_id, permission_name);
                }
                Ok(has_permission)
            }
             Err(e) => {
                error!("Erro ao verificar permissão '{}' para usuário {}: {}", permission_name, user_id, e);
                Err(e)
            }
        }
    }
} 