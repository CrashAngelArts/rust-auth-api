use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::session_policy::{GlobalSessionPolicy, SessionLimitPolicy, UserSessionPolicy};
use chrono::Utc;
use rusqlite::{params, Error as SqliteError, ErrorCode};
use tracing::{error, info};
use uuid::Uuid;

/// Repositório para gerenciar políticas de sessão
pub struct SessionPolicyRepository;

impl SessionPolicyRepository {
    /// Cria as tabelas necessárias para o repositório, se não existirem
    pub fn create_tables(pool: &DbPool) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Tabela para política global
        conn.execute(
            "CREATE TABLE IF NOT EXISTS global_session_policy (
                id TEXT PRIMARY KEY,
                max_sessions_per_user INTEGER NOT NULL,
                revoke_strategy TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;
        
        // Tabela para exceções de usuários
        conn.execute(
            "CREATE TABLE IF NOT EXISTS user_session_policy (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                max_sessions_per_user INTEGER NOT NULL,
                revoke_strategy TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id)
            )",
            [],
        )?;
        
        info!("🔧 Tabelas de política de sessão criadas ou verificadas");
        
        // Inicializar com uma política global padrão se não existir
        Self::initialize_default_policy(pool)?;
        
        Ok(())
    }
    
    /// Inicializa a política global padrão, se não existir
    fn initialize_default_policy(pool: &DbPool) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Verificar se já existe uma política global
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM global_session_policy", 
            [], 
            |row| row.get(0)
        )?;
        
        if count == 0 {
            // Criar política padrão
            let default_policy = SessionLimitPolicy::default();
            let now = Utc::now();
            
            conn.execute(
                "INSERT INTO global_session_policy (id, max_sessions_per_user, revoke_strategy, is_active, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    Uuid::new_v4().to_string(),
                    default_policy.max_sessions_per_user,
                    format!("{:?}", default_policy.revoke_strategy),
                    default_policy.is_active,
                    now.to_rfc3339()
                ],
            )?;
            
            info!("✅ Política global de sessão padrão inicializada: limite de {} sessões por usuário", 
                  default_policy.max_sessions_per_user);
        }
        
        Ok(())
    }
    
    /// Obtém a política global de sessão
    pub fn get_global_policy(pool: &DbPool) -> Result<GlobalSessionPolicy, ApiError> {
        let conn = pool.get()?;
        
        let policy = conn.query_row(
            "SELECT id, max_sessions_per_user, revoke_strategy, is_active, updated_at
             FROM global_session_policy
             LIMIT 1",
            [],
            |row| {
                let revoke_strategy_str: String = row.get(2)?;
                let revoke_strategy = Self::parse_revocation_strategy(&revoke_strategy_str)
                    .unwrap_or_default();
                
                Ok(GlobalSessionPolicy {
                    id: row.get(0)?,
                    session_limit: SessionLimitPolicy {
                        max_sessions_per_user: row.get(1)?,
                        revoke_strategy,
                        is_active: row.get(3)?,
                    },
                    is_active: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )?;
        
        Ok(policy)
    }
    
    /// Atualiza a política global de sessão
    pub fn update_global_policy(pool: &DbPool, policy: &SessionLimitPolicy) -> Result<GlobalSessionPolicy, ApiError> {
        let conn = pool.get()?;
        let now = Utc::now();
        
        // Atualizar a política global
        conn.execute(
            "UPDATE global_session_policy 
             SET max_sessions_per_user = ?1, 
                 revoke_strategy = ?2, 
                 is_active = ?3, 
                 updated_at = ?4",
            params![
                policy.max_sessions_per_user,
                format!("{:?}", policy.revoke_strategy),
                policy.is_active,
                now.to_rfc3339()
            ],
        )?;
        
        info!("🔄 Política global de sessão atualizada: limite de {} sessões por usuário", 
              policy.max_sessions_per_user);
        
        // Retornar a política atualizada
        Self::get_global_policy(pool)
    }
    
    /// Obtém a política de sessão para um usuário específico
    pub fn get_user_policy(pool: &DbPool, user_id: &str) -> Result<Option<UserSessionPolicy>, ApiError> {
        let conn = pool.get()?;
        
        let result = conn.query_row(
            "SELECT id, max_sessions_per_user, revoke_strategy, is_active, created_at, updated_at
             FROM user_session_policy
             WHERE user_id = ?1",
            [user_id],
            |row| {
                let revoke_strategy_str: String = row.get(2)?;
                let revoke_strategy = Self::parse_revocation_strategy(&revoke_strategy_str)
                    .unwrap_or_default();
                
                Ok(UserSessionPolicy {
                    id: row.get(0)?,
                    user_id: user_id.to_string(),
                    session_limit: SessionLimitPolicy {
                        max_sessions_per_user: row.get(1)?,
                        revoke_strategy,
                        is_active: row.get(3)?,
                    },
                    is_active: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        );
        
        match result {
            Ok(policy) => Ok(Some(policy)),
            Err(SqliteError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ApiError::from(e))
        }
    }
    
    /// Cria ou atualiza a política de sessão para um usuário específico
    pub fn set_user_policy(
        pool: &DbPool, 
        user_id: &str, 
        policy: &SessionLimitPolicy
    ) -> Result<UserSessionPolicy, ApiError> {
        let conn = pool.get()?;
        let now = Utc::now();
        
        // Verificar se o usuário já tem uma política
        let existing_policy = Self::get_user_policy(pool, user_id)?;
        
        if let Some(existing) = existing_policy {
            // Atualizar política existente
            conn.execute(
                "UPDATE user_session_policy 
                 SET max_sessions_per_user = ?1, 
                     revoke_strategy = ?2, 
                     is_active = ?3, 
                     updated_at = ?4
                 WHERE user_id = ?5",
                params![
                    policy.max_sessions_per_user,
                    format!("{:?}", policy.revoke_strategy),
                    policy.is_active,
                    now.to_rfc3339(),
                    user_id
                ],
            )?;
            
            info!("🔄 Política de sessão atualizada para usuário {}: limite de {} sessões", 
                  user_id, policy.max_sessions_per_user);
                  
            Ok(UserSessionPolicy {
                id: existing.id,
                user_id: user_id.to_string(),
                session_limit: policy.clone(),
                is_active: policy.is_active,
                created_at: existing.created_at,
                updated_at: now,
            })
        } else {
            // Criar nova política
            let id = Uuid::new_v4().to_string();
            
            conn.execute(
                "INSERT INTO user_session_policy 
                 (id, user_id, max_sessions_per_user, revoke_strategy, is_active, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    user_id,
                    policy.max_sessions_per_user,
                    format!("{:?}", policy.revoke_strategy),
                    policy.is_active,
                    now.to_rfc3339(),
                    now.to_rfc3339()
                ],
            )?;
            
            info!("✅ Política de sessão criada para usuário {}: limite de {} sessões", 
                  user_id, policy.max_sessions_per_user);
                  
            Ok(UserSessionPolicy {
                id,
                user_id: user_id.to_string(),
                session_limit: policy.clone(),
                is_active: policy.is_active,
                created_at: now,
                updated_at: now,
            })
        }
    }
    
    /// Remove a política específica de um usuário
    pub fn remove_user_policy(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        conn.execute(
            "DELETE FROM user_session_policy WHERE user_id = ?1",
            [user_id],
        )?;
        
        info!("🗑️ Política de sessão removida para usuário {}", user_id);
        
        Ok(())
    }
    
    /// Retorna o limite efetivo de sessões para um usuário, considerando políticas globais e específicas
    pub fn get_effective_policy(pool: &DbPool, user_id: &str) -> Result<SessionLimitPolicy, ApiError> {
        // 1. Tentar obter política específica do usuário
        let user_policy = Self::get_user_policy(pool, user_id)?;
        
        // 2. Se o usuário tiver uma política ativa, usá-la
        if let Some(policy) = user_policy {
            if policy.is_active {
                return Ok(policy.session_limit);
            }
        }
        
        // 3. Caso contrário, usar a política global
        let global_policy = Self::get_global_policy(pool)?;
        
        if global_policy.is_active {
            Ok(global_policy.session_limit)
        } else {
            // Se a política global não estiver ativa, permitir sessões ilimitadas
            Ok(SessionLimitPolicy {
                max_sessions_per_user: u32::MAX,
                revoke_strategy: Default::default(),
                is_active: false,
            })
        }
    }
    
    /// Conta o número de sessões ativas para um usuário
    pub fn count_active_sessions(pool: &DbPool, user_id: &str) -> Result<u32, ApiError> {
        let conn = pool.get()?;
        let now = Utc::now().to_rfc3339();
        
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions 
             WHERE user_id = ?1 AND expires_at > ?2",
            [user_id, &now],
            |row| row.get(0),
        )?;
        
        Ok(count as u32)
    }
    
    /// Verifica se um usuário excedeu o limite de sessões
    pub fn has_exceeded_limit(pool: &DbPool, user_id: &str) -> Result<bool, ApiError> {
        let policy = Self::get_effective_policy(pool, user_id)?;
        
        // Se a política não estiver ativa, não há limite
        if !policy.is_active {
            return Ok(false);
        }
        
        let session_count = Self::count_active_sessions(pool, user_id)?;
        
        Ok(session_count >= policy.max_sessions_per_user)
    }
    
    /// Quando o limite é atingido, aplica a estratégia de revogação configurada
    pub fn apply_limit_strategy(pool: &DbPool, user_id: &str) -> Result<bool, ApiError> {
        let policy = Self::get_effective_policy(pool, user_id)?;
        
        // Se a política não estiver ativa, não fazer nada
        if !policy.is_active {
            return Ok(true); // Permitir sempre
        }
        
        let session_count = Self::count_active_sessions(pool, user_id)?;
        
        // Se ainda não atingiu o limite, não fazer nada
        if session_count < policy.max_sessions_per_user {
            return Ok(true); // Permitir
        }
        
        // Aplicar a estratégia de revogação conforme configurado
        match policy.revoke_strategy {
            crate::models::session_policy::RevocationStrategy::RevokeOldest => {
                Self::revoke_oldest_session(pool, user_id)?;
                Ok(true) // Permitir após revogar a mais antiga
            },
            crate::models::session_policy::RevocationStrategy::RevokeLeastRecentlyUsed => {
                Self::revoke_least_recently_used_session(pool, user_id)?;
                Ok(true) // Permitir após revogar a menos usada
            },
            crate::models::session_policy::RevocationStrategy::BlockNew => {
                Ok(false) // Não permitir novas sessões
            },
            crate::models::session_policy::RevocationStrategy::RevokeAll => {
                Self::revoke_all_sessions(pool, user_id)?;
                Ok(true) // Permitir após revogar todas
            }
        }
    }
    
    /// Revoga a sessão mais antiga de um usuário
    fn revoke_oldest_session(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let now = Utc::now().to_rfc3339();
        
        // Obter a sessão mais antiga
        let oldest_session_id: String = conn.query_row(
            "SELECT id FROM sessions 
             WHERE user_id = ?1 AND expires_at > ?2
             ORDER BY created_at ASC
             LIMIT 1",
            [user_id, &now],
            |row| row.get(0),
        )?;
        
        // Revogar a sessão
        conn.execute(
            "DELETE FROM sessions WHERE id = ?1",
            [&oldest_session_id],
        )?;
        
        info!("🔒 Sessão mais antiga revogada para usuário {} devido ao limite de sessões: {}", 
              user_id, oldest_session_id);
        
        Ok(())
    }
    
    /// Revoga a sessão menos usada recentemente de um usuário
    fn revoke_least_recently_used_session(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let now = Utc::now().to_rfc3339();
        
        // Obter a sessão menos usada recentemente
        let lru_session_id: String = conn.query_row(
            "SELECT id FROM sessions 
             WHERE user_id = ?1 AND expires_at > ?2
             ORDER BY last_active_at ASC
             LIMIT 1",
            [user_id, &now],
            |row| row.get(0),
        )?;
        
        // Revogar a sessão
        conn.execute(
            "DELETE FROM sessions WHERE id = ?1",
            [&lru_session_id],
        )?;
        
        info!("🔒 Sessão menos usada recentemente revogada para usuário {} devido ao limite de sessões: {}", 
              user_id, lru_session_id);
        
        Ok(())
    }
    
    /// Revoga todas as sessões de um usuário
    fn revoke_all_sessions(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Excluir todas as sessões
        let deleted = conn.execute(
            "DELETE FROM sessions WHERE user_id = ?1",
            [user_id],
        )?;
        
        info!("🔒 Todas as {} sessões revogadas para usuário {} devido ao limite de sessões", 
              deleted, user_id);
        
        Ok(())
    }
    
    /// Converte uma string de estratégia de revogação para o enum correspondente
    fn parse_revocation_strategy(strategy_str: &str) -> Result<crate::models::session_policy::RevocationStrategy, ApiError> {
        match strategy_str {
            "RevokeOldest" => Ok(crate::models::session_policy::RevocationStrategy::RevokeOldest),
            "RevokeLeastRecentlyUsed" => Ok(crate::models::session_policy::RevocationStrategy::RevokeLeastRecentlyUsed),
            "BlockNew" => Ok(crate::models::session_policy::RevocationStrategy::BlockNew),
            "RevokeAll" => Ok(crate::models::session_policy::RevocationStrategy::RevokeAll),
            _ => {
                error!("❌ Estratégia de revogação inválida: {}", strategy_str);
                Ok(crate::models::session_policy::RevocationStrategy::default())
            }
        }
    }
} 