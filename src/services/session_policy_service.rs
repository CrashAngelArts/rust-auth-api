use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::session_policy::{GlobalSessionPolicy, RevocationStrategy, SessionLimitPolicy, UserSessionPolicy};
use crate::repositories::session_policy_repository::SessionPolicyRepository;
use tracing::{error, info, warn};

/// Serviço para gerenciar políticas de sessão
pub struct SessionPolicyService;

impl SessionPolicyService {
    /// Inicializa o serviço de política de sessão
    pub fn init(pool: &DbPool) -> Result<(), ApiError> {
        // Criar tabelas necessárias
        SessionPolicyRepository::create_tables(pool)?;
        
        info!("✅ Serviço de política de sessão inicializado");
        
        Ok(())
    }
    
    /// Obtém a política global de sessão
    pub fn get_global_policy(pool: &DbPool) -> Result<GlobalSessionPolicy, ApiError> {
        SessionPolicyRepository::get_global_policy(pool)
    }
    
    /// Atualiza a política global de sessão
    pub fn update_global_policy(pool: &DbPool, policy: &SessionLimitPolicy) -> Result<GlobalSessionPolicy, ApiError> {
        // Validar a política antes de atualizar
        if policy.max_sessions_per_user == 0 {
            return Err(ApiError::BadRequestError("O número máximo de sessões não pode ser zero 🚫".to_string()));
        }
        
        if policy.max_sessions_per_user > 100 {
            return Err(ApiError::BadRequestError("O número máximo de sessões não pode exceder 100 🚫".to_string()));
        }
        
        SessionPolicyRepository::update_global_policy(pool, policy)
    }
    
    /// Obtém a política de sessão para um usuário específico, se existir
    pub fn get_user_policy(pool: &DbPool, user_id: &str) -> Result<Option<UserSessionPolicy>, ApiError> {
        SessionPolicyRepository::get_user_policy(pool, user_id)
    }
    
    /// Cria ou atualiza a política de sessão para um usuário específico
    pub fn set_user_policy(
        pool: &DbPool, 
        user_id: &str, 
        policy: &SessionLimitPolicy
    ) -> Result<UserSessionPolicy, ApiError> {
        // Validar a política
        if policy.max_sessions_per_user == 0 {
            return Err(ApiError::BadRequestError("O número máximo de sessões não pode ser zero 🚫".to_string()));
        }
        
        if policy.max_sessions_per_user > 100 {
            return Err(ApiError::BadRequestError("O número máximo de sessões não pode exceder 100 🚫".to_string()));
        }
        
        SessionPolicyRepository::set_user_policy(pool, user_id, policy)
    }
    
    /// Remove a política específica de um usuário
    pub fn remove_user_policy(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        SessionPolicyRepository::remove_user_policy(pool, user_id)
    }
    
    /// Verifica e aplica a política de limite de sessões durante a criação de uma nova sessão
    pub fn check_and_apply_policy(pool: &DbPool, user_id: &str) -> Result<bool, ApiError> {
        // Verificar se o usuário excedeu o limite
        let has_exceeded = SessionPolicyRepository::has_exceeded_limit(pool, user_id)?;
        
        if has_exceeded {
            // Obter a política efetiva para o usuário
            let policy = SessionPolicyRepository::get_effective_policy(pool, user_id)?;
            
            if policy.is_active {
                if policy.revoke_strategy == RevocationStrategy::BlockNew {
                    // Se a estratégia for bloquear novas sessões, avisar e não permitir
                    warn!("🚫 Nova sessão bloqueada para o usuário {} - limite de {} sessões atingido",
                          user_id, policy.max_sessions_per_user);
                    
                    return Ok(false);
                } else {
                    // Caso contrário, aplicar a estratégia de revogação
                    info!("⚠️ Usuário {} excedeu o limite de sessões. Aplicando estratégia: {:?}", 
                          user_id, policy.revoke_strategy);
                    
                    return SessionPolicyRepository::apply_limit_strategy(pool, user_id);
                }
            }
        }
        
        // Se não excedeu o limite ou a política não está ativa, permitir
        Ok(true)
    }
    
    /// Conta o número de sessões ativas para um usuário
    pub fn count_active_sessions(pool: &DbPool, user_id: &str) -> Result<u32, ApiError> {
        SessionPolicyRepository::count_active_sessions(pool, user_id)
    }
    
    /// Obtém o resumo da política de sessão para um usuário, incluindo dados de uso atual
    pub fn get_policy_summary(pool: &DbPool, user_id: &str) -> Result<SessionPolicySummary, ApiError> {
        let policy = SessionPolicyRepository::get_effective_policy(pool, user_id)?;
        let session_count = SessionPolicyRepository::count_active_sessions(pool, user_id)?;
        let is_custom = SessionPolicyRepository::get_user_policy(pool, user_id)?.is_some();
        
        Ok(SessionPolicySummary {
            max_sessions: policy.max_sessions_per_user,
            current_sessions: session_count,
            revoke_strategy: policy.revoke_strategy,
            is_custom,
            is_active: policy.is_active,
        })
    }
}

/// Resumo da política de sessão de um usuário, incluindo uso atual
#[derive(Debug, serde::Serialize)]
pub struct SessionPolicySummary {
    /// Número máximo de sessões permitidas
    pub max_sessions: u32,
    
    /// Número atual de sessões ativas
    pub current_sessions: u32,
    
    /// Estratégia de revogação quando o limite é atingido
    pub revoke_strategy: RevocationStrategy,
    
    /// Se esta é uma política personalizada ou a global
    pub is_custom: bool,
    
    /// Se a política está ativa
    pub is_active: bool,
} 
