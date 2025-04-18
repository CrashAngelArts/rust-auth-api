use serde::{Deserialize, Serialize};

/// Estratégias de revogação para quando o limite de sessões é atingido
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum RevocationStrategy {
    /// Revoga a sessão mais antiga do usuário
    RevokeOldest,
    
    /// Revoga a sessão menos utilizada recentemente
    RevokeLeastRecentlyUsed,
    
    /// Bloqueia novas sessões, exigindo logout manual pelo usuário
    BlockNew,
    
    /// Revoga todas as sessões existentes e permite apenas a nova sessão
    RevokeAll,
}

impl Default for RevocationStrategy {
    fn default() -> Self {
        RevocationStrategy::RevokeOldest
    }
}

/// Política de limite de sessões ativas por usuário
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLimitPolicy {
    /// Número máximo de sessões simultaneas por usuário
    pub max_sessions_per_user: u32,
    
    /// Estratégia de revogação quando o limite é atingido
    pub revoke_strategy: RevocationStrategy,
    
    /// Se o limite está ativo
    pub is_active: bool,
}

impl Default for SessionLimitPolicy {
    fn default() -> Self {
        SessionLimitPolicy {
            max_sessions_per_user: 5,
            revoke_strategy: RevocationStrategy::default(),
            is_active: true,
        }
    }
}

/// DTO para criar/atualizar uma política de limite de sessões
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionLimitPolicyDto {
    /// Número máximo de sessões simultaneas por usuário
    pub max_sessions_per_user: u32,
    
    /// Estratégia de revogação quando o limite é atingido
    pub revoke_strategy: RevocationStrategy,
    
    /// Se o limite está ativo
    pub is_active: bool,
}

/// Configuração global da política de sessões
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSessionPolicy {
    /// ID único da configuração
    pub id: String,
    
    /// Política de limite de sessões
    pub session_limit: SessionLimitPolicy,
    
    /// Se as políticas de sessão estão ativas globalmente
    pub is_active: bool,
    
    /// Data de última atualização
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Exceção à política global para um usuário específico
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSessionPolicy {
    /// ID único da configuração
    pub id: String,
    
    /// ID do usuário para o qual esta política se aplica
    pub user_id: String,
    
    /// Política de limite de sessões personalizada para este usuário
    pub session_limit: SessionLimitPolicy,
    
    /// Se esta exceção está ativa
    pub is_active: bool,
    
    /// Data de criação
    pub created_at: chrono::DateTime<chrono::Utc>,
    
    /// Data de última atualização
    pub updated_at: chrono::DateTime<chrono::Utc>,
} 