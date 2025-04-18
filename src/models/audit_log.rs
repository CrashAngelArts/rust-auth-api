use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Tipos de ações que podem ser registradas nos logs de auditoria
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AuditAction {
    /// Criação de um recurso
    Create,
    
    /// Leitura/visualização de um recurso
    Read,
    
    /// Atualização de um recurso
    Update,
    
    /// Exclusão de um recurso
    Delete,
    
    /// Login no sistema
    Login,
    
    /// Logout do sistema
    Logout,
    
    /// Bloqueio de recurso/conta
    Lock,
    
    /// Desbloqueio de recurso/conta
    Unlock,
    
    /// Permissão concedida
    GrantPermission,
    
    /// Permissão revogada
    RevokePermission,
    
    /// Execução de ação administrativa
    AdminAction,
    
    /// Operação em massa (bulk)
    BulkOperation,
    
    /// Falha de segurança/tentativa bloqueada
    SecurityFailure,
    
    /// Ação relacionada a configuração
    Configuration,
    
    /// Outros tipos de ações
    Other,
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditAction::Create => write!(f, "Criar 📝"),
            AuditAction::Read => write!(f, "Ler 👁️"),
            AuditAction::Update => write!(f, "Atualizar 🔄"),
            AuditAction::Delete => write!(f, "Excluir 🗑️"),
            AuditAction::Login => write!(f, "Login 🔑"),
            AuditAction::Logout => write!(f, "Logout 👋"),
            AuditAction::Lock => write!(f, "Bloquear 🔒"),
            AuditAction::Unlock => write!(f, "Desbloquear 🔓"),
            AuditAction::GrantPermission => write!(f, "Conceder Permissão ✅"),
            AuditAction::RevokePermission => write!(f, "Revogar Permissão ❌"),
            AuditAction::AdminAction => write!(f, "Ação Administrativa 👨‍💼"),
            AuditAction::BulkOperation => write!(f, "Operação em Massa 📊"),
            AuditAction::SecurityFailure => write!(f, "Falha de Segurança ⚠️"),
            AuditAction::Configuration => write!(f, "Configuração ⚙️"),
            AuditAction::Other => write!(f, "Outra Ação 🔹"),
        }
    }
}

/// Status de conclusão de uma ação auditada
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AuditStatus {
    /// Ação concluída com sucesso
    Success,
    
    /// Ação falhou
    Failure,
    
    /// Ação bloqueada por política de segurança
    Blocked,
    
    /// Ação em andamento
    InProgress,
    
    /// Status desconhecido
    Unknown,
}

impl fmt::Display for AuditStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditStatus::Success => write!(f, "Sucesso ✅"),
            AuditStatus::Failure => write!(f, "Falha ❌"),
            AuditStatus::Blocked => write!(f, "Bloqueado 🚫"),
            AuditStatus::InProgress => write!(f, "Em Andamento ⏳"),
            AuditStatus::Unknown => write!(f, "Desconhecido ❓"),
        }
    }
}

/// Níveis de severidade do log
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum AuditSeverity {
    /// Informação normal
    Info,
    
    /// Aviso - atenção necessária
    Warning,
    
    /// Severidade alta - possível problema de segurança
    High,
    
    /// Crítico - incidente de segurança confirmado
    Critical,
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditSeverity::Info => write!(f, "Informação 📋"),
            AuditSeverity::Warning => write!(f, "Aviso ⚠️"),
            AuditSeverity::High => write!(f, "Alta Severidade 🔥"),
            AuditSeverity::Critical => write!(f, "Crítico 🚨"),
        }
    }
}

/// Critérios para consulta de logs de auditoria
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditLogQuery {
    /// ID do usuário (opcional)
    pub user_id: Option<String>,
    
    /// ID do administrador (opcional)
    pub admin_id: Option<String>,
    
    /// Tipo de ação (opcional)
    pub action: Option<AuditAction>,
    
    /// Tipo de recurso (opcional)
    pub resource_type: Option<String>,
    
    /// ID do recurso (opcional)
    pub resource_id: Option<String>,
    
    /// Status da ação (opcional)
    pub status: Option<AuditStatus>,
    
    /// Severity da ação (opcional)
    pub severity: Option<AuditSeverity>,
    
    /// Data de início (opcional)
    pub from_date: Option<DateTime<Utc>>,
    
    /// Data de término (opcional)
    pub to_date: Option<DateTime<Utc>>,
    
    /// Quantidade de registros a retornar
    #[serde(default = "default_limit")]
    pub limit: usize,
    
    /// Offset para paginação
    #[serde(default)]
    pub offset: usize,
}

/// Valor padrão para limite de registros
fn default_limit() -> usize {
    100
}

impl Default for AuditLogQuery {
    fn default() -> Self {
        AuditLogQuery {
            user_id: None,
            admin_id: None,
            action: None,
            resource_type: None,
            resource_id: None,
            status: None,
            severity: None,
            from_date: None,
            to_date: None,
            limit: default_limit(),
            offset: 0,
        }
    }
}

/// Estrutura de uma entrada de log de auditoria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// ID único da entrada de log
    pub id: String,
    
    /// ID do usuário que realizou a ação (opcional)
    pub user_id: Option<String>,
    
    /// ID do administrador que autorizou/executou a ação (opcional)
    pub admin_id: Option<String>,
    
    /// Tipo da ação realizada
    pub action: AuditAction,
    
    /// Tipo de recurso afetado (ex: "user", "role", "permission")
    pub resource_type: String,
    
    /// ID do recurso afetado (opcional)
    pub resource_id: Option<String>,
    
    /// Timestamp da ação
    pub timestamp: DateTime<Utc>,
    
    /// Endereço IP de origem da ação (opcional)
    pub ip_address: Option<String>,
    
    /// User-Agent do cliente (opcional)
    pub user_agent: Option<String>,
    
    /// Detalhes adicionais em formato JSON (opcional)
    pub details: Option<Value>,
    
    /// Status da ação
    pub status: AuditStatus,
    
    /// Nível de severidade do log
    pub severity: AuditSeverity,
    
    /// Descrição textual da ação para fácil leitura humana
    pub description: Option<String>,
    
    /// ID da sessão relacionada (opcional)
    pub session_id: Option<String>,
}

/// DTO para criar uma nova entrada de log
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAuditLogDto {
    /// ID do usuário que realizou a ação (opcional)
    pub user_id: Option<String>,
    
    /// ID do administrador que autorizou/executou a ação (opcional)
    pub admin_id: Option<String>,
    
    /// Tipo da ação realizada
    pub action: AuditAction,
    
    /// Tipo de recurso afetado (ex: "user", "role", "permission")
    pub resource_type: String,
    
    /// ID do recurso afetado (opcional)
    pub resource_id: Option<String>,
    
    /// Endereço IP de origem da ação (opcional)
    pub ip_address: Option<String>,
    
    /// User-Agent do cliente (opcional)
    pub user_agent: Option<String>,
    
    /// Detalhes adicionais em formato JSON (opcional)
    pub details: Option<Value>,
    
    /// Status da ação (default: Success)
    #[serde(default = "default_status")]
    pub status: AuditStatus,
    
    /// Nível de severidade do log (default: Info)
    #[serde(default = "default_severity")]
    pub severity: AuditSeverity,
    
    /// Descrição textual da ação para fácil leitura humana
    pub description: Option<String>,
    
    /// ID da sessão relacionada (opcional)
    pub session_id: Option<String>,
}

/// Status padrão para novas entradas de log
fn default_status() -> AuditStatus {
    AuditStatus::Success
}

/// Severidade padrão para novas entradas de log
fn default_severity() -> AuditSeverity {
    AuditSeverity::Info
}

impl CreateAuditLogDto {
    /// Cria um novo DTO com valores mínimos necessários
    pub fn new(action: AuditAction, resource_type: &str) -> Self {
        CreateAuditLogDto {
            user_id: None,
            admin_id: None,
            action,
            resource_type: resource_type.to_string(),
            resource_id: None,
            ip_address: None,
            user_agent: None,
            details: None,
            status: default_status(),
            severity: default_severity(),
            description: None,
            session_id: None,
        }
    }
    
    /// Define o ID do usuário
    pub fn with_user_id(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }
    
    /// Define o ID do administrador
    pub fn with_admin_id(mut self, admin_id: &str) -> Self {
        self.admin_id = Some(admin_id.to_string());
        self
    }
    
    /// Define o ID do recurso
    pub fn with_resource_id(mut self, resource_id: &str) -> Self {
        self.resource_id = Some(resource_id.to_string());
        self
    }
    
    /// Define o IP de origem
    pub fn with_ip(mut self, ip: &str) -> Self {
        self.ip_address = Some(ip.to_string());
        self
    }
    
    /// Define o User-Agent
    pub fn with_user_agent(mut self, user_agent: &str) -> Self {
        self.user_agent = Some(user_agent.to_string());
        self
    }
    
    /// Define detalhes adicionais em JSON
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
    
    /// Define o status da ação
    pub fn with_status(mut self, status: AuditStatus) -> Self {
        self.status = status;
        self
    }
    
    /// Define a severidade do log
    pub fn with_severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }
    
    /// Define a descrição da ação
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }
    
    /// Define o ID da sessão
    pub fn with_session_id(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }
} 