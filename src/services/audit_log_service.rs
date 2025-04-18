use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::audit_log::{AuditLogEntry, AuditLogQuery, AuditAction, AuditStatus, AuditSeverity, CreateAuditLogDto};
use crate::repositories::audit_log_repository::AuditLogRepository;
use actix_web::HttpRequest;
use serde_json::Value;
use tracing::{info, error};

/// Serviço para gerenciar logs de auditoria
pub struct AuditLogService;

impl AuditLogService {
    /// Inicializa o serviço de logs de auditoria
    pub fn init(pool: &DbPool) -> Result<(), ApiError> {
        // Criar tabelas necessárias
        AuditLogRepository::create_tables(pool)?;
        
        info!("✅ Serviço de logs de auditoria inicializado");
        
        Ok(())
    }
    
    /// Registra uma ação crítica no sistema
    pub fn log_critical_action(
        pool: &DbPool,
        dto: CreateAuditLogDto,
    ) -> Result<AuditLogEntry, ApiError> {
        // Definir a severidade como alta para ações críticas
        let dto = dto.with_severity(AuditSeverity::Critical);
        
        // Registrar a ação
        let log_entry = AuditLogRepository::create(pool, &dto)?;
        
        info!("🔴 Ação crítica registrada: {} [{}] {}", 
              log_entry.action, log_entry.resource_type, log_entry.resource_id.as_deref().unwrap_or("-"));
        
        Ok(log_entry)
    }
    
    /// Registra uma ação de segurança no sistema
    pub fn log_security_action(
        pool: &DbPool,
        dto: CreateAuditLogDto,
    ) -> Result<AuditLogEntry, ApiError> {
        // Definir a severidade como alta para ações de segurança
        let dto = dto.with_severity(AuditSeverity::High);
        
        // Registrar a ação
        let log_entry = AuditLogRepository::create(pool, &dto)?;
        
        info!("🔒 Ação de segurança registrada: {} [{}] {}", 
              log_entry.action, log_entry.resource_type, log_entry.resource_id.as_deref().unwrap_or("-"));
        
        Ok(log_entry)
    }
    
    /// Registra uma ação administrativa no sistema
    pub fn log_admin_action(
        pool: &DbPool,
        admin_id: &str,
        action: AuditAction,
        resource_type: &str,
        resource_id: Option<&str>,
        details: Option<Value>,
        req: Option<&HttpRequest>,
    ) -> Result<AuditLogEntry, ApiError> {
        let mut dto = CreateAuditLogDto::new(action, resource_type)
            .with_admin_id(admin_id)
            .with_severity(AuditSeverity::Warning);
        
        if let Some(res_id) = resource_id {
            dto = dto.with_resource_id(res_id);
        }
        
        if let Some(details_value) = details {
            dto = dto.with_details(details_value);
        }
        
        // Adicionar informações do request se disponível
        if let Some(request) = req {
            if let Some(ip) = request.connection_info().realip_remote_addr() {
                dto = dto.with_ip(ip);
            }
            
            if let Some(user_agent) = request.headers().get("User-Agent") {
                if let Ok(ua_str) = user_agent.to_str() {
                    dto = dto.with_user_agent(ua_str);
                }
            }
        }
        
        // Registrar a ação
        let log_entry = AuditLogRepository::create(pool, &dto)?;
        
        info!("👑 Ação administrativa registrada: {} [{}] {}", 
              log_entry.action, log_entry.resource_type, log_entry.resource_id.as_deref().unwrap_or("-"));
        
        Ok(log_entry)
    }
    
    /// Registra uma ação de usuário no sistema
    pub fn log_user_action(
        pool: &DbPool,
        user_id: &str,
        action: AuditAction,
        resource_type: &str,
        resource_id: Option<&str>,
        details: Option<Value>,
        req: Option<&HttpRequest>,
    ) -> Result<AuditLogEntry, ApiError> {
        let mut dto = CreateAuditLogDto::new(action, resource_type)
            .with_user_id(user_id);
        
        if let Some(res_id) = resource_id {
            dto = dto.with_resource_id(res_id);
        }
        
        if let Some(details_value) = details {
            dto = dto.with_details(details_value);
        }
        
        // Adicionar informações do request se disponível
        if let Some(request) = req {
            if let Some(ip) = request.connection_info().realip_remote_addr() {
                dto = dto.with_ip(ip);
            }
            
            if let Some(user_agent) = request.headers().get("User-Agent") {
                if let Ok(ua_str) = user_agent.to_str() {
                    dto = dto.with_user_agent(ua_str);
                }
            }
        }
        
        // Registrar a ação
        let log_entry = AuditLogRepository::create(pool, &dto)?;
        
        info!("👤 Ação de usuário registrada: {} [{}] {}", 
              log_entry.action, log_entry.resource_type, log_entry.resource_id.as_deref().unwrap_or("-"));
        
        Ok(log_entry)
    }
    
    /// Registra uma falha de segurança no sistema
    pub fn log_security_failure(
        pool: &DbPool,
        user_id: Option<&str>,
        resource_type: &str,
        resource_id: Option<&str>,
        details: Option<Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        description: Option<&str>,
    ) -> Result<AuditLogEntry, ApiError> {
        let mut dto = CreateAuditLogDto::new(AuditAction::SecurityFailure, resource_type)
            .with_status(AuditStatus::Failure)
            .with_severity(AuditSeverity::High);
        
        if let Some(user) = user_id {
            dto = dto.with_user_id(user);
        }
        
        if let Some(res_id) = resource_id {
            dto = dto.with_resource_id(res_id);
        }
        
        if let Some(details_value) = details {
            dto = dto.with_details(details_value);
        }
        
        if let Some(ip) = ip_address {
            dto = dto.with_ip(ip);
        }
        
        if let Some(ua) = user_agent {
            dto = dto.with_user_agent(ua);
        }
        
        if let Some(desc) = description {
            dto = dto.with_description(desc);
        }
        
        // Registrar a falha
        let log_entry = AuditLogRepository::create(pool, &dto)?;
        
        error!("⚠️ Falha de segurança registrada: [{}] {}", 
               log_entry.resource_type, log_entry.resource_id.as_deref().unwrap_or("-"));
        
        Ok(log_entry)
    }
    
    /// Busca logs de auditoria por critérios
    pub fn search_logs(
        pool: &DbPool,
        query: &AuditLogQuery,
    ) -> Result<(Vec<AuditLogEntry>, u64), ApiError> {
        // Buscar logs baseados na query
        let logs = AuditLogRepository::search(pool, query)?;
        
        // Contar o total de registros (para paginação)
        let total = AuditLogRepository::count(pool, query)?;
        
        Ok((logs, total))
    }
    
    /// Busca um log específico por ID
    pub fn get_log_by_id(
        pool: &DbPool,
        id: &str,
    ) -> Result<Option<AuditLogEntry>, ApiError> {
        AuditLogRepository::find_by_id(pool, id)
    }
    
    /// Limpa logs antigos do sistema
    pub fn clean_old_logs(
        pool: &DbPool,
        days_to_keep: u32,
    ) -> Result<usize, ApiError> {
        AuditLogRepository::clean_old_logs(pool, days_to_keep)
    }
    
    /// Utilitário para extrair informações do request
    pub fn extract_request_info(req: &HttpRequest) -> (Option<String>, Option<String>) {
        let ip = req.connection_info().realip_remote_addr().map(|s| s.to_string());
        
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok().map(|s| s.to_string()));
        
        (ip, user_agent)
    }
} 