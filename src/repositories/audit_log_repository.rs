use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::audit_log::{AuditLogEntry, AuditLogQuery, AuditAction, AuditStatus, AuditSeverity, CreateAuditLogDto};
use chrono::Utc;
use rusqlite::params;
use serde_json::{Value, json};
use tracing::{info, error};
use uuid::Uuid;

/// Repositório para gerenciar logs de auditoria
pub struct AuditLogRepository;

impl AuditLogRepository {
    /// Cria as tabelas necessárias para armazenar logs de auditoria
    pub fn create_tables(pool: &DbPool) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                user_id TEXT NULL,
                admin_id TEXT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT NULL,
                user_agent TEXT NULL,
                details TEXT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NULL,
                session_id TEXT NULL
            )",
            [],
        )?;
        
        info!("📝 Tabela de logs de auditoria criada ou verificada");
        
        Ok(())
    }
    
    /// Insere uma nova entrada de log de auditoria
    pub fn create(pool: &DbPool, entry: &CreateAuditLogDto) -> Result<AuditLogEntry, ApiError> {
        let conn = pool.get()?;
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        
        // Converter os enums para string
        let action_str = format!("{:?}", entry.action);
        let status_str = format!("{:?}", entry.status);
        let severity_str = format!("{:?}", entry.severity);
        
        // Serializar detalhes para JSON se existirem
        let details_json = match &entry.details {
            Some(details) => serde_json::to_string(details)?,
            None => String::new(),
        };
        
        conn.execute(
            "INSERT INTO audit_logs (
                id, user_id, admin_id, action, resource_type, resource_id,
                timestamp, ip_address, user_agent, details, status, severity,
                description, session_id
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
            )",
            params![
                id,
                entry.user_id,
                entry.admin_id,
                action_str,
                entry.resource_type,
                entry.resource_id,
                now.to_rfc3339(),
                entry.ip_address,
                entry.user_agent,
                if details_json.is_empty() { None } else { Some(details_json) },
                status_str,
                severity_str,
                entry.description,
                entry.session_id
            ],
        )?;
        
        // Criar o objeto AuditLogEntry com os dados inseridos
        let log_entry = AuditLogEntry {
            id,
            user_id: entry.user_id.clone(),
            admin_id: entry.admin_id.clone(),
            action: entry.action,
            resource_type: entry.resource_type.clone(),
            resource_id: entry.resource_id.clone(),
            timestamp: now,
            ip_address: entry.ip_address.clone(),
            user_agent: entry.user_agent.clone(),
            details: entry.details.clone(),
            status: entry.status,
            severity: entry.severity,
            description: entry.description.clone(),
            session_id: entry.session_id.clone(),
        };
        
        info!("📝 Nova entrada de log criada: {} [{}] {}", 
              log_entry.action, log_entry.resource_type, log_entry.resource_id.as_deref().unwrap_or("-"));
        
        Ok(log_entry)
    }
    
    /// Busca uma entrada de log por ID
    pub fn find_by_id(pool: &DbPool, id: &str) -> Result<Option<AuditLogEntry>, ApiError> {
        let conn = pool.get()?;
        
        let result = conn.query_row(
            "SELECT 
                id, user_id, admin_id, action, resource_type, resource_id,
                timestamp, ip_address, user_agent, details, status, severity,
                description, session_id
             FROM audit_logs
             WHERE id = ?1",
            [id],
            |row| {
                let action_str: String = row.get(3)?;
                let status_str: String = row.get(10)?;
                let severity_str: String = row.get(11)?;
                let details_json: Option<String> = row.get(9)?;
                
                // Converter tipos
                let action = Self::parse_action(&action_str).unwrap_or(AuditAction::Other);
                let status = Self::parse_status(&status_str).unwrap_or(AuditStatus::Unknown);
                let severity = Self::parse_severity(&severity_str).unwrap_or(AuditSeverity::Info);
                
                // Deserializar detalhes JSON se existirem
                let details = match details_json {
                    Some(json_str) if !json_str.is_empty() => {
                        serde_json::from_str(&json_str).unwrap_or(json!({}))
                    },
                    _ => Value::Null,
                };
                
                Ok(AuditLogEntry {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    admin_id: row.get(2)?,
                    action,
                    resource_type: row.get(4)?,
                    resource_id: row.get(5)?,
                    timestamp: row.get(6)?,
                    ip_address: row.get(7)?,
                    user_agent: row.get(8)?,
                    details: if details == Value::Null { None } else { Some(details) },
                    status,
                    severity,
                    description: row.get(12)?,
                    session_id: row.get(13)?,
                })
            },
        );
        
        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => {
                error!("❌ Erro ao buscar log de auditoria: {}", e);
                Err(ApiError::from(e))
            }
        }
    }
    
    /// Busca logs de auditoria com base em critérios
    pub fn search(pool: &DbPool, query: &AuditLogQuery) -> Result<Vec<AuditLogEntry>, ApiError> {
        let conn = pool.get()?;
        
        // Criar a consulta SQL base
        let mut sql = String::from(
            "SELECT 
                id, user_id, admin_id, action, resource_type, resource_id,
                timestamp, ip_address, user_agent, details, status, severity,
                description, session_id
             FROM audit_logs
             WHERE 1=1"
        );
        
        // Vetor para armazenar parâmetros
        let mut params: Vec<String> = Vec::new();
        
        // Adicionar condições baseadas nos critérios da query
        if let Some(user_id) = &query.user_id {
            sql.push_str(" AND user_id = ?");
            params.push(user_id.clone());
        }
        
        if let Some(admin_id) = &query.admin_id {
            sql.push_str(" AND admin_id = ?");
            params.push(admin_id.clone());
        }
        
        if let Some(action) = &query.action {
            sql.push_str(" AND action = ?");
            params.push(format!("{:?}", action));
        }
        
        if let Some(resource_type) = &query.resource_type {
            sql.push_str(" AND resource_type = ?");
            params.push(resource_type.clone());
        }
        
        if let Some(resource_id) = &query.resource_id {
            sql.push_str(" AND resource_id = ?");
            params.push(resource_id.clone());
        }
        
        if let Some(status) = &query.status {
            sql.push_str(" AND status = ?");
            params.push(format!("{:?}", status));
        }
        
        if let Some(severity) = &query.severity {
            sql.push_str(" AND severity = ?");
            params.push(format!("{:?}", severity));
        }
        
        if let Some(from_date) = &query.from_date {
            sql.push_str(" AND timestamp >= ?");
            params.push(from_date.to_rfc3339());
        }
        
        if let Some(to_date) = &query.to_date {
            sql.push_str(" AND timestamp <= ?");
            params.push(to_date.to_rfc3339());
        }
        
        // Ordenar por timestamp decrescente (mais recente primeiro)
        sql.push_str(" ORDER BY timestamp DESC");
        
        // Adicionar limit e offset
        sql.push_str(" LIMIT ? OFFSET ?");
        params.push(query.limit.to_string());
        params.push(query.offset.to_string());
        
        // Converter params para slice de &str
        let param_refs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
        
        // Executar a consulta
        let mut stmt = conn.prepare(&sql)?;
        let log_iter = stmt.query_map(rusqlite::params_from_iter(param_refs.iter()), |row| {
            let action_str: String = row.get(3)?;
            let status_str: String = row.get(10)?;
            let severity_str: String = row.get(11)?;
            let details_json: Option<String> = row.get(9)?;
            
            // Converter tipos
            let action = Self::parse_action(&action_str).unwrap_or(AuditAction::Other);
            let status = Self::parse_status(&status_str).unwrap_or(AuditStatus::Unknown);
            let severity = Self::parse_severity(&severity_str).unwrap_or(AuditSeverity::Info);
            
            // Deserializar detalhes JSON se existirem
            let details = match details_json {
                Some(json_str) if !json_str.is_empty() => {
                    serde_json::from_str(&json_str).unwrap_or(json!({}))
                },
                _ => Value::Null,
            };
            
            Ok(AuditLogEntry {
                id: row.get(0)?,
                user_id: row.get(1)?,
                admin_id: row.get(2)?,
                action,
                resource_type: row.get(4)?,
                resource_id: row.get(5)?,
                timestamp: row.get(6)?,
                ip_address: row.get(7)?,
                user_agent: row.get(8)?,
                details: if details == Value::Null { None } else { Some(details) },
                status,
                severity,
                description: row.get(12)?,
                session_id: row.get(13)?,
            })
        })?;
        
        let mut logs = Vec::new();
        for entry in log_iter {
            match entry {
                Ok(log) => logs.push(log),
                Err(e) => {
                    error!("❌ Erro ao processar log de auditoria: {}", e);
                    return Err(ApiError::from(e));
                }
            }
        }
        
        Ok(logs)
    }
    
    /// Limpa logs antigos com base em critérios
    pub fn clean_old_logs(pool: &DbPool, days_to_keep: u32) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        
        // Calcular a data limite
        let now = Utc::now();
        let cutoff_date = now - chrono::Duration::days(days_to_keep as i64);
        let cutoff_date_str = cutoff_date.to_rfc3339();
        
        // Executar a exclusão
        let deleted = conn.execute(
            "DELETE FROM audit_logs WHERE timestamp < ?1",
            [cutoff_date_str],
        )?;
        
        if deleted > 0 {
            info!("🧹 {} logs de auditoria antigos foram removidos", deleted);
        }
        
        Ok(deleted)
    }
    
    /// Conta o número total de logs com base nos critérios
    pub fn count(pool: &DbPool, query: &AuditLogQuery) -> Result<u64, ApiError> {
        let conn = pool.get()?;
        
        // Criar a consulta SQL base
        let mut sql = String::from("SELECT COUNT(*) FROM audit_logs WHERE 1=1");
        
        // Vetor para armazenar parâmetros
        let mut params: Vec<String> = Vec::new();
        
        // Adicionar condições baseadas nos critérios da query
        if let Some(user_id) = &query.user_id {
            sql.push_str(" AND user_id = ?");
            params.push(user_id.clone());
        }
        
        if let Some(admin_id) = &query.admin_id {
            sql.push_str(" AND admin_id = ?");
            params.push(admin_id.clone());
        }
        
        if let Some(action) = &query.action {
            sql.push_str(" AND action = ?");
            params.push(format!("{:?}", action));
        }
        
        if let Some(resource_type) = &query.resource_type {
            sql.push_str(" AND resource_type = ?");
            params.push(resource_type.clone());
        }
        
        if let Some(resource_id) = &query.resource_id {
            sql.push_str(" AND resource_id = ?");
            params.push(resource_id.clone());
        }
        
        if let Some(status) = &query.status {
            sql.push_str(" AND status = ?");
            params.push(format!("{:?}", status));
        }
        
        if let Some(severity) = &query.severity {
            sql.push_str(" AND severity = ?");
            params.push(format!("{:?}", severity));
        }
        
        if let Some(from_date) = &query.from_date {
            sql.push_str(" AND timestamp >= ?");
            params.push(from_date.to_rfc3339());
        }
        
        if let Some(to_date) = &query.to_date {
            sql.push_str(" AND timestamp <= ?");
            params.push(to_date.to_rfc3339());
        }
        
        // Converter params para slice de &str
        let param_refs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
        
        // Executar a consulta
        let count: u64 = conn.query_row(
            &sql,
            rusqlite::params_from_iter(param_refs.iter()),
            |row| row.get(0),
        )?;
        
        Ok(count)
    }
    
    /// Converte string para enum AuditAction
    fn parse_action(action_str: &str) -> Result<AuditAction, ApiError> {
        match action_str {
            "Create" => Ok(AuditAction::Create),
            "Read" => Ok(AuditAction::Read),
            "Update" => Ok(AuditAction::Update),
            "Delete" => Ok(AuditAction::Delete),
            "Login" => Ok(AuditAction::Login),
            "Logout" => Ok(AuditAction::Logout),
            "Lock" => Ok(AuditAction::Lock),
            "Unlock" => Ok(AuditAction::Unlock),
            "GrantPermission" => Ok(AuditAction::GrantPermission),
            "RevokePermission" => Ok(AuditAction::RevokePermission),
            "AdminAction" => Ok(AuditAction::AdminAction),
            "BulkOperation" => Ok(AuditAction::BulkOperation),
            "SecurityFailure" => Ok(AuditAction::SecurityFailure),
            "Configuration" => Ok(AuditAction::Configuration),
            "Other" => Ok(AuditAction::Other),
            _ => {
                error!("❌ Tipo de ação desconhecido: {}", action_str);
                Ok(AuditAction::Other)
            }
        }
    }
    
    /// Converte string para enum AuditStatus
    fn parse_status(status_str: &str) -> Result<AuditStatus, ApiError> {
        match status_str {
            "Success" => Ok(AuditStatus::Success),
            "Failure" => Ok(AuditStatus::Failure),
            "Blocked" => Ok(AuditStatus::Blocked),
            "InProgress" => Ok(AuditStatus::InProgress),
            "Unknown" => Ok(AuditStatus::Unknown),
            _ => {
                error!("❌ Status desconhecido: {}", status_str);
                Ok(AuditStatus::Unknown)
            }
        }
    }
    
    /// Converte string para enum AuditSeverity
    fn parse_severity(severity_str: &str) -> Result<AuditSeverity, ApiError> {
        match severity_str {
            "Info" => Ok(AuditSeverity::Info),
            "Warning" => Ok(AuditSeverity::Warning),
            "High" => Ok(AuditSeverity::High),
            "Critical" => Ok(AuditSeverity::Critical),
            _ => {
                error!("❌ Severidade desconhecida: {}", severity_str);
                Ok(AuditSeverity::Info)
            }
        }
    }
} 