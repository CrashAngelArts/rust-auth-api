use crate::db::DbPool;
use crate::errors::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::audit_log::{AuditLogQuery, AuditAction};
use crate::models::response::ApiResponse;
use crate::services::audit_log_service::AuditLogService;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Estrutura para resposta paginada de logs de auditoria
#[derive(Debug, Serialize)]
pub struct AuditLogListResponse {
    /// Lista de logs
    pub logs: Vec<serde_json::Value>,
    
    /// Total de registros encontrados (para paginação)
    pub total: u64,
    
    /// Página atual
    pub page: usize,
    
    /// Tamanho da página
    pub page_size: usize,
}

/// Query para busca paginada
#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    /// Página (começa em 1)
    #[serde(default = "default_page")]
    pub page: usize,
    
    /// Tamanho da página
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_page() -> usize {
    1
}

fn default_page_size() -> usize {
    20
}

/// Query para busca com filtros
#[derive(Debug, Deserialize)]
pub struct AuditFilterQuery {
    /// Usuário
    pub user_id: Option<String>,
    
    /// Administrador
    pub admin_id: Option<String>,
    
    /// Tipo de ação
    pub action: Option<String>,
    
    /// Tipo de recurso
    pub resource_type: Option<String>,
    
    /// ID do recurso
    pub resource_id: Option<String>,
    
    /// Data de início
    pub from_date: Option<DateTime<Utc>>,
    
    /// Data de término
    pub to_date: Option<DateTime<Utc>>,
    
    /// Severidade
    pub severity: Option<String>,
}

/// # Lista logs de auditoria
/// 
/// Retorna uma lista paginada de logs de auditoria, com suporte a filtros
/// 
/// ## Endpoint
/// 
/// `GET /api/admin/audit-logs`
/// 
/// ## Parâmetros de Query
/// 
/// - `page`: Página (começa em 1, default: 1)
/// - `page_size`: Tamanho da página (default: 20)
/// - `user_id`: Filtrar por ID do usuário
/// - `admin_id`: Filtrar por ID do administrador
/// - `action`: Filtrar por tipo de ação (Create, Read, Update, Delete, Login, etc.)
/// - `resource_type`: Filtrar por tipo de recurso (user, role, etc.)
/// - `resource_id`: Filtrar por ID do recurso
/// - `severity`: Filtrar por severidade (Info, Warning, High, Critical)
/// - `from_date`: Filtrar a partir desta data (formato ISO8601)
/// - `to_date`: Filtrar até esta data (formato ISO8601)
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "logs": [
///       {
///         "id": "550e8400-e29b-41d4-a716-446655440000",
///         "user_id": "550e8400-e29b-41d4-a716-446655440001",
///         "admin_id": null,
///         "action": "Login",
///         "resource_type": "auth",
///         "resource_id": null,
///         "timestamp": "2023-01-01T12:00:00Z",
///         "ip_address": "192.168.1.1",
///         "user_agent": "Mozilla/5.0...",
///         "details": { "success": true },
///         "status": "Success",
///         "severity": "Info",
///         "description": "Login bem-sucedido"
///       }
///     ],
///     "total": 100,
///     "page": 1,
///     "page_size": 20
///   }
/// }
/// ```
pub async fn list_audit_logs(
    pool: web::Data<DbPool>,
    pagination: web::Query<PaginationQuery>,
    filter: web::Query<AuditFilterQuery>,
    _auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let page = pagination.page.max(1);
    let page_size = pagination.page_size.min(100).max(1);
    
    // Ajuste índices para paginação
    let offset = (page - 1) * page_size;
    
    // Criar query para o serviço
    let mut query = AuditLogQuery::default();
    query.offset = offset;
    query.limit = page_size;
    
    // Adicionar filtros
    query.user_id = filter.user_id.clone();
    query.admin_id = filter.admin_id.clone();
    query.resource_type = filter.resource_type.clone();
    query.resource_id = filter.resource_id.clone();
    query.from_date = filter.from_date;
    query.to_date = filter.to_date;
    
    // Converter action de string para enum
    if let Some(action_str) = &filter.action {
        query.action = match action_str.as_str() {
            "Create" => Some(AuditAction::Create),
            "Read" => Some(AuditAction::Read),
            "Update" => Some(AuditAction::Update),
            "Delete" => Some(AuditAction::Delete),
            "Login" => Some(AuditAction::Login),
            "Logout" => Some(AuditAction::Logout),
            "Lock" => Some(AuditAction::Lock),
            "Unlock" => Some(AuditAction::Unlock),
            "GrantPermission" => Some(AuditAction::GrantPermission),
            "RevokePermission" => Some(AuditAction::RevokePermission),
            "AdminAction" => Some(AuditAction::AdminAction),
            "BulkOperation" => Some(AuditAction::BulkOperation),
            "SecurityFailure" => Some(AuditAction::SecurityFailure),
            "Configuration" => Some(AuditAction::Configuration),
            "Other" => Some(AuditAction::Other),
            _ => None,
        };
    }
    
    // Buscar logs e total
    let (logs, total) = AuditLogService::search_logs(&pool, &query)?;
    
    // Converter logs para JSON para simplificar a serialização
    let logs_json: Vec<serde_json::Value> = logs.into_iter()
        .map(|log| serde_json::to_value(log).unwrap_or_default())
        .collect();
    
    let response = AuditLogListResponse {
        logs: logs_json,
        total,
        page,
        page_size,
    };
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

/// # Obtém detalhes de um log de auditoria
/// 
/// Retorna os detalhes de um log de auditoria específico por ID
/// 
/// ## Endpoint
/// 
/// `GET /api/admin/audit-logs/{id}`
/// 
/// ## Parâmetros de URL
/// 
/// - `id`: ID do log de auditoria
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "user_id": "550e8400-e29b-41d4-a716-446655440001",
///     "admin_id": null,
///     "action": "Login",
///     "resource_type": "auth",
///     "resource_id": null,
///     "timestamp": "2023-01-01T12:00:00Z",
///     "ip_address": "192.168.1.1",
///     "user_agent": "Mozilla/5.0...",
///     "details": { "success": true },
///     "status": "Success",
///     "severity": "Info",
///     "description": "Login bem-sucedido"
///   }
/// }
/// ```
pub async fn get_audit_log_by_id(
    pool: web::Data<DbPool>,
    id: web::Path<String>,
    _auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let log = AuditLogService::get_log_by_id(&pool, &id)?
        .ok_or_else(|| ApiError::NotFoundError("Log de auditoria não encontrado 📝".to_string()))?;
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(log)))
}

/// # Limpa logs de auditoria antigos
/// 
/// Remove logs de auditoria mais antigos que o número de dias especificado
/// 
/// ## Endpoint
/// 
/// `DELETE /api/admin/audit-logs/clean`
/// 
/// ## Parâmetros de Query
/// 
/// - `days_to_keep`: Número de dias para manter logs (default: 30, mínimo: 7)
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": "10 logs de auditoria antigos foram removidos com sucesso ✅",
///   "data": {
///     "removed_count": 10
///   }
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct CleanLogsQuery {
    #[serde(default = "default_days_to_keep")]
    pub days_to_keep: u32,
}

fn default_days_to_keep() -> u32 {
    30
}

#[derive(Debug, Serialize)]
pub struct CleanLogsResponse {
    pub removed_count: usize,
}

pub async fn clean_audit_logs(
    pool: web::Data<DbPool>,
    query: web::Query<CleanLogsQuery>,
    _auth_user: AuthenticatedUser,
    req: HttpRequest,
) -> Result<impl Responder, ApiError> {
    // Garantir um mínimo de 7 dias para evitar remoção acidental de logs importantes
    let days_to_keep = query.days_to_keep.max(7);
    
    // Registrar esta ação como uma ação administrativa
    let (_ip, _user_agent) = AuditLogService::extract_request_info(&req);
    
    // Limpar os logs
    let removed_count = AuditLogService::clean_old_logs(&pool, days_to_keep)?;
    
    info!("🧹 {} logs de auditoria mais antigos que {} dias foram removidos", 
          removed_count, days_to_keep);
    
    // Registrar a limpeza no próprio log de auditoria
    let admin_id = &_auth_user.id;
    let mut details = serde_json::Map::new();
    details.insert("days_to_keep".to_string(), days_to_keep.into());
    details.insert("removed_count".to_string(), removed_count.into());
    
    AuditLogService::log_admin_action(
        &pool,
        admin_id,
        AuditAction::Delete,
        "audit_log",
        None,
        Some(serde_json::Value::Object(details)),
        Some(&req),
    )?;
    
    let response = CleanLogsResponse {
        removed_count,
    };
    
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        response,
        &format!("{} logs de auditoria antigos foram removidos com sucesso ✅", removed_count),
    )))
}

/// Configura as rotas do controlador
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/admin/audit-logs")
            .route("", web::get().to(list_audit_logs))
            .route("/{id}", web::get().to(get_audit_log_by_id))
            .route("/clean", web::delete().to(clean_audit_logs))
    );
} 