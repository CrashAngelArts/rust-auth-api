use crate::db::DbPool;
use crate::errors::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::device::UpdateDeviceDto;
use crate::models::response::ApiResponse;
use crate::services::device_service::DeviceService;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use validator::Validate;

/// # Lista Dispositivos
/// 
/// Lista todos os dispositivos conectados associados ao usuário autenticado.
/// 
/// ## Endpoint
/// 
/// `GET /api/auth/devices`
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "devices": [
///       {
///         "id": "550e8400-e29b-41d4-a716-446655440000",
///         "device_name": "iPhone em São Paulo",
///         "device_type": "Celular 📱 (Safari em iOS)",
///         "ip_address": "192.168.1.1",
///         "location": "São Paulo, Brasil",
///         "last_active_at": "2023-09-15T14:30:00Z",
///         "is_current": true,
///         "created_at": "2023-09-15T14:30:00Z"
///       },
///       {
///         "id": "550e8400-e29b-41d4-a716-446655440001",
///         "device_name": "Computador em Rio de Janeiro",
///         "device_type": "Computador 💻 (Chrome em Windows)",
///         "ip_address": "192.168.1.2",
///         "location": "Rio de Janeiro, Brasil",
///         "last_active_at": "2023-09-14T10:15:00Z",
///         "is_current": false,
///         "created_at": "2023-09-14T10:15:00Z"
///       }
///     ],
///     "current_device": {
///       "id": "550e8400-e29b-41d4-a716-446655440000",
///       "device_name": "iPhone em São Paulo",
///       "device_type": "Celular 📱 (Safari em iOS)",
///       "ip_address": "192.168.1.1",
///       "location": "São Paulo, Brasil",
///       "last_active_at": "2023-09-15T14:30:00Z",
///       "is_current": true,
///       "created_at": "2023-09-15T14:30:00Z"
///     }
///   }
/// }
/// ```
pub async fn list_devices(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    // Buscar todos os dispositivos do usuário
    let devices = DeviceService::list_user_devices(&pool, &auth_user.id)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(devices)))
}

/// # Detalhes do Dispositivo
/// 
/// Obtém detalhes completos de um dispositivo específico.
/// 
/// ## Endpoint
/// 
/// `GET /api/auth/devices/{id}`
/// 
/// ## Parâmetros de URL
/// 
/// - `id`: ID do dispositivo a ser consultado
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "device_name": "iPhone em São Paulo",
///     "device_type": "Celular 📱 (Safari em iOS)",
///     "ip_address": "192.168.1.1",
///     "location": "São Paulo, Brasil",
///     "last_active_at": "2023-09-15T14:30:00Z",
///     "is_current": true,
///     "created_at": "2023-09-15T14:30:00Z"
///   }
/// }
/// ```
pub async fn get_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    // Buscar detalhes do dispositivo
    let device = DeviceService::get_device_details(&pool, &device_id, &auth_user.id)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(device)))
}

/// # Atualiza Dispositivo
/// 
/// Atualiza o nome/descrição de um dispositivo específico.
/// 
/// ## Endpoint
/// 
/// `PUT /api/auth/devices/{id}`
/// 
/// ## Parâmetros de URL
/// 
/// - `id`: ID do dispositivo a ser atualizado
/// 
/// ## Corpo da Requisição
/// 
/// ```json
/// {
///   "device_name": "Meu iPhone (Trabalho)"
/// }
/// ```
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "device_name": "Meu iPhone (Trabalho)",
///     "device_type": "Celular 📱 (Safari em iOS)",
///     "ip_address": "192.168.1.1",
///     "location": "São Paulo, Brasil",
///     "last_active_at": "2023-09-15T14:30:00Z",
///     "is_current": true,
///     "created_at": "2023-09-15T14:30:00Z"
///   }
/// }
/// ```
pub async fn update_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
    update_dto: web::Json<UpdateDeviceDto>,
) -> Result<impl Responder, ApiError> {
    // Validar dados de entrada
    update_dto.validate()?;
    
    // Atualizar o dispositivo
    let updated_device = DeviceService::update_device(
        &pool, 
        &device_id, 
        &auth_user.id, 
        &update_dto.device_name
    )?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(updated_device)))
}

/// # Define Dispositivo como Atual
/// 
/// Define um dispositivo específico como o dispositivo atual do usuário.
/// O dispositivo atual é destacado na interface e usado para determinar
/// a origem das ações do usuário.
/// 
/// ## Endpoint
/// 
/// `POST /api/auth/devices/{id}/set-current`
/// 
/// ## Parâmetros de URL
/// 
/// - `id`: ID do dispositivo a ser definido como atual
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": "Dispositivo definido como atual com sucesso! 📱✨",
///   "data": {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "device_name": "Meu iPhone (Trabalho)",
///     "device_type": "Celular 📱 (Safari em iOS)",
///     "ip_address": "192.168.1.1",
///     "location": "São Paulo, Brasil",
///     "last_active_at": "2023-09-15T14:30:00Z",
///     "is_current": true,
///     "created_at": "2023-09-15T14:30:00Z"
///   }
/// }
/// ```
pub async fn set_as_current_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    // Definir como dispositivo atual
    DeviceService::set_current_device(&pool, &device_id, &auth_user.id)?;
    
    // Buscar detalhes atualizados do dispositivo
    let device = DeviceService::get_device_details(&pool, &device_id, &auth_user.id)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        device, 
        "Dispositivo definido como atual com sucesso! 📱✨"
    )))
}

/// # Revoga Dispositivo
/// 
/// Revoga o acesso (encerra a sessão) de um dispositivo específico.
/// Não é possível revogar o dispositivo atual (da sessão em uso).
/// 
/// ## Endpoint
/// 
/// `DELETE /api/auth/devices/{id}`
/// 
/// ## Parâmetros de URL
/// 
/// - `id`: ID do dispositivo a ser revogado
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "message": "Dispositivo revogado com sucesso! 🔒",
///     "revoked_at": "2023-09-15T15:45:30Z"
///   }
/// }
/// ```
/// 
/// ## Resposta de Erro (ao tentar revogar dispositivo atual)
/// 
/// ```json
/// {
///   "status": "error",
///   "message": "Não é possível revogar o dispositivo atual. Use o endpoint de logout para isso. 🔒",
///   "data": null
/// }
/// ```
pub async fn revoke_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
    req: HttpRequest,
) -> Result<impl Responder, ApiError> {
    // Extrair o ID da sessão atual (do token)
    let current_session_id = req.extensions()
        .get::<String>()
        .map(|s| s.clone())
        .unwrap_or_default();
    
    // Verificar se o usuário está tentando revogar o dispositivo atual
    if current_session_id == device_id.to_string() {
        return Err(ApiError::BadRequestError(
            "Não é possível revogar o dispositivo atual. Use o endpoint de logout para isso. 🔒".to_string()
        ));
    }
    
    // Revogar o dispositivo
    DeviceService::revoke_device(&pool, &device_id, &auth_user.id)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": "Dispositivo revogado com sucesso! 🔒",
        "revoked_at": chrono::Utc::now().to_rfc3339()
    }))))
}

/// # Limpa Sessões Expiradas
/// 
/// Limpa sessões expiradas do banco de dados. Apenas para administradores.
/// 
/// ## Endpoint
/// 
/// `POST /api/admin/clean-sessions`
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "message": "5 sessões expiradas foram removidas 🧹",
///     "cleaned_at": "2023-09-15T16:00:00Z"
///   }
/// }
/// ```
pub async fn clean_expired_sessions(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> {
    // Limpar sessões expiradas
    let deleted = DeviceService::clean_expired_sessions(&pool)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": format!("{} sessões expiradas foram removidas 🧹", deleted),
        "cleaned_at": chrono::Utc::now().to_rfc3339()
    }))))
}
