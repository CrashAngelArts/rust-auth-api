use crate::db::DbPool;
use crate::errors::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::device::UpdateDeviceDto;
use crate::models::response::ApiResponse;
use crate::services::device_service::DeviceService;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use validator::Validate;

// Lista todos os dispositivos conectados do usuário atual
pub async fn list_devices(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    // Buscar todos os dispositivos do usuário
    let devices = DeviceService::list_user_devices(&pool, &auth_user.id)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(devices)))
}

// Obtém detalhes de um dispositivo específico
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

// Atualiza informações de um dispositivo
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

// Revoga acesso de um dispositivo específico
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
            "Não é possível revogar o dispositivo atual. Use o endpoint de logout para isso.".to_string()
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

// Limpa sessões expiradas (admin)
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
