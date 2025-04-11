use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::keystroke_dynamics::{RegisterKeystrokePatternDto, VerifyKeystrokePatternDto};
use crate::models::response::ApiResponse;
use crate::services::keystroke_service::KeystrokeService;
use crate::services::user_service::UserService;
use actix_web::{web, HttpResponse, Responder};
use tracing::info;
use validator::Validate;

/// Registra um novo padrão de digitação
pub async fn register_keystroke_pattern(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<RegisterKeystrokePatternDto>,
) -> Result<impl Responder, ApiError> {
    // Validar os dados
    data.validate()?;
    
    // Verificar se o usuário existe
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Registrar o padrão
    KeystrokeService::register_pattern(
        &pool,
        &user_id.into_inner(),
        data.typing_pattern.clone(),
        data.similarity_threshold,
    )?;
    
    info!("✅ Padrão de digitação registrado para o usuário: {}", user.username);
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": "Padrão de digitação registrado com sucesso! 🎹",
        "similarity_threshold": data.similarity_threshold,
        "pattern_length": data.typing_pattern.len()
    }))))
}

/// Verifica um padrão de digitação durante o login
pub async fn verify_keystroke_pattern(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<VerifyKeystrokePatternDto>,
) -> Result<impl Responder, ApiError> {
    // Validar os dados
    data.validate()?;
    
    // Verificar se o usuário existe
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Verificar o padrão
    let verification_result = KeystrokeService::verify_keystroke_pattern(
        &pool,
        &user_id.into_inner(),
        data.typing_pattern.clone(),
    )?;
    
    info!("🔍 Verificação de padrão de digitação para usuário: {}, resultado: {}", 
          user.username, if verification_result.accepted { "aceito ✅" } else { "rejeitado ❌" });
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(verification_result)))
}

/// Habilita ou desabilita a verificação de ritmo de digitação
pub async fn toggle_keystroke_verification(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    enabled: web::Query<bool>,
) -> Result<impl Responder, ApiError> {
    // Verificar se o usuário existe
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Atualizar o status
    KeystrokeService::toggle_keystroke_verification(
        &pool,
        &user_id.into_inner(),
        *enabled,
    )?;
    
    let status = if *enabled { "habilitada ✅" } else { "desabilitada ❌" };
    info!("🔄 Verificação de ritmo de digitação {} para o usuário: {}", status, user.username);
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": format!("Verificação de ritmo de digitação {}", status),
        "enabled": *enabled
    }))))
}

/// Obtém o status da verificação de ritmo de digitação
pub async fn get_keystroke_status(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    // Verificar se o usuário existe
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Obter o status
    let status = KeystrokeService::get_keystroke_status(
        &pool,
        &user_id.into_inner(),
    )?;
    
    info!("ℹ️ Status de verificação de ritmo de digitação para usuário: {}", user.username);
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(status)))
}
