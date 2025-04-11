use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::keystroke_dynamics::{RegisterKeystrokePatternDto, VerifyKeystrokePatternDto};
use crate::models::response::ApiResponse;
use crate::services::keystroke_service::KeystrokeService;
use crate::services::keystroke_security_service::KeystrokeSecurityService;
use crate::services::user_service::UserService;
use actix_web::{web, HttpResponse, Responder, HttpRequest};
use tracing::{info, warn};
use validator::Validate;
use std::time::Duration;

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
    req: HttpRequest,
    security_service: web::Data<KeystrokeSecurityService>,
) -> Result<impl Responder, ApiError> {
    // Validar os dados
    data.validate()?;
    
    // Verificar se o usuário existe
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    let user_id_str = user_id.into_inner();
    
    // Verificar se o usuário está sob observação por atividade suspeita
    if security_service.is_user_suspicious(&user_id_str).await {
        warn!("👀 Usuário {} está sob observação por atividade suspeita 🔍", user.username);
        // Adicionar um pequeno atraso para dificultar ataques de força bruta
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    
    // Obter informações do cliente para monitoramento de segurança
    let ip_address = req.connection_info().realip_remote_addr().map(|s| s.to_string());
    let user_agent = req.headers().get("user-agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string());
    
    // Verificar o padrão
    let verification_result = KeystrokeService::verify_keystroke_pattern(
        &pool,
        &user_id_str,
        data.typing_pattern.clone(),
    )?;
    
    // Registrar a tentativa no serviço de segurança
    security_service.record_verification_attempt(
        &user_id_str,
        verification_result.accepted,
        verification_result.similarity_percentage as f64,
        ip_address,
        user_agent,
    ).await?;
    
    info!("🔍 Verificação de padrão de digitação para usuário: {}, resultado: {}", 
          user.username, if verification_result.accepted { "aceito ✅" } else { "rejeitado ❌" });
    
    // Se a verificação falhar, adicionar um pequeno atraso para dificultar ataques de força bruta
    if !verification_result.accepted {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    
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
