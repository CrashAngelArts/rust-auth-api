use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::recovery_code::{CreateRecoveryCodeDto, VerifyRecoveryCodeDto};
use crate::models::response::ApiResponse;
use crate::services::recovery_code_service::RecoveryCodeService;
use crate::utils::jwt::extract_user_id;
use actix_web::{delete, get, post, web, HttpRequest, HttpResponse};
use actix_web_grants::proc_macro::has_permissions;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use tracing::info;
use validator::Validate;

/// Gera um novo código de recuperação para um usuário
#[post("/users/{user_id}/recovery-codes")]
#[has_permissions("ADMIN")]
pub async fn generate_recovery_code(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<CreateRecoveryCodeDto>,
    _auth: BearerAuth, // Somente admin pode gerar códigos para outros usuários
) -> Result<HttpResponse, ApiError> {
    // Validar dados
    data.validate()?;
    
    // Gerar código de recuperação
    let recovery_code_response = RecoveryCodeService::generate_code(
        &pool,
        &user_id,
        data.expiration_hours,
    )?;
    
    info!("✅ Código de recuperação gerado para o usuário: {}", user_id);
    
    // Retornar resposta
    Ok(HttpResponse::Created().json(ApiResponse::success_with_message(
        recovery_code_response,
        "Código de recuperação gerado com sucesso! Guarde este código em um local seguro 🔐"
    )))
}

/// Verifica um código de recuperação
#[post("/recovery-codes/verify")]
pub async fn verify_recovery_code(
    pool: web::Data<DbPool>,
    data: web::Json<VerifyRecoveryCodeDto>,
) -> Result<HttpResponse, ApiError> {
    // Validar dados
    data.validate()?;
    
    // Verificar código (sem consumir)
    let user_id = RecoveryCodeService::verify_code(&pool, &data.code, false)?;
    
    info!("✅ Código de recuperação verificado para o usuário: {}", user_id);
    
    // Retornar resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        serde_json::json!({ "user_id": user_id, "valid": true }),
        "Código de recuperação válido ✅"
    )))
}

/// Consome (usa) um código de recuperação
#[post("/recovery-codes/use")]
pub async fn use_recovery_code(
    pool: web::Data<DbPool>,
    data: web::Json<VerifyRecoveryCodeDto>,
) -> Result<HttpResponse, ApiError> {
    // Validar dados
    data.validate()?;
    
    // Verificar e consumir código
    let user_id = RecoveryCodeService::verify_code(&pool, &data.code, true)?;
    
    info!("✅ Código de recuperação consumido para o usuário: {}", user_id);
    
    // Retornar resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        serde_json::json!({ "user_id": user_id }),
        "Código de recuperação utilizado com sucesso ✅"
    )))
}

/// Lista todos os códigos de recuperação de um usuário
#[get("/users/{user_id}/recovery-codes")]
#[has_permissions("ADMIN")]
pub async fn list_user_recovery_codes(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    _auth: BearerAuth, // Somente admin pode listar códigos
) -> Result<HttpResponse, ApiError> {
    // Listar códigos do usuário
    let codes = RecoveryCodeService::list_user_codes(&pool, &user_id)?;
    
    info!("📋 Listados {} códigos de recuperação para o usuário: {}", codes.len(), user_id);
    
    // Retornar resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(codes)))
}

/// Limpa códigos de recuperação expirados ou usados
#[delete("/recovery-codes/expired")]
#[has_permissions("ADMIN")]
pub async fn clean_expired_recovery_codes(
    pool: web::Data<DbPool>,
    _auth: BearerAuth, // Somente admin pode executar limpeza
) -> Result<HttpResponse, ApiError> {
    // Limpar códigos expirados
    let removed_count = RecoveryCodeService::clean_expired_codes(&pool)?;
    
    info!("🧹 Limpeza: {} códigos de recuperação expirados removidos", removed_count);
    
    // Retornar resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        serde_json::json!({ "removed_count": removed_count }),
        "Limpeza de códigos de recuperação concluída 🧹"
    )))
}

/// Cria um código de recuperação para o próprio usuário
#[post("/user/recovery-code")]
pub async fn create_my_recovery_code(
    pool: web::Data<DbPool>,
    _data: web::Json<serde_json::Value>, // Aceita objeto vazio
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Extrair ID do usuário do token JWT
    let user_id = extract_user_id(&req)?;
    
    // Configuração padrão: código sem expiração
    let expiration_hours = None;
    
    // Gerar código de recuperação
    let recovery_code_response = RecoveryCodeService::generate_code(
        &pool,
        &user_id,
        expiration_hours,
    )?;
    
    info!("✅ Usuário gerou seu próprio código de recuperação: {}", user_id);
    
    // Retornar resposta
    Ok(HttpResponse::Created().json(ApiResponse::success_with_message(
        recovery_code_response,
        "Seu código de recuperação foi gerado! Guarde este código em um local seguro 🔐"
    )))
}

/// Configura as rotas para o módulo de códigos de recuperação
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(generate_recovery_code)
            .service(verify_recovery_code)
            .service(use_recovery_code)
            .service(list_user_recovery_codes)
            .service(clean_expired_recovery_codes)
            .service(create_my_recovery_code)
    );
}