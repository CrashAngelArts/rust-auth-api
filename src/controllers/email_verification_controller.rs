use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::TokenClaims;
use crate::models::email_verification::VerifyEmailCodeDto;
use crate::models::response::ApiResponse;
use crate::services::email_verification_service::EmailVerificationService;
use actix_web::{web, HttpResponse, Responder};
use tracing::info;
use validator::Validate;

// Verifica um código de email
pub async fn verify_email_code(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>,
    data: web::Json<VerifyEmailCodeDto>,
) -> Result<impl Responder, ApiError> {
    // Validar os dados
    data.validate()?;
    
    // Obter o ID do usuário das claims
    let user_id = claims.sub.clone();
    
    // Verificar o código
    let verification_result = EmailVerificationService::verify_code(
        &pool,
        &user_id,
        &data.code,
    )?;
    
    info!("✅ Código de verificação por email validado para o usuário ID: {}", user_id);
    
    // Retornar resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        verification_result,
        "Código verificado com sucesso! 🎉",
    )))
}

// Reenvia um código de verificação
pub async fn resend_verification_code(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>,
    email_service: web::Data<crate::services::email_service::EmailService>,
) -> Result<impl Responder, ApiError> {
    // Obter o ID do usuário das claims
    let user_id = claims.sub.clone();
    
    // Verificar se já existe um código pendente
    if EmailVerificationService::has_pending_code(&pool, &user_id)? {
        // Limpar códigos antigos
        let conn = pool.get()?;
        conn.execute(
            "DELETE FROM email_verification_codes WHERE user_id = ?1 AND verified = 0",
            [&user_id],
        )?;
    }
    
    // Obter o usuário
    let user = crate::services::user_service::UserService::get_user_by_id(&pool, &user_id)?;
    
    // Gerar e enviar novo código
    EmailVerificationService::generate_and_send_code(
        &pool,
        &user,
        None,
        None,
        &email_service,
        15, // 15 minutos de expiração
    ).await?;
    
    info!("📧 Novo código de verificação enviado para: {}", user.email);
    
    // Retornar resposta
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "Novo código de verificação enviado para seu email! 📨",
    )))
}

// Limpa códigos expirados (admin)
pub async fn clean_expired_codes(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> {
    // Limpar códigos expirados
    let deleted = EmailVerificationService::clean_expired_codes(&pool)?;
    
    // Retornar resposta
    let message = format!("{} códigos de verificação expirados foram removidos 🧹", deleted);
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        serde_json::json!({ "deleted": deleted }),
        &message,
    )))
}
