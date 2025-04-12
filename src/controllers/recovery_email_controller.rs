use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::recovery_email::{AddRecoveryEmailDto, VerifyRecoveryEmailDto};
use crate::services::email_service::EmailService;
use crate::services::recovery_email_service::RecoveryEmailService;
use crate::utils::jwt::extract_user_id;
use actix_web::{delete, get, post, web, HttpResponse, HttpRequest};
use tracing::info;

// Adicionar um novo email de recuperação
#[post("/recovery-emails")]
pub async fn add_recovery_email(
    pool: web::Data<DbPool>,
    email_service: web::Data<EmailService>,
    dto: web::Json<AddRecoveryEmailDto>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Extrair ID do usuário do token
    let user_id = extract_user_id(&req)?;

    // Adicionar email de recuperação
    let recovery_email = RecoveryEmailService::add_recovery_email(
        &pool,
        &user_id,
        dto.into_inner(),
        &email_service,
    ).await?;

    info!("✅ Email de recuperação adicionado para usuário: {}", user_id);
    Ok(HttpResponse::Created().json(serde_json::json!({
        "message": "Email de recuperação adicionado com sucesso! Verifique sua caixa de entrada para confirmar 📧",
        "recovery_email": recovery_email
    })))
}

// Verificar um email de recuperação
#[post("/recovery-emails/verify")]
pub async fn verify_recovery_email(
    pool: web::Data<DbPool>,
    dto: web::Json<VerifyRecoveryEmailDto>,
) -> Result<HttpResponse, ApiError> {
    // Verificar email de recuperação
    let recovery_email = RecoveryEmailService::verify_recovery_email(&pool, &dto.token)?;

    info!("✅ Email de recuperação verificado: {}", recovery_email.email);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Email de recuperação verificado com sucesso! ✅",
        "recovery_email": recovery_email
    })))
}

// Listar todos os emails de recuperação do usuário
#[get("/recovery-emails")]
pub async fn list_recovery_emails(
    pool: web::Data<DbPool>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Extrair ID do usuário do token
    let user_id = extract_user_id(&req)?;

    // Listar emails de recuperação
    let emails = RecoveryEmailService::list_recovery_emails(&pool, &user_id)?;

    Ok(HttpResponse::Ok().json(emails))
}

// Remover um email de recuperação
#[delete("/recovery-emails/{id}")]
pub async fn remove_recovery_email(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Extrair ID do usuário do token
    let user_id = extract_user_id(&req)?;
    let email_id = path.into_inner();

    // Remover email de recuperação
    RecoveryEmailService::remove_recovery_email(&pool, &user_id, &email_id)?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Email de recuperação removido com sucesso! 🗑️"
    })))
}

// Reenviar email de verificação
#[post("/recovery-emails/{id}/resend")]
pub async fn resend_verification_email(
    pool: web::Data<DbPool>,
    email_service: web::Data<EmailService>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> {
    // Extrair ID do usuário do token
    let user_id = extract_user_id(&req)?;
    let email_id = path.into_inner();

    // Reenviar email de verificação
    RecoveryEmailService::resend_verification_email(&pool, &user_id, &email_id, &email_service).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Email de verificação reenviado com sucesso! 📤"
    })))
}
