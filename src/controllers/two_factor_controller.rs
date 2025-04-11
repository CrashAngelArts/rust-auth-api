use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::response::ApiResponse;
use crate::models::two_factor::{Enable2FADto, Verify2FADto, Disable2FADto};
use crate::services::{user_service::UserService, two_factor_service::TwoFactorService};
use actix_web::{web, HttpResponse, Responder};
use tracing::info;
use validator::Validate;

// Inicia o processo de configuração 2FA
pub async fn setup_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    // Obter o usuário
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Verificar se o 2FA já está ativado
    if user.totp_enabled {
        return Err(ApiError::BadRequestError("Autenticação de dois fatores já está ativada".to_string()));
    }
    
    // Gerar configuração 2FA
    let setup = TwoFactorService::generate_setup(&user)?;
    
    // Atualizar o usuário com o segredo TOTP (ainda não ativado)
    let conn = pool.get()?;
    conn.execute(
        "UPDATE users SET totp_secret = ?1, updated_at = ?2 WHERE id = ?3",
        (&setup.secret, chrono::Utc::now(), &user_id.into_inner()),
    )?;
    
    info!("🔐 Configuração 2FA iniciada para o usuário: {}", user.username);
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(setup)))
}

// Ativa 2FA após verificar o código TOTP
pub async fn enable_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Enable2FADto>,
) -> Result<impl Responder, ApiError> {
    // Validar os dados
    data.validate()?;
    
    // Obter o usuário
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Verificar se o 2FA já está ativado
    if user.totp_enabled {
        return Err(ApiError::BadRequestError("Autenticação de dois fatores já está ativada".to_string()));
    }
    
    // Verificar se o segredo TOTP existe
    let totp_secret = match &user.totp_secret {
        Some(secret) => secret,
        None => return Err(ApiError::BadRequestError("Configure o 2FA primeiro".to_string())),
    };
    
    // Ativar 2FA
    let response = TwoFactorService::enable_2fa(&pool, &user_id, &data.totp_code, totp_secret)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

// Desativa 2FA
pub async fn disable_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Disable2FADto>,
) -> Result<impl Responder, ApiError> {
    // Validar os dados
    data.validate()?;
    
    // Obter o usuário
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Verificar se o 2FA está ativado
    if !user.totp_enabled {
        return Err(ApiError::BadRequestError("Autenticação de dois fatores não está ativada".to_string()));
    }
    
    // Verificar a senha
    if !UserService::verify_password(&data.password, &user.password_hash)? {
        return Err(ApiError::AuthenticationError("Senha incorreta".to_string()));
    }
    
    // Verificar o código TOTP
    let totp_secret = match &user.totp_secret {
        Some(secret) => secret,
        None => return Err(ApiError::InternalServerError("Erro na configuração 2FA".to_string())),
    };
    
    if !TwoFactorService::verify_totp(totp_secret, &data.totp_code)? {
        return Err(ApiError::AuthenticationError("Código TOTP inválido".to_string()));
    }
    
    // Desativar 2FA
    TwoFactorService::disable_2fa(&pool, &user_id)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": "Autenticação de dois fatores desativada com sucesso",
        "enabled": false
    }))))
}

// Regenera códigos de backup
pub async fn regenerate_backup_codes(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Verify2FADto>,
) -> Result<impl Responder, ApiError> {
    // Validar os dados
    data.validate()?;
    
    // Obter o usuário
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Verificar se o 2FA está ativado
    if !user.totp_enabled {
        return Err(ApiError::BadRequestError("Autenticação de dois fatores não está ativada".to_string()));
    }
    
    // Verificar o código TOTP
    let totp_secret = match &user.totp_secret {
        Some(secret) => secret,
        None => return Err(ApiError::InternalServerError("Erro na configuração 2FA".to_string())),
    };
    
    if !TwoFactorService::verify_totp(totp_secret, &data.totp_code)? {
        return Err(ApiError::AuthenticationError("Código TOTP inválido".to_string()));
    }
    
    // Regenerar códigos de backup
    let backup_codes = TwoFactorService::regenerate_backup_codes(&pool, &user_id)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": "Códigos de backup regenerados com sucesso",
        "backup_codes": backup_codes
    }))))
}

// Verifica o status do 2FA
pub async fn get_2fa_status(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    // Obter o usuário
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Retornar o status
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "enabled": user.totp_enabled,
        "created_at": user.updated_at.to_rfc3339()
    }))))
}
