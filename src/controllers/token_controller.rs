use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::response::ApiResponse;
use crate::models::token::RefreshTokenDto;
use crate::services::token_service::TokenService;
use crate::services::user_service::UserService;
use crate::config::Config;
use actix_web::{web, HttpResponse, Responder};
use chrono::{DateTime, Utc};
use tracing::info;


// Rotaciona um token JWT
pub async fn rotate_token(
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    data: web::Json<RefreshTokenDto>,
) -> Result<impl Responder, ApiError> {
    // Extrair o segredo JWT da configuração
    let jwt_secret = &config.jwt.secret;
    
    // Rotacionar o token
    let (new_token, _token_id, _token_family) = TokenService::rotate_token(
        &pool,
        &data.refresh_token,
        jwt_secret,
        config.jwt.refresh_expiration_days * 24 * 60, // Converter dias para minutos
        false // Não invalidar a família de tokens
    )?;
    
    // Obter o usuário a partir das claims do token
    let claims = TokenService::validate_token(&new_token, jwt_secret, &pool, false)?;
    let user = UserService::get_user_by_id(&pool, &claims.sub)?;
    
    // Criar a resposta
    let response = serde_json::json!({
        "access_token": new_token,
        "refresh_token": data.refresh_token.clone(), // Mantém o mesmo refresh token
        "token_type": "Bearer",
        "expires_in": 3600, // Valor fixo de 1 hora em segundos
        "user_id": user.id,
        "username": user.username
    });
    
    info!("🔄 Token rotacionado com sucesso para o usuário: {}", user.username);
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

// Revoga um token JWT
pub async fn revoke_token(
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    data: web::Json<RefreshTokenDto>,
) -> Result<impl Responder, ApiError> {
    // Extrair o segredo JWT da configuração
    let jwt_secret = &config.jwt.secret;
    
    // Validar o token
    let claims = TokenService::validate_token(&data.refresh_token, jwt_secret, &pool, false)?;
    
    // Adicionar o token à lista negra
    let expiry = DateTime::from_timestamp(claims.exp, 0)
        .ok_or_else(|| ApiError::InternalServerError("Erro ao converter timestamp".to_string()))?;
    
    TokenService::blacklist_token(&pool, &claims.jti, expiry)?;
    
    info!("🚫 Token revogado com sucesso para o usuário ID: {}", claims.sub);
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": "Token revogado com sucesso",
        "revoked_at": Utc::now().to_rfc3339()
    }))))
}

// Revoga todos os tokens de um usuário (logout de todos os dispositivos)
pub async fn revoke_all_tokens(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> {
    // Obter o usuário
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Gerar nova família de tokens
    let new_family = uuid::Uuid::new_v4().to_string();
    
    // Atualizar a família de tokens do usuário
    let conn = pool.get()?;
    conn.execute(
        "UPDATE users SET token_family = ?1, updated_at = ?2 WHERE id = ?3",
        (new_family, Utc::now(), &user_id.into_inner()),
    )?;
    
    info!("🔄 Todos os tokens revogados para o usuário: {}", user.username);
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": "Todos os tokens foram revogados com sucesso",
        "revoked_at": Utc::now().to_rfc3339()
    }))))
}

// Limpa tokens expirados da lista negra (tarefa de manutenção)
pub async fn clean_expired_tokens(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> {
    // Limpar tokens expirados
    let count = TokenService::clean_expired_tokens(&pool)?;
    
    // Retornar a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "message": format!("{} tokens expirados foram removidos da lista negra", count),
        "cleaned_at": Utc::now().to_rfc3339(),
        "count": count
    }))))
}
