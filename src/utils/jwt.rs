use crate::errors::ApiError;
use crate::models::auth::TokenClaims;
use actix_web::{HttpRequest, HttpMessage};

/// Extrai o ID do usuário do token JWT na requisição
pub fn extract_user_id(req: &HttpRequest) -> Result<String, ApiError> {
    // Obter as claims do token JWT das extensões da requisição
    let claims = req.extensions().get::<TokenClaims>()
        .cloned()
        .ok_or_else(|| ApiError::AuthenticationError("Usuário não autenticado 🔒".to_string()))?;
    
    Ok(claims.sub)
}

/// Verifica se o usuário é administrador
pub fn is_admin(req: &HttpRequest) -> Result<bool, ApiError> {
    // Obter as claims do token JWT das extensões da requisição
    let claims = req.extensions().get::<TokenClaims>()
        .cloned()
        .ok_or_else(|| ApiError::AuthenticationError("Usuário não autenticado 🔒".to_string()))?;
    
    Ok(claims.is_admin)
}
