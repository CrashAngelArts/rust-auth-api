use crate::errors::ApiError;
use crate::models::auth::TokenClaims;
use actix_web::{HttpRequest, HttpMessage};
use jsonwebtoken::{decode, DecodingKey, TokenData, Validation};

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

/// Utilitários para JWT
pub struct JwtUtils;

impl JwtUtils {
    /// Verifica um token JWT e retorna as claims
    pub fn verify(jwt_secret: &str, token: &str) -> Result<TokenClaims, ApiError> {
        // Configurar a validação
        let mut validation = Validation::default();
        validation.validate_exp = true;
        validation.validate_nbf = true;
        
        // Decodificar o token
        let token_data: TokenData<TokenClaims> = decode(
            token, 
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &validation
        ).map_err(|e| {
            ApiError::AuthenticationError(format!("Token inválido: {} 🔒", e))
        })?;
        
        Ok(token_data.claims)
    }
}
