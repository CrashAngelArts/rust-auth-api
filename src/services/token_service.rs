use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::token::{BlacklistedToken, TokenClaims};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use tracing::info;
use uuid::Uuid;


pub struct TokenService;

impl TokenService {
    // Gera um novo token JWT com suporte a rotação
    pub fn generate_token(
        user_id: &str, 
        token_family: &str, 
        is_2fa_verified: bool,
        expiry_minutes: i64,
        secret: &str
    ) -> Result<(String, String), ApiError> {
        let now = Utc::now();
        let expiry = now + Duration::minutes(expiry_minutes);
        let token_id = Uuid::new_v4().to_string();
        
        // Claims para o token
        let claims = TokenClaims {
            sub: user_id.to_string(),
            exp: expiry.timestamp(),
            iat: now.timestamp(),
            jti: token_id.clone(),
            fam: token_family.to_string(),
            tfv: if is_2fa_verified { Some(true) } else { None },
        };
        
        // Codificar o token
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        ).map_err(|e| ApiError::InternalServerError(format!("Erro ao gerar token: {}", e)))?;
        
        Ok((token, token_id))
    }
    
    // Valida um token JWT e verifica se não está na lista negra
    pub fn validate_token(
        token: &str, 
        secret: &str,
        pool: &DbPool,
        require_2fa: bool
    ) -> Result<TokenClaims, ApiError> {
        // Decodificar o token
        let token_data = decode::<TokenClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        ).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    ApiError::AuthenticationError("Token expirado".to_string())
                },
                _ => ApiError::AuthenticationError(format!("Token inválido: {}", e)),
            }
        })?;
        
        let claims = token_data.claims;
        
        // Verificar se o token está na lista negra
        if Self::is_token_blacklisted(pool, &claims.jti)? {
            return Err(ApiError::AuthenticationError("Token revogado".to_string()));
        }
        
        // Verificar se o 2FA é necessário e foi verificado
        if require_2fa && claims.tfv != Some(true) {
            return Err(ApiError::AuthenticationError("Verificação 2FA necessária".to_string()));
        }
        
        Ok(claims)
    }
    
    // Adiciona um token à lista negra
    pub fn blacklist_token(
        pool: &DbPool, 
        token_id: &str, 
        expiry: DateTime<Utc>
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        let blacklisted_token = BlacklistedToken::new(token_id.to_string(), expiry);
        
        conn.execute(
            "INSERT INTO token_blacklist (id, token_id, expiry, created_at) VALUES (?1, ?2, ?3, ?4)",
            (
                &blacklisted_token.id,
                &blacklisted_token.token_id,
                &blacklisted_token.expiry,
                &blacklisted_token.created_at,
            ),
        )?;
        
        info!("🚫 Token adicionado à lista negra: {}", token_id);
        
        Ok(())
    }
    
    // Verifica se um token está na lista negra
    pub fn is_token_blacklisted(pool: &DbPool, token_id: &str) -> Result<bool, ApiError> {
        let conn = pool.get()?;
        
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM token_blacklist WHERE token_id = ?1",
            [token_id],
            |row| row.get(0),
        )?;
        
        Ok(count > 0)
    }
    
    // Limpa tokens expirados da lista negra
    pub fn clean_expired_tokens(pool: &DbPool) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        
        let now = Utc::now();
        
        let count = conn.execute(
            "DELETE FROM token_blacklist WHERE expiry < ?1",
            [now],
        )?;
        
        if count > 0 {
            info!("🧹 {} tokens expirados removidos da lista negra", count);
        }
        
        Ok(count)
    }
    
    // Rotaciona um token JWT (para refresh tokens)
    pub fn rotate_token(
        pool: &DbPool,
        old_token: &str,
        secret: &str,
        expiry_minutes: i64,
        invalidate_family: bool
    ) -> Result<(String, String, String), ApiError> {
        // Validar o token antigo (sem verificar 2FA)
        let claims = Self::validate_token(old_token, secret, pool, false)?;
        
        // Adicionar o token antigo à lista negra
        let expiry = Utc::now() + Duration::minutes(5); // Pequena janela para evitar race conditions
        Self::blacklist_token(pool, &claims.jti, expiry)?;
        
        // Se necessário, invalidar toda a família de tokens
        let token_family = if invalidate_family {
            // Gerar nova família de tokens
            let new_family = Uuid::new_v4().to_string();
            
            // Atualizar a família de tokens do usuário
            let conn = pool.get()?;
            let user_id = claims.sub.clone(); // Clone para evitar o erro de move
            conn.execute(
                "UPDATE users SET token_family = ?1, updated_at = ?2 WHERE id = ?3",
                (new_family.clone(), Utc::now(), &user_id),
            )?;
            
            info!("🔄 Família de tokens rotacionada para o usuário ID: {}", user_id);
            
            new_family
        } else {
            claims.fam
        };
        
        // Gerar novo token com a mesma (ou nova) família
        let (new_token, token_id) = Self::generate_token(
            &claims.sub,
            &token_family,
            claims.tfv.unwrap_or(false),
            expiry_minutes,
            secret
        )?;
        
        info!("🔄 Token rotacionado para o usuário ID: {}", claims.sub);
        
        Ok((new_token, token_id, token_family))
    }
}
