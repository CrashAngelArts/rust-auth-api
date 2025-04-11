use crate::errors::ApiError;
use crate::models::auth::TokenClaims;
use crate::services::auth_service::AuthService;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    Error, HttpMessage,
};
use futures::future::{ready, Ready, LocalBoxFuture};

use tracing::warn;
use std::rc::Rc;

// Middleware para autenticação JWT
pub struct JwtAuth {
    pub jwt_secret: String,
}

impl JwtAuth {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }
}

impl Clone for JwtAuth {
    fn clone(&self) -> Self {
        Self {
            jwt_secret: self.jwt_secret.clone(),
        }
    }
}

// Implementação do Transform para o middleware
impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddleware {
            service: Rc::new(service),
            jwt_secret: self.jwt_secret.clone(),
        }))
    }
}

// Middleware para autenticação JWT
pub struct JwtAuthMiddleware<S> {
    service: Rc<S>,
    jwt_secret: String,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let jwt_secret = self.jwt_secret.clone();

        Box::pin(async move {
            // Extrai o token do cabeçalho Authorization
            let auth_header = req
                .headers()
                .get("Authorization")
                .map(|h| h.to_str().unwrap_or_default())
                .unwrap_or_default();

            // Verifica se o token está no formato Bearer
            if !auth_header.starts_with("Bearer ") {
                return Err(ApiError::AuthenticationError("Token não fornecido".to_string()).into());
            }

            // Extrai o token
            let token = &auth_header[7..];

            // Valida o token
            match AuthService::validate_token(token, &jwt_secret) {
                Ok(claims) => {
                    // Adiciona as claims ao contexto da requisição
                    req.extensions_mut().insert(claims);
                    
                    // Continua o processamento
                    let res = service.call(req).await?;
                    Ok(res)
                }
                Err(e) => {
                    warn!("🔒 Falha na autenticação: {}", e);
                    Err(ApiError::AuthenticationError("Token inválido ou expirado".to_string()).into())
                }
            }
        })
    }
}

// Middleware para verificar se o usuário é administrador
pub struct AdminAuth;

impl AdminAuth {
    pub fn new() -> Self {
        Self {}
    }
}

impl Clone for AdminAuth {
    fn clone(&self) -> Self {
        Self
    }
}

// Implementação do Transform para o middleware de admin
impl<S, B> Transform<S, ServiceRequest> for AdminAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AdminAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AdminAuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

// Middleware para verificar se o usuário é administrador
pub struct AdminAuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AdminAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        Box::pin(async move {
            // Obtém as claims do contexto da requisição
            let is_admin = req.extensions().get::<TokenClaims>()
                .map(|claims| claims.is_admin)
                .unwrap_or(false);
            
            // Verifica se o usuário é administrador
            if is_admin {
                // Continua o processamento
                let res = service.call(req).await?;
                return Ok(res);
            }

            // Se não for administrador, retorna erro
            Err(ApiError::AuthorizationError("Acesso negado. Permissão de administrador necessária.".to_string()).into())
        })
    }
}
