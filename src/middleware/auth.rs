use crate::errors::ApiError;
use crate::models::auth::TokenClaims;
use crate::services::auth_service::AuthService;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    Error, HttpMessage, FromRequest,
};
use futures::future::{ready, Ready, LocalBoxFuture};
use std::future::Future;
use std::pin::Pin;
use tracing::warn;
use std::rc::Rc;
use actix_web::web;
use moka::future::Cache;
use tracing::error; 

// Estrutura para representar um usuário autenticado
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_admin: bool,
}

// Implementação do FromRequest para obter o usuário autenticado
impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();
        
        Box::pin(async move {
            // Obter as claims do token JWT das extensões da requisição
            let claims = req.extensions().get::<TokenClaims>()
                .cloned()
                .ok_or_else(|| ApiError::AuthenticationError("Usuário não autenticado".to_string()))?;
            
            // Criar o usuário autenticado a partir das claims
            let user = AuthenticatedUser {
                id: claims.sub,
                username: claims.username,
                email: claims.email,
                is_admin: claims.is_admin,
            };
            
            Ok(user)
        })
    }
}

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

        // Obter o cache de token dos dados da aplicação (referência)
        let token_cache_data = req.app_data::<web::Data<Cache<String, TokenClaims>>>();

        // Extrair o token do cabeçalho (Option<&str>)
        let token_opt = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .filter(|s| s.starts_with("Bearer "))
            .map(|s| &s[7..]);
        
        // Precisamos de uma cópia 'Owned' do token para o contexto async
        let token_owned_opt: Option<String> = token_opt.map(str::to_string);
        
        // Obter referência clonável ao cache
        let cache_clone = match token_cache_data {
            Some(cache) => cache.clone(), // Clona o web::Data<Cache>, que é barato (Arc)
            None => {
                return Box::pin(async move {
                    error!(" Cache de token não encontrado nos dados da aplicação!");
                    Err(ApiError::InternalServerError("Erro interno de configuração do servidor".to_string()).into())
                });
            }
        };

        Box::pin(async move {
            // Validar apenas se o token foi extraído corretamente
            let token = match token_owned_opt {
                Some(t) => t,
                None => {
                     return Err(ApiError::AuthenticationError("Token não fornecido ou mal formatado".to_string()).into());
                }
            };

            // Valida o token usando o serviço e o cache
            match AuthService::validate_token(&token, &jwt_secret, None, &cache_clone).await { // Passar None como pool
                Ok(claims) => {
                    // Adiciona as claims ao contexto da requisição ORIGINAL
                    req.extensions_mut().insert(claims);
                    
                    // Adiciona o ID da sessão para uso no gerenciamento de dispositivos
                    if let Some(session_id) = req.headers().get("X-Session-ID").and_then(|h| h.to_str().ok()) {
                        req.extensions_mut().insert(session_id.to_string());
                    }
                    
                    // Continua o processamento
                    let res = service.call(req).await?;
                    Ok(res)
                }
                Err(e) => {
                    warn!(" Falha na autenticação via middleware: {}", e);
                    Err(e.into()) // Retornar o erro de validação
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
