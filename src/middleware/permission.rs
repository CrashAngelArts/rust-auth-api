use crate::{
    db::DbPool,
    errors::ApiError,
    middleware::auth::AuthenticatedUser, // Para obter o ID do usuário logado
    services::rbac_service::RbacService,
};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web::Data, // Para acessar o DbPool
    Error, HttpMessage, // Para acessar extensões e app_data
};
use futures_util::future::{self, LocalBoxFuture, Ready};
use std::rc::Rc;
use tracing::warn;

// Fábrica do Middleware
#[derive(Clone)]
pub struct PermissionAuth {
    required_permission: String,
}

impl PermissionAuth {
    pub fn new(permission: &str) -> Self { 
        Self {
            required_permission: permission.to_string(),
        }
    }
}

// Implementação do Transform (fábrica)
impl<S, B> Transform<S, ServiceRequest> for PermissionAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = PermissionAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(PermissionAuthMiddleware {
            service: Rc::new(service),
            required_permission: self.required_permission.clone(),
        }))
    }
}

// O Middleware real
pub struct PermissionAuthMiddleware<S> {
    service: Rc<S>,
    required_permission: String,
}

// Implementação do Service (lógica principal)
impl<S, B> Service<ServiceRequest> for PermissionAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Clonar dados necessários para o contexto async
        let service = Rc::clone(&self.service);
        let required_permission = self.required_permission.clone();

        // Tentar obter o usuário autenticado das extensões
        let user_result = req.extensions().get::<AuthenticatedUser>().cloned();

        // Tentar obter o DbPool dos dados da aplicação
        let pool_result = req.app_data::<Data<DbPool>>().cloned(); // Clona o Data<DbPool> (Arc)

        // --- Início da Lógica Síncrona (dentro do Box::pin) ---
        // Verificar se conseguimos obter o usuário e o pool
        let user = match user_result {
            Some(u) => u,
            None => {
                warn!("🛡️ Falha na Autorização: Usuário não encontrado nas extensões. JwtAuth rodou?");
                return Box::pin(future::err(ApiError::AuthenticationError(
                    "Usuário não autenticado.".to_string(),
                ).into()));
            }
        };

        let pool = match pool_result {
            Some(p) => p,
            None => {
                warn!("🛡️ Falha na Autorização: DbPool não encontrado nos dados da aplicação.");
                return Box::pin(future::err(ApiError::InternalServerError(
                    "Erro interno de configuração do servidor (DbPool).".to_string(),
                ).into()));
            }
        };

        // Verificar a permissão usando o RbacService (chamada síncrona!)
        match RbacService::check_user_permission(&pool, &user.id, &required_permission) { // SEM .await
            Ok(true) => {
                // Usuário tem a permissão, prosseguir com a requisição
                 Box::pin(async move { service.call(req).await }) // Chamar o próximo serviço
            }
            Ok(false) => {
                // Usuário não tem a permissão
                warn!(
                    "🛡️ Acesso negado para usuário '{}' à permissão '{}'",
                    user.id, required_permission
                );
                 Box::pin(future::err(ApiError::AuthorizationError(format!(
                    "Acesso negado. Permissão necessária: '{}'.",
                    required_permission
                ))
                .into()))
            }
            Err(e) => {
                // Erro ao verificar permissão (ex: erro de banco de dados)
                warn!(
                    "🛡️ Erro ao verificar permissão '{}' para usuário '{}': {}",
                    required_permission, user.id, e
                );
                 Box::pin(future::err(e.into())) // Propagar o erro original
            }
        }
        // --- Fim da Lógica Síncrona ---
    }
}
