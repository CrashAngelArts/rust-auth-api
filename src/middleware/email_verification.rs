use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::TokenClaims;
use crate::services::email_verification_service::EmailVerificationService;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, HttpMessage,
};
use futures::future::{ok, Ready};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use tracing::warn;

// Middleware para verificar se o usuário confirmou o código de email
#[derive(Clone)]
pub struct EmailVerificationCheck;

impl EmailVerificationCheck {
    pub fn new() -> Self {
        EmailVerificationCheck
    }
}

impl<S, B> Transform<S, ServiceRequest> for EmailVerificationCheck
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = EmailVerificationCheckMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(EmailVerificationCheckMiddleware {
            service: Rc::new(service),
        })
    }
}

pub struct EmailVerificationCheckMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for EmailVerificationCheckMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);

        // Verificar se o usuário tem um token JWT válido
        if let Some(claims) = req.extensions().get::<TokenClaims>() {
            let user_id = claims.sub.clone();
            
            // Obter o pool de conexão do banco de dados
            if let Some(pool) = req.app_data::<web::Data<DbPool>>() {
                // Verificar se o usuário tem um código pendente
                match EmailVerificationService::has_pending_code(&pool, &user_id) {
                    Ok(has_pending) => {
                        if has_pending {
                            // Usuário tem um código pendente, bloquear acesso
                            let fut = async move {
                                Err(ApiError::AuthenticationError(
                                    "É necessário verificar o código enviado para o seu email antes de continuar 📧".to_string(),
                                )
                                .into())
                            };
                            return Box::pin(fut);
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ Erro ao verificar código pendente: {}", e);
                        // Em caso de erro, permitir o acesso para não bloquear o usuário
                    }
                }
            }
        }

        // Continuar com a requisição
        let fut = async move { service.call(req).await };
        Box::pin(fut)
    }
}
