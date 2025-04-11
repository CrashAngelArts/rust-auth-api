use crate::errors::{log_error, ApiError};
use crate::models::response::ApiResponse;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::StatusCode, Error,
};
use futures::future::{ready, Ready};
use futures::Future;
use tracing::error;
use std::{
    pin::Pin,
    rc::Rc,
};

// Middleware para tratamento de erros
pub struct ErrorHandler;

impl ErrorHandler {
    pub fn new() -> Self {
        Self {}
    }
}

// Implementação do Transform para o middleware
impl<S, B> Transform<S, ServiceRequest> for ErrorHandler
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = ErrorHandlerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ErrorHandlerMiddleware {
            service: Rc::new(service),
        }))
    }
}

// Middleware para tratamento de erros
pub struct ErrorHandlerMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for ErrorHandlerMiddleware<S>
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

        Box::pin(async move {
            // Tenta executar o serviço
            let result = service.call(req).await;

            // Se ocorrer um erro, trata-o
            match result {
                Ok(res) => Ok(res),
                Err(err) => {
                    // Converte o erro para ApiError, se possível
                    if let Some(api_error) = err.as_error::<ApiError>() {
                        // Registra o erro
                        log_error(api_error);
                        
                        // Retorna a resposta de erro
                        Err(err)
                    } else {
                        // Erro não reconhecido
                        error!("❌ Erro não tratado: {:?}", err);
                        
                        // Cria uma resposta de erro genérica
                        let error_response = ApiResponse::<()>::error("Erro interno do servidor");
                        
                        Err(actix_web::error::InternalError::new(
                            error_response,
                            StatusCode::INTERNAL_SERVER_ERROR,
                        )
                        .into())
                    }
                }
            }
        })
    }
}
