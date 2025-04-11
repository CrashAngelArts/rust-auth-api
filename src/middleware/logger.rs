use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures::future::{ready, Ready};
use futures::Future;
use tracing::{debug, info};
use std::{
    pin::Pin,
    rc::Rc,
    time::Instant,
};

// Middleware para logging de requisições
pub struct RequestLogger;

impl RequestLogger {
    pub fn new() -> Self {
        Self {}
    }
}

// Implementação do Transform para o middleware
impl<S, B> Transform<S, ServiceRequest> for RequestLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequestLoggerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestLoggerMiddleware {
            service: Rc::new(service),
        }))
    }
}

// Middleware para logging de requisições
pub struct RequestLoggerMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestLoggerMiddleware<S>
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
        let start_time = Instant::now();
        
        // Extrai informações da requisição
        let method = req.method().clone();
        let path = req.path().to_owned();
        let remote_addr = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_owned();
        
        // Log de início da requisição
        debug!("🔍 Requisição iniciada: {} {} de {}", method, path, remote_addr);
        
        Box::pin(async move {
            // Executa o serviço
            let res = service.call(req).await?;
            
            // Calcula o tempo de resposta
            let elapsed = start_time.elapsed();
            
            // Log de finalização da requisição
            let status = res.status();
            let status_code = status.as_u16();
            
            // Escolhe o emoji e a cor com base no status
            let (emoji, status_str) = match status_code {
                100..=199 => ("ℹ️", format!("\x1b[94m{}\x1b[0m", status_code)), // Azul claro
                200..=299 => ("✅", format!("\x1b[92m{}\x1b[0m", status_code)), // Verde
                300..=399 => ("↪️", format!("\x1b[96m{}\x1b[0m", status_code)), // Ciano
                400..=499 => ("⚠️", format!("\x1b[93m{}\x1b[0m", status_code)), // Amarelo
                _ => ("❌", format!("\x1b[91m{}\x1b[0m", status_code)),         // Vermelho
            };
            
            info!(
                "{} {} {} {} - {} - {:.2?}",
                emoji, method, path, status_str, remote_addr, elapsed
            );
            
            Ok(res)
        })
    }
}
