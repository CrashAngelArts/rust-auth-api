use crate::errors::ApiError;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform}, Error,
};
use futures::future::{ready, Ready};
use futures::Future;
use log::warn;
use std::{
    collections::HashMap,
    pin::Pin,
    rc::Rc,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

// Estrutura para armazenar informações de limite de taxa
struct RateLimitInfo {
    requests: u32,
    last_reset: Instant,
}

// Middleware para limitação de taxa
pub struct RateLimiter {
    max_requests: u32,
    duration: Duration,
    store: Arc<Mutex<HashMap<String, RateLimitInfo>>>,
}

impl RateLimiter {
    pub fn new(max_requests: u32, duration_seconds: u32) -> Self {
        Self {
            max_requests,
            duration: Duration::from_secs(duration_seconds as u64),
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// Implementação do Transform para o middleware
impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterMiddleware {
            service: Rc::new(service),
            max_requests: self.max_requests,
            duration: self.duration,
            store: self.store.clone(),
        }))
    }
}

// Middleware para limitação de taxa
pub struct RateLimiterMiddleware<S> {
    service: Rc<S>,
    max_requests: u32,
    duration: Duration,
    store: Arc<Mutex<HashMap<String, RateLimitInfo>>>,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
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
        let max_requests = self.max_requests;
        let duration = self.duration;
        let store = self.store.clone();
        
        // Obtém o endereço IP do cliente
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_owned();
        
        Box::pin(async move {
            // Verifica se o cliente já atingiu o limite
            let now = Instant::now();
            let mut store = store.lock().unwrap();
            
            // Obtém ou cria as informações de limite para o cliente
            let info = store.entry(client_ip.clone()).or_insert(RateLimitInfo {
                requests: 0,
                last_reset: now,
            });
            
            // Verifica se o período de limite expirou
            if now.duration_since(info.last_reset) > duration {
                // Reseta o contador
                info.requests = 0;
                info.last_reset = now;
            }
            
            // Incrementa o contador
            info.requests += 1;
            
            // Verifica se o cliente excedeu o limite
            if info.requests > max_requests {
                // Calcula o tempo restante para o reset
                let reset_after = duration.as_secs() as f64 - now.duration_since(info.last_reset).as_secs_f64();
                
                // Log de aviso
                warn!(
                    "🚫 Limite de taxa excedido para IP: {}. Requisições: {}/{}. Reset em: {:.2}s",
                    client_ip, info.requests, max_requests, reset_after
                );
                
                // Retorna erro de limite excedido
                return Err(ApiError::RateLimitExceededError(format!(
                    "Limite de requisições excedido. Tente novamente em {:.0} segundos",
                    reset_after.ceil()
                ))
                .into());
            }
            
            // Continua o processamento
            let res = service.call(req).await?;
            Ok(res)
        })
    }
}
