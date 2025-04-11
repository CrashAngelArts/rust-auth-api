use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::{header::{HeaderName, HeaderValue}, StatusCode},
    Error,
};
use futures::future::{ok, Ready};
use futures::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use std::collections::HashMap;
use crate::errors::{ApiError, ErrorResponse};
use std::rc::Rc;

// Estrutura para armazenar tentativas de verificação por usuário
struct KeystrokeAttempts {
    attempts: Vec<Instant>,
    blocked_until: Option<Instant>,
}

// Configuração do rate limiter específico para keystroke
pub struct KeystrokeRateLimiter {
    max_attempts: usize,
    window_duration: Duration,
    block_duration: Duration,
    attempts_map: Arc<Mutex<HashMap<String, KeystrokeAttempts>>>,
}

impl KeystrokeRateLimiter {
    pub fn new(max_attempts: usize, window_duration: Duration, block_duration: Duration) -> Self {
        KeystrokeRateLimiter {
            max_attempts,
            window_duration,
            block_duration,
            attempts_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Configuração padrão: 5 tentativas em 1 minuto, bloqueio por 5 minutos
    pub fn default() -> Self {
        Self::new(
            5,
            Duration::from_secs(60),
            Duration::from_secs(300),
        )
    }
}

impl<S, B> Transform<S, ServiceRequest> for KeystrokeRateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = KeystrokeRateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(KeystrokeRateLimiterMiddleware {
            service: Rc::new(service),
            max_attempts: self.max_attempts,
            window_duration: self.window_duration,
            block_duration: self.block_duration,
            attempts_map: self.attempts_map.clone(),
        })
    }
}

pub struct KeystrokeRateLimiterMiddleware<S> {
    service: Rc<S>,
    max_attempts: usize,
    window_duration: Duration,
    block_duration: Duration,
    attempts_map: Arc<Mutex<HashMap<String, KeystrokeAttempts>>>,
}

impl<S, B> Service<ServiceRequest> for KeystrokeRateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Extrair o user_id da URL
        let user_id = match req.match_info().get("user_id") {
            Some(id) => id.to_string(),
            None => {
                // Se não houver user_id, apenas passa a requisição adiante
                let fut = self.service.call(req);
                return Box::pin(async move {
                    fut.await
                });
            }
        };

        // Verificar se é uma rota de verificação de keystroke
        let path = req.path().to_string();
        if !path.contains("/keystroke/verify") {
            // Se não for uma rota de verificação, apenas passa a requisição adiante
            let fut = self.service.call(req);
            return Box::pin(async move {
                fut.await
            });
        }

        let max_attempts = self.max_attempts;
        let window_duration = self.window_duration;
        let block_duration = self.block_duration;
        let attempts_map = self.attempts_map.clone();
        let service = self.service.clone();

        Box::pin(async move {
            let now = Instant::now();
            let mut map = attempts_map.lock().await;
            
            // Obter ou criar entrada para o usuário
            let entry = map.entry(user_id.clone()).or_insert(KeystrokeAttempts {
                attempts: Vec::new(),
                blocked_until: None,
            });

            // Verificar se o usuário está bloqueado
            if let Some(blocked_until) = entry.blocked_until {
                if now < blocked_until {
                    // Usuário ainda está bloqueado
                    let remaining = blocked_until.duration_since(now).as_secs();
                    let error = ErrorResponse {
                        status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                        message: format!("Muitas tentativas de verificação. Tente novamente em {} segundos 🔒", remaining),
                        error_code: "KEYSTROKE_RATE_LIMITED".to_string(),
                        error_details: Some(format!("Limite de {} tentativas excedido. Bloqueado por {} segundos.", max_attempts, block_duration.as_secs())),
                        validation_details: None,
                    };
                    
                    return Err(ApiError::RateLimited(error).into());
                } else {
                    // Bloqueio expirou, limpar tentativas
                    entry.blocked_until = None;
                    entry.attempts.clear();
                }
            }

            // Limpar tentativas antigas
            let window_start = now - window_duration;
            entry.attempts.retain(|&attempt| attempt >= window_start);

            // Verificar número de tentativas na janela de tempo
            if entry.attempts.len() >= max_attempts {
                // Bloquear o usuário
                entry.blocked_until = Some(now + block_duration);
                
                let error = ErrorResponse {
                    status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                    message: format!("Muitas tentativas de verificação. Tente novamente em {} segundos 🔒", block_duration.as_secs()),
                    error_code: "KEYSTROKE_RATE_LIMITED".to_string(),
                    error_details: Some(format!("Limite de {} tentativas excedido. Bloqueado por {} segundos.", max_attempts, block_duration.as_secs())),
                    validation_details: None,
                };
                
                return Err(ApiError::RateLimited(error).into());
            }

            // Registrar esta tentativa
            entry.attempts.push(now);

            // Adicionar headers de rate limit
            let fut = service.call(req);
            let mut res = fut.await?;
            
            // Adicionar headers informativos
            let remaining = max_attempts - entry.attempts.len();
            let reset = window_duration.as_secs() - entry.attempts.first()
                .map(|t| now.duration_since(*t).as_secs())
                .unwrap_or(0);
            
            let headers = res.headers_mut();
            headers.insert(HeaderName::from_static("x-ratelimit-limit"), 
                          HeaderValue::from(max_attempts as u32));
            headers.insert(HeaderName::from_static("x-ratelimit-remaining"), 
                          HeaderValue::from(remaining as u32));
            headers.insert(HeaderName::from_static("x-ratelimit-reset"), 
                          HeaderValue::from(reset as u32));

            Ok(res)
        })
    }
}

// Função para limpar entradas antigas periodicamente
pub async fn clean_keystroke_rate_limit_entries(attempts_map: Arc<Mutex<HashMap<String, KeystrokeAttempts>>>) {
    let now = Instant::now();
    let mut map = attempts_map.lock().await;
    
    // Remover entradas expiradas
    map.retain(|_, entry| {
        if let Some(blocked_until) = entry.blocked_until {
            if now > blocked_until {
                // Bloqueio expirou
                return false;
            }
        }
        
        // Remover entradas sem tentativas recentes
        if entry.attempts.is_empty() {
            return false;
        }
        
        true
    });
}
