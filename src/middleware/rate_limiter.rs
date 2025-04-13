use crate::errors::ApiError;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform}, Error,
};
use futures::future::{ready, Ready};
use futures::Future;
use tracing::warn;
use std::{
    collections::HashMap,
    pin::Pin,
    rc::Rc,
    sync::{Arc, Mutex},
    time::{Instant},
};

// Estrutura para armazenar informações do Token Bucket
#[derive(Debug, Clone)]
struct TokenBucketInfo {
    tokens: f64, // Número atual de tokens (pode ser fracionado)
    last_refill_time: Instant, // Momento da última recarga/verificação
}

// Middleware para limitação de taxa (Token Bucket)
#[derive(Clone)] // Adicionado Clone para uso no Transform
pub struct RateLimiter {
    capacity: f64, // <-- Corrigido: Capacidade máxima de tokens no balde
    refill_rate: f64, // <-- Corrigido: Tokens adicionados por segundo
    store: Arc<Mutex<HashMap<String, TokenBucketInfo>>>,
}

impl RateLimiter {
    /// Cria um novo Rate Limiter com o algoritmo Token Bucket.
    ///
    /// # Arguments
    ///
    /// * `capacity` - A capacidade máxima de tokens que o balde pode conter (ex: 100).
    /// * `refill_rate` - A taxa na qual os tokens são adicionados ao balde (tokens por segundo, ex: 10.0).
    pub fn new(capacity: u32, refill_rate: f64) -> Self { // <-- Assinatura corrigida
        if refill_rate <= 0.0 {
            panic!("A taxa de recarga (refill_rate) deve ser positiva.");
        }
        if capacity == 0 {
             panic!("A capacidade (capacity) deve ser positiva.");
        }
        warn!(capacity, refill_rate, "🚦 Inicializando RateLimiter (Token Bucket)");
        Self {
            capacity: capacity as f64, // <-- Corpo corrigido
            refill_rate,            // <-- Corpo corrigido
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
            capacity: self.capacity,    // Passa capacity (f64)
            refill_rate: self.refill_rate, // Passa refill_rate (f64)
            store: self.store.clone(),
        }))
    }
}

// Middleware real para limitação de taxa (Token Bucket)
pub struct RateLimiterMiddleware<S> {
    service: Rc<S>,
    capacity: f64,    // Armazena capacity (f64)
    refill_rate: f64, // Armazena refill_rate (f64)
    store: Arc<Mutex<HashMap<String, TokenBucketInfo>>>,
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
        let capacity = self.capacity;
        let refill_rate = self.refill_rate;
        let store = self.store.clone();

        // Obtém o endereço IP do cliente
        let client_ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_owned();

        Box::pin(async move {
            let now = Instant::now();
            let mut store_guard = store.lock().expect("Mutex do RateLimiter está poisoned"); // Usar expect para erro claro

            // Obtém ou cria as informações do bucket para o cliente IP
            // .entry().or_insert_with() é mais eficiente que .entry().or_insert() se a criação for cara
            let info = store_guard.entry(client_ip.clone()).or_insert_with(|| {
                warn!(ip = %client_ip, capacity, "🚦 Criando novo Token Bucket");
                TokenBucketInfo {
                    tokens: capacity, // Começa cheio
                    last_refill_time: now,
                }
            });

            // Calcula o tempo passado desde a última recarga
            let elapsed = now.duration_since(info.last_refill_time);

            // Calcula quantos tokens adicionar (evita adicionar tokens por muito tempo passado de uma vez)
            // Adiciona tokens proporcionalmente ao tempo passado
            let tokens_to_add = elapsed.as_secs_f64() * refill_rate;

            // Atualiza os tokens no balde: adiciona os novos e limita pela capacidade
            info.tokens = (info.tokens + tokens_to_add).min(capacity);

            // Atualiza o tempo da última recarga para o momento atual
            info.last_refill_time = now;

            // Verifica se há tokens suficientes para a requisição (precisamos de pelo menos 1)
            if info.tokens >= 1.0 {
                // Consome um token
                info.tokens -= 1.0;
                // Drop store_guard para liberar o Mutex antes de chamar o serviço interno
                drop(store_guard);

                // Log de sucesso (opcional, pode ser verboso)
                // trace!(ip=%client_ip, tokens_remaining=info.tokens, "🚦 Token consumido");

                // Continua o processamento
                let res = service.call(req).await?;
                Ok(res)
            } else {
                // Calcula tempo estimado até o próximo token (opcional, para mensagem de erro)
                let time_to_next_token = (1.0 - info.tokens) / refill_rate;

                // Log de aviso
                warn!(
                    ip = %client_ip,
                    tokens = format!("{:.2}", info.tokens), // Loga tokens restantes
                    capacity,
                    refill_rate,
                    wait_estimated = format!("{:.2}", time_to_next_token),
                    "🚫 Limite de taxa (Token Bucket) excedido"
                );

                 // Drop store_guard para liberar o Mutex antes de retornar o erro
                drop(store_guard);

                // Retorna erro de limite excedido
                Err(ApiError::RateLimitExceededError(format!(
                    "Limite de requisições excedido. Tente novamente em {:.0} segundos",
                    time_to_next_token.ceil() // Arredonda para cima
                ))
                .into())
            }
        })
    }
}
