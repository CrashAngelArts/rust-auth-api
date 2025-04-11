use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::header,
    Error,
};
use csrf::{ChaCha20Poly1305CsrfProtection, CsrfProtection};
use futures::future::{ready, Ready, LocalBoxFuture};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    rc::Rc,
};
use tracing::{error, info};

// Middleware para adicionar cabeçalhos de segurança
pub struct SecurityHeaders {
    headers: HashMap<String, String>,
}

impl SecurityHeaders {
    pub fn new() -> Self {
        let mut headers = HashMap::new();
        
        // Configurações padrão de cabeçalhos de segurança
        headers.insert(
            "X-Content-Type-Options".to_string(), 
            "nosniff".to_string()
        );
        headers.insert(
            "X-Frame-Options".to_string(), 
            "DENY".to_string()
        );
        headers.insert(
            "X-XSS-Protection".to_string(), 
            "1; mode=block".to_string()
        );
        headers.insert(
            "Content-Security-Policy".to_string(), 
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'".to_string()
        );
        headers.insert(
            "Referrer-Policy".to_string(), 
            "no-referrer".to_string()
        );
        headers.insert(
            "Strict-Transport-Security".to_string(), 
            "max-age=31536000; includeSubDomains".to_string()
        );
        
        Self { headers }
    }
    
    // Adiciona ou substitui um cabeçalho personalizado
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_string(), value.to_string());
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware {
            service: Rc::new(service),
            security_headers: self.clone(),
        }))
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: Rc<S>,
    security_headers: SecurityHeaders,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
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
        let headers = self.security_headers.headers.clone();

        Box::pin(async move {
            let mut res = service.call(req).await?;
            
            // Adicionar cabeçalhos de segurança à resposta
            for (name, value) in headers.iter() {
                if let Ok(header_name) = header::HeaderName::from_bytes(name.as_bytes()) {
                    if let Ok(header_value) = header::HeaderValue::from_str(value) {
                        res.headers_mut().insert(header_name, header_value);
                    }
                }
            }
            
            Ok(res)
        })
    }
}

// Middleware para proteção CSRF
pub struct CsrfProtectionMiddleware {
    secret_key: [u8; 32],
}

impl CsrfProtectionMiddleware {
    pub fn new(secret: &str) -> Self {
        // Derivar uma chave de 32 bytes do segredo fornecido
        let mut key = [0u8; 32];
        let bytes = secret.as_bytes();
        let len = std::cmp::min(bytes.len(), 32);
        key[..len].copy_from_slice(&bytes[..len]);
        
        Self { secret_key: key }
    }
}

impl<S, B> Transform<S, ServiceRequest> for CsrfProtectionMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CsrfProtectionService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let csrf = ChaCha20Poly1305CsrfProtection::from_key(self.secret_key);
        ready(Ok(CsrfProtectionService {
            service: Rc::new(service),
            csrf: Rc::new(csrf),
        }))
    }
}

pub struct CsrfProtectionService<S> {
    service: Rc<S>,
    csrf: Rc<ChaCha20Poly1305CsrfProtection>,
}

impl<S, B> Service<ServiceRequest> for CsrfProtectionService<S>
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
        let csrf = Rc::clone(&self.csrf);
        
        Box::pin(async move {
            // Verificar se é um método seguro (GET, HEAD, OPTIONS, TRACE)
            let method = req.method().clone();
            if method.is_safe() {
                // Métodos seguros não precisam de verificação CSRF
                return service.call(req).await;
            }
            
            // Para métodos não seguros (POST, PUT, DELETE, etc.), verificar token CSRF
            let csrf_cookie = req.cookie("csrf_token");
            let csrf_header = req.headers().get("X-CSRF-Token")
                .and_then(|h| h.to_str().ok());
            
            match (csrf_cookie, csrf_header) {
                (Some(cookie), Some(header)) => {
                    // Verificar se o token do cookie e do cabeçalho são válidos
                    // Converter strings para tipos específicos do CSRF
                    let cookie_str = cookie.value();
                    let header_str = header;
                    
                    // Verificar o par de tokens
                    // Converter as strings para bytes
                    let header_bytes = header_str.as_bytes().to_vec();
                    let cookie_parts: Vec<&str> = cookie_str.split('|').collect();
                    
                    if cookie_parts.len() == 2 {
                        if let Ok(expires) = cookie_parts[0].parse::<i64>() {
                            let cookie_token = cookie_parts[1].as_bytes().to_vec();
                            
                            // Criar os tokens usando os construtores new
                            let token = csrf::UnencryptedCsrfToken::new(header_bytes);
                            let cookie = csrf::UnencryptedCsrfCookie::new(expires, cookie_token);
                            if csrf.verify_token_pair(&token, &cookie) {
                                // Token válido, continuar com a requisição
                                let res = service.call(req).await?;
                                Ok(res)
                            } else {
                                // Token inválido, registrar e rejeitar
                                error!("🔒 Falha na validação CSRF: tokens não correspondem");
                                Err(actix_web::error::ErrorForbidden("Token CSRF inválido").into())
                            }
                        } else {
                            // Formato de cookie inválido
                            error!("🔒 Falha na validação CSRF: formato de cookie inválido");
                            Err(actix_web::error::ErrorForbidden("Token CSRF inválido").into())
                        }
                    } else {
                        // Formato de cookie inválido
                        error!("🔒 Falha na validação CSRF: formato de cookie inválido");
                        Err(actix_web::error::ErrorForbidden("Token CSRF inválido").into())
                    }
                },
                _ => {
                    // Token ausente, registrar e rejeitar
                    error!("🔒 Falha na validação CSRF: token ausente");
                    Err(actix_web::error::ErrorForbidden("Token CSRF ausente").into())
                }
            }
        })
    }
}

// Função para gerar um novo token CSRF
pub fn generate_csrf_token(secret: &str) -> (String, String) {
    // Derivar uma chave de 32 bytes do segredo fornecido
    let mut key = [0u8; 32];
    let bytes = secret.as_bytes();
    let len = std::cmp::min(bytes.len(), 32);
    key[..len].copy_from_slice(&bytes[..len]);
    
    let csrf = ChaCha20Poly1305CsrfProtection::from_key(key);
    // Gerar o par de tokens e tratar o resultado
    let result = csrf.generate_token_pair(None, 86400);
    let (cookie_value, header_value) = match result {
        Ok((token, cookie)) => (token.b64_string(), cookie.b64_string()),
        Err(e) => {
            error!("🔒 Erro ao gerar tokens CSRF: {}", e);
            (String::new(), String::new())
        }
    };
    
    (cookie_value, header_value)
}

// Implementação de Clone para SecurityHeaders
impl Clone for SecurityHeaders {
    fn clone(&self) -> Self {
        Self {
            headers: self.headers.clone(),
        }
    }
}

// Função para configurar middleware de segurança
pub fn configure_security(jwt_secret: &str) -> (SecurityHeaders, CsrfProtectionMiddleware) {
    info!("✅ Configurando middlewares de segurança");
    (
        SecurityHeaders::new(),
        CsrfProtectionMiddleware::new(jwt_secret),
    )
}
