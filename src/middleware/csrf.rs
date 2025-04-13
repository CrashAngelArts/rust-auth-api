use actix_web::{
    body::MessageBody,
    cookie::{time::Duration, Cookie, SameSite},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    http::{header, Method, StatusCode},
    Error, HttpMessage, HttpResponse, ResponseError,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64_ENGINE, Engine as _};
use futures_util::future::{self, LocalBoxFuture, Ready};
use rand::{rngs::OsRng, RngCore};
use ring::constant_time;
use std::{fmt, rc::Rc, task::{Context, Poll}};
use thiserror::Error;
use crate::config::Config;

// --- Constantes ---
const CSRF_COOKIE_NAME: &str = "csrf_token";
const CSRF_HEADER_NAME: &str = "X-CSRF-Token";
const CSRF_TOKEN_BYTE_LENGTH: usize = 32;

// --- Erro CSRF ---
#[derive(Debug, Error)]
pub enum CsrfError {
    #[error("🚫 Token CSRF ausente no cookie.")]
    MissingCookieToken,
    #[error("🚫 Token CSRF ausente no header.")]
    MissingHeaderToken,
    #[error("🚫 Falha na validação do token CSRF.")]
    TokenMismatch,
    #[error("🚫 Header CSRF contém caracteres inválidos.")]
    InvalidHeaderValue,
}

// Implementação para que o erro possa ser convertido em uma resposta HTTP
impl ResponseError for CsrfError {
    fn status_code(&self) -> StatusCode {
        StatusCode::FORBIDDEN
    }

    fn error_response(&self) -> HttpResponse {
        log::warn!("🛡️ Falha na validação CSRF: {}", self);
        HttpResponse::build(self.status_code())
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .body(format!("{{\"error\":\"{}\"}}", self))
    }
}

// --- Middleware ---

// Struct vazia para registrar o Transform
#[derive(Clone)]
pub struct CsrfProtect {
    secret: String,
}

impl CsrfProtect {
    /// Cria uma nova instância do Transform CSRF a partir da configuração da aplicação.
    pub fn from_config(config: &Config) -> Self {
        let secret = config.security.csrf_secret.clone();
        if secret.len() < 32 {
            log::warn!("🛡️ O segredo CSRF configurado tem menos de 32 bytes, o que é inseguro!");
        }
        Self { secret }
    }
}


// Implementação do Transform (fábrica)
impl<S, B> Transform<S, ServiceRequest> for CsrfProtect
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = CsrfProtectMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(CsrfProtectMiddleware {
            service: Rc::new(service),
            _secret: self.secret.clone(),
        }))
    }
}

// O Middleware real
pub struct CsrfProtectMiddleware<S> {
    service: Rc<S>,
    _secret: String,
}

// Função auxiliar para gerar token CSRF seguro
fn generate_csrf_token() -> String {
    let mut bytes = vec![0u8; CSRF_TOKEN_BYTE_LENGTH];
    OsRng.fill_bytes(&mut bytes);
    B64_ENGINE.encode(&bytes)
}

// Implementação do Service (lógica principal)
impl<S, B> Service<ServiceRequest> for CsrfProtectMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().clone();
        let path = req.path().to_string();
        let is_safe_method = matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);

        if !is_safe_method {
            log::debug!("🛡️ [CSRF] Validando token para método inseguro: {} {}", method, path);
            let cookie_token = match req.cookie(CSRF_COOKIE_NAME) {
                Some(cookie) => cookie.value().to_string(),
                None => {
                    log::warn!("🛡️ [CSRF] Token ausente no cookie para {} {}", method, path);
                    return Box::pin(future::err(CsrfError::MissingCookieToken.into()));
                }
            };

            let header_token = match req.headers().get(CSRF_HEADER_NAME) {
                Some(value) => match value.to_str() {
                    Ok(v) => v.to_string(),
                    Err(_) => {
                        log::warn!("🛡️ [CSRF] Header contém caracteres inválidos para {} {}", method, path);
                        return Box::pin(future::err(CsrfError::InvalidHeaderValue.into()));
                    }
                },
                None => {
                    log::warn!("🛡️ [CSRF] Token ausente no header para {} {}", method, path);
                    return Box::pin(future::err(CsrfError::MissingHeaderToken.into()));
                }
            };

            if constant_time::verify_slices_are_equal(cookie_token.as_bytes(), header_token.as_bytes()).is_err() {
                 log::warn!("🛡️ [CSRF] Falha na validação (cookie vs header) para {} {}", method, path);
                 return Box::pin(future::err(CsrfError::TokenMismatch.into()));
            }
            log::debug!("🛡️ [CSRF] Validação bem-sucedida para {} {}", method, path);
        } else {
             log::debug!("🛡️ [CSRF] Método seguro ({}), pulando validação.", method);
        }


        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res: ServiceResponse<B> = fut.await?;

            let new_token = generate_csrf_token();

            let csrf_cookie = Cookie::build(CSRF_COOKIE_NAME, new_token.clone())
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Strict)
                .finish();

            res.headers_mut().append(
                header::SET_COOKIE,
                csrf_cookie.to_string().parse().map_err(|e| {
                    log::error!("🛡️ [CSRF] Falha ao criar header Set-Cookie: {}", e);
                    actix_web::error::ErrorInternalServerError("Failed to set CSRF cookie header")
                })?,
            );
            log::debug!("🛡️ [CSRF] Cookie CSRF definido/atualizado na resposta para {} {}", method, path);

            Ok(res)
        })
    }
} 