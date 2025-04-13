use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;
use std::collections::HashMap; // Importar HashMap
use std::fmt;
use thiserror::Error;
use tracing::{error, warn};
use validator::ValidationErrors;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Erro de autenticação: {0}")]
    AuthenticationError(String),

    #[error("Erro de autorização: {0}")]
    AuthorizationError(String),

    // Alterar para conter detalhes estruturados
    #[error("Erro de validação")] // Mensagem genérica, detalhes estarão no corpo
    ValidationError(HashMap<String, Vec<String>>),

    #[error("Recurso não encontrado: {0}")]
    NotFoundError(String),

    #[error("Erro de banco de dados: {0}")]
    DatabaseError(String),

    #[error("Erro de email: {0}")]
    EmailError(String),

    #[error("Erro interno do servidor: {0}")]
    InternalServerError(String),

    #[error("Erro de conflito: {0}")]
    ConflictError(String),

    #[error("Requisição inválida: {0}")]
    BadRequestError(String),

    #[error("Limite de taxa excedido: {0}")]
    RateLimitExceededError(String),

    #[error("Conta bloqueada temporariamente: {0}")] // Novo erro para conta bloqueada
    AccountLockedError(String),
    
    #[error("Acesso proibido: {0}")]
    Forbidden(ErrorResponse),
    
    #[error("Muitas requisições: {0}")]
    TooManyRequests(ErrorResponse),
    
    #[error("Limite de taxa excedido: {0}")]
    RateLimited(ErrorResponse),

    // Adicionando as variantes que estão faltando
    #[error("Requisição inválida: {0}")]
    BadRequest(String),

    #[error("Recurso não encontrado: {0}")]
    NotFound(String),

    #[error("Atividade de login suspeita: {0}")]
    SuspiciousLoginActivity(String),
}

// Conversão de erro de bloqueio do Actix
impl From<actix_web::error::BlockingError> for ApiError {
    fn from(error: actix_web::error::BlockingError) -> ApiError {
        ApiError::InternalServerError(format!("Erro em tarefa bloqueante: {}", error))
    }
}

// Conversão de erro de transporte SMTP do Lettre
impl From<lettre::transport::smtp::Error> for ApiError {
    fn from(error: lettre::transport::smtp::Error) -> ApiError {
        ApiError::EmailError(format!("Erro de transporte SMTP: {}", error))
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ErrorResponse {
    pub status: u16,
    pub message: String,
    pub error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_details: Option<String>, // Detalhes adicionais do erro
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_details: Option<HashMap<String, Vec<String>>>, // Campo para erros de validação
}

// Implementar Display para ErrorResponse
impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        
        // Lidar com os novos tipos de erro que já contém ErrorResponse
        match self {
            ApiError::Forbidden(error_response) => {
                return HttpResponse::build(StatusCode::FORBIDDEN).json(error_response);
            }
            ApiError::TooManyRequests(error_response) => {
                return HttpResponse::build(StatusCode::TOO_MANY_REQUESTS).json(error_response);
            }
            ApiError::RateLimited(error_response) => {
                return HttpResponse::build(StatusCode::TOO_MANY_REQUESTS).json(error_response);
            }
            _ => {}
        }
        
        // Criar a resposta base para outros tipos de erro
        let mut error_response = ErrorResponse {
            status: status_code.as_u16(),
            message: self.to_string(), // Usa a mensagem definida em #[error(...)]
            error_code: format!("ERR_{}", status_code.as_u16()),
            error_details: None,
            validation_details: None, // Inicializa como None
        };

        // Adicionar detalhes específicos para ValidationError
        if let ApiError::ValidationError(details) = self {
            error_response.validation_details = Some(details.clone());
            error_response.error_code = "VALIDATION_ERROR".to_string();
        }

        HttpResponse::build(status_code).json(error_response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::AuthenticationError(_) => StatusCode::UNAUTHORIZED, // 401
            ApiError::AuthorizationError(_) => StatusCode::FORBIDDEN,    // 403
            ApiError::ValidationError(_) => StatusCode::BAD_REQUEST,      // 400
            ApiError::NotFoundError(_) => StatusCode::NOT_FOUND,         // 404
            ApiError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::EmailError(_) => StatusCode::INTERNAL_SERVER_ERROR,    // 500
            ApiError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR, // 500
            ApiError::ConflictError(_) => StatusCode::CONFLICT,           // 409
            ApiError::BadRequestError(_) => StatusCode::BAD_REQUEST,      // 400
            ApiError::RateLimitExceededError(_) => StatusCode::TOO_MANY_REQUESTS, // 429
            ApiError::AccountLockedError(_) => StatusCode::FORBIDDEN,     // 403 (Usuário identificado, mas proibido de logar)
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,              // 403
            ApiError::TooManyRequests(_) => StatusCode::TOO_MANY_REQUESTS, // 429
            ApiError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,    // 429
            _ => StatusCode::INTERNAL_SERVER_ERROR, // 500 para outros erros
        }
    }
}

// Implementações para conversão de erros comuns para ApiError
impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> ApiError {
        // Tratar erro de constraint UNIQUE especificamente para unlock_token
        if let rusqlite::Error::SqliteFailure(ref err, Some(ref msg)) = error {
            if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE && msg.contains("unlock_token") {
                // Tentar gerar um novo token é complexo aqui, melhor logar e retornar erro genérico
                error!("Erro de constraint UNIQUE ao gerar unlock_token: {}", error);
                return ApiError::InternalServerError("Não foi possível gerar um token de desbloqueio único. Tente novamente.".to_string());
            }
        }
        ApiError::DatabaseError(error.to_string())
    }
}

impl From<r2d2::Error> for ApiError {
    fn from(error: r2d2::Error) -> ApiError {
        ApiError::DatabaseError(error.to_string())
    }
}

impl From<bcrypt::BcryptError> for ApiError {
    fn from(error: bcrypt::BcryptError) -> ApiError {
        ApiError::InternalServerError(error.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(error: jsonwebtoken::errors::Error) -> ApiError {
        ApiError::AuthenticationError(error.to_string())
    }
}

impl From<std::env::VarError> for ApiError {
    fn from(error: std::env::VarError) -> ApiError {
        ApiError::InternalServerError(error.to_string())
    }
}

impl From<lettre::error::Error> for ApiError {
    fn from(error: lettre::error::Error) -> ApiError {
        ApiError::EmailError(error.to_string())
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> ApiError {
        ApiError::InternalServerError(error.to_string())
    }
}

impl From<uuid::Error> for ApiError {
    fn from(error: uuid::Error) -> ApiError {
        ApiError::BadRequest(format!("UUID inválido: {}", error))
    }
}

impl From<ValidationErrors> for ApiError {
    fn from(errors: ValidationErrors) -> ApiError {
        let mut details = HashMap::new();
        for (field, field_errors) in errors.field_errors() {
            let messages: Vec<String> = field_errors
                .iter()
                .map(|e| e.message.as_ref().map(|m| m.to_string()).unwrap_or_else(|| format!("Erro de validação no campo '{}'", field)))
                .collect();
            details.insert(field.to_string(), messages);
        }
        ApiError::ValidationError(details)
    }
}

// Função de utilidade para log de erros
pub fn log_error(error: &ApiError) {
    match error {
        ApiError::InternalServerError(msg) | ApiError::DatabaseError(msg) | ApiError::EmailError(msg) => {
            error!("{}", msg);
        }
        _ => {
            warn!("{}", error);
        }
    }
}
