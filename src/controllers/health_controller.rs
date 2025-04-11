use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::response::ApiResponse;
use actix_web::{web, HttpResponse, Responder};
use tracing::info;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// Estrutura para a resposta de saúde
#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub timestamp: u64,
    pub database: String,
    pub cors: Vec<String>,
    pub email_base_url: String,
}

// Verifica a saúde da API
pub async fn health_check(
    pool: web::Data<DbPool>,
    config: web::Data<crate::config::Config>,
) -> Result<impl Responder, ApiError> {
    // Verifica a conexão com o banco de dados
    let conn = pool.get()?;
    let db_status = match conn.execute("SELECT 1", []) {
        Ok(_) => "online",
        Err(_) => "offline",
    };
    
    // Obtém o timestamp atual
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    // Cria a resposta
    let health_response = HealthResponse {
        status: "online".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp,
        database: db_status.to_string(),
        cors: config.cors.allowed_origins.clone(),
        email_base_url: config.email.base_url.clone(),
    };
    
    info!("🏥 Verificação de saúde realizada: sistema online");
    
    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(health_response)))
}

// Verifica a versão da API
pub async fn version() -> Result<impl Responder, ApiError> {
    // Cria a resposta
    let version_response = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "name": env!("CARGO_PKG_NAME"),
        "authors": env!("CARGO_PKG_AUTHORS"),
        "description": env!("CARGO_PKG_DESCRIPTION"),
    });
    
    info!("📊 Informações de versão solicitadas");
    
    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(version_response)))
}
