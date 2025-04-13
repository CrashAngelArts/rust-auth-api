mod config;
mod controllers;
mod db;
// mod email; // Removido, pois a implementação está em services/email_service.rs
mod errors;
mod middleware;
mod models;
mod routes;
mod services;
mod utils;

use actix_web::{App, HttpServer, web};
use actix_web::cookie::Key;
use actix_files::Files; // Adicionado para servir arquivos estáticos
use dotenv::dotenv;
use tracing::{info, error};
use tracing_actix_web::TracingLogger;
use middleware::security::configure_security;
use moka::future::Cache;
use crate::models::auth::TokenClaims; // Alterado de Session para TokenClaims
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Carrega as variáveis de ambiente
    dotenv().ok();
    
    // Inicializa o sistema de logging estruturado com tracing
    if let Err(e) = utils::tracing::init_tracing() {
        eprintln!("❌ Erro ao inicializar sistema de logging: {}", e);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
    }
    
    // Registra informações sobre o ambiente de execução
    utils::tracing::log_startup_info();
    
    // Carrega a configuração
    let config = match config::load_config() {
        Ok(config) => {
            info!("✅ Configuração carregada com sucesso");
            config
        }
        Err(e) => {
            error!("❌ Erro ao carregar configuração: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };
    
    // Inicializa o banco de dados
    let pool = match db::init_db(&config.database.url) {
        Ok(pool) => {
            info!("✅ Banco de dados inicializado com sucesso");
            pool
        }
        Err(e) => {
            error!("❌ Erro ao inicializar banco de dados: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
        }
    };
    
    // Migrações agora são executadas dentro de db::init_db
    
    // Inicializa o serviço de email
    let email_service = services::email_service::EmailService::new(
        config.email.smtp_server.clone(),
        config.email.smtp_port,
        config.email.username.clone(),
        config.email.password.clone(),
        config.email.from.clone(),
        config.email.from_name.clone(),
        config.email.base_url.clone(),
        config.email.enabled,
    );
    
    if config.email.enabled {
        info!("✅ Serviço de email inicializado com sucesso");
    } else {
        info!("ℹ️ Serviço de email inicializado em modo desabilitado");
    }
    
    // Inicializa o cache de validação de token com Moka 🚀
    let token_cache: Cache<String, TokenClaims> = Cache::builder()
        // Máximo de 10.000 tokens cacheados
        .max_capacity(10_000)
        // Expira tokens após 1 hora de inatividade (TTL)
        .time_to_live(Duration::from_secs(3600)) 
        // Expira tokens após 24 horas, independente da atividade (opcional, mas bom para limpeza)
        .time_to_idle(Duration::from_secs(3600 * 24))
        .build();
    info!("✅ Cache de validação de token (Moka) inicializado com sucesso");

    // Configura os middlewares de segurança
    let (security_headers, csrf_protection) = configure_security(&config.jwt.secret);
    
    // Chave para cookies assinados
    let cookie_key = Key::derive_from(config.jwt.secret.as_bytes());
    
    // Inicia o servidor
    info!("🚀 Iniciando servidor em {}:{}", config.server.host, config.server.port);
    
    let server_config = config.clone();
    
    HttpServer::new(move || {
        App::new()
            // Middlewares globais
            .wrap(TracingLogger::default())
            .wrap(security_headers.clone())
            // Dados da aplicação
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(server_config.clone()))
            .app_data(web::Data::new(email_service.clone()))
            .app_data(web::Data::new(token_cache.clone())) // Adiciona o cache aos dados da app
            .app_data(web::JsonConfig::default().limit(4096))
            .app_data(cookie_key.clone())
            // Servir arquivos estáticos da pasta 'static'
            .service(Files::new("/static", "static").show_files_listing())
            // Configuração de rotas
            .configure(|cfg| routes::configure_routes(cfg, &server_config))
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?
    .run()
    .await
}
