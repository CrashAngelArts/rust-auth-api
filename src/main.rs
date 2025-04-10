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
use dotenv::dotenv;
use log::{info, error};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Carrega as variáveis de ambiente
    dotenv().ok();
    
    // Configura o logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    
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
    
    // Inicia o servidor
    info!("🚀 Iniciando servidor em {}:{}", config.server.host, config.server.port);
    
    let server_config = config.clone();
    
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(server_config.clone()))
            .app_data(web::Data::new(email_service.clone()))
            .app_data(web::JsonConfig::default().limit(4096))
            .configure(|cfg| routes::configure_routes(cfg, &server_config))
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?
    .run()
    .await
}
