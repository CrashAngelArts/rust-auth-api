use actix_cors::Cors;
use actix_web::http::header;
use crate::config::Config;
use log::info;

// Configura o CORS para a aplicação
pub fn configure_cors(config: &Config) -> Cors {
    // Obtém as origens permitidas da configuração
    let allowed_origins = &config.cors.allowed_origins;
    
    // Cria o builder do CORS
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
        .allowed_headers(vec![
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ORIGIN,
        ])
        .max_age(3600);
    
    // Adiciona as origens permitidas
    for origin in allowed_origins {
        info!("🔒 Permitindo CORS para origem: {}", origin);
        cors = cors.allowed_origin(origin);
    }
    
    cors
}
