use crate::config::Config;
use crate::db::DbPool;
use crate::models::oauth::{OAuthCallbackRequest, OAuthLoginRequest, OAuthProvider};
use crate::models::response::ApiResponse;
use crate::services::auth_service::AuthService;

use crate::services::oauth_service::OAuthService;

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde_json::json;
use std::sync::Arc;

pub async fn oauth_login(
    _req: HttpRequest,
    data: web::Json<OAuthLoginRequest>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder {
    let oauth_service = OAuthService::new(config.get_ref().clone(), db_pool.get_ref().clone());
    
    match oauth_service.get_authorization_url(data.provider.clone(), "state123").await {
        Ok(url_response) => {
            HttpResponse::Ok().json(ApiResponse::success_with_message(
                url_response,
                "URL de autorização gerada com sucesso 🔑"
            ))
        },
        Err(e) => {
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                &e.to_string()
            ))
        }
    }
}

pub async fn oauth_callback(
    req: HttpRequest,
    query: web::Query<OAuthCallbackRequest>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder {
    let oauth_service = OAuthService::new(config.get_ref().clone(), db_pool.get_ref().clone());
    // Não precisamos criar uma instância de AuthService, usaremos as funções diretamente
    
    // Obter o provedor da query ou do estado
    let provider_str = query.provider.clone().unwrap_or_else(|| "google".to_string());
    let provider = match provider_str.as_str() {
        "google" => OAuthProvider::Google,
        "facebook" => OAuthProvider::Facebook,
        "microsoft" => OAuthProvider::Microsoft,
        "github" => OAuthProvider::GitHub,
        "apple" => OAuthProvider::Apple,
        _ => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                &format!("Provedor não suportado: {}", provider_str)
            ));
        }
    };
    
    // Verificar se o código está presente
    if query.code.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Código de autorização ausente"
        ));
    }
    
    // Processar o callback OAuth
    match oauth_service.process_callback(
        provider,
        &query.code,
        &query.state.clone().unwrap_or_default(),
    ).await {
        Ok(user_profile) => {
            // Processar o login OAuth
            match oauth_service.process_oauth_login(user_profile).await {
                Ok(user) => {
                    // Gerar tokens JWT
                    // Gerar tokens JWT manualmente
                    match AuthService::generate_auth_tokens(&db_pool, &user) {
                        Ok(auth_response) => {
                            // Registrar o dispositivo
                            let user_agent = req.headers().get("User-Agent").map(|h| h.to_str().unwrap_or("")).unwrap_or("").to_string();
                            let ip_address = req.connection_info().realip_remote_addr().unwrap_or("").to_string();
                            
                            // Criar sessão
                            let _ = AuthService::create_session(
                                &db_pool,
                                &user.id,
                                &auth_response.refresh_token,
                                &user_agent,
                                &ip_address
                            );
                            
                            // Redirecionar para a página de sucesso com o token
                            HttpResponse::Found()
                                .append_header(("Location", format!("/auth/success?token={}", auth_response.access_token)))
                                .finish()
                        },
                        Err(e) => {
                            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                                &format!("Erro ao gerar tokens: {}", e)
                            ))
                        }
                    }
                },
                Err(e) => {
                    HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                        &e.to_string()
                    ))
                }
            }
        },
        Err(e) => {
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                &e.to_string()
            ))
        }
    }
}

pub async fn list_oauth_connections(
    _req: HttpRequest,
    user_id: web::Path<String>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder {
    let oauth_service = OAuthService::new(config.get_ref().clone(), db_pool.get_ref().clone());
    
    match oauth_service.list_user_oauth_connections(&user_id) {
        Ok(connections) => {
            let connections_response = connections.iter()
                .map(|conn| json!({
                    "id": conn.id,
                    "provider": conn.provider.to_string(),
                    "email": conn.email,
                    "name": conn.name,
                    "connected_at": conn.created_at
                }))
                .collect::<Vec<_>>();
            
            HttpResponse::Ok().json(ApiResponse::success_with_message(
                connections_response,
                "Conexões OAuth listadas com sucesso 📝"
            ))
        },
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                &e.to_string()
            ))
        }
    }
}

pub async fn remove_oauth_connection(
    _req: HttpRequest,
    path: web::Path<(String, String)>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder {
    let (user_id, connection_id) = path.into_inner();
    let oauth_service = OAuthService::new(config.get_ref().clone(), db_pool.get_ref().clone());
    
    match oauth_service.remove_oauth_connection(&user_id, &connection_id) {
        Ok(_) => {
            HttpResponse::Ok().json(ApiResponse::<()>::message(
                "Conexão OAuth removida com sucesso 🗑️"
            ))
        },
        Err(e) => {
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error(
                &e.to_string()
            ))
        }
    }
}
