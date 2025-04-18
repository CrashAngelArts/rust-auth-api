use crate::db::DbPool;
use crate::errors::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::repositories::login_location_repository::LoginLocationRepository;
use crate::models::api::ApiResponse;
use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;
use tracing::info;

/// Parâmetros de consulta para listar localizações
#[derive(Debug, Deserialize)]
pub struct LocationsQueryParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

/// Parâmetros para limpar localizações antigas
#[derive(Debug, Deserialize)]
pub struct CleanLocationsParams {
    #[serde(default = "default_retention_days")]
    pub days: i64,
}

// Valor padrão para o limite de localizações
fn default_limit() -> usize {
    20
}

// Valor padrão para dias de retenção
fn default_retention_days() -> i64 {
    90
}

/// Lista as localizações de login do usuário autenticado
pub async fn list_my_locations(
    pool: web::Data<DbPool>,
    query: web::Query<LocationsQueryParams>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    info!("🔍 Listando localizações de login para o usuário: {}", auth_user.id);
    
    let locations = LoginLocationRepository::find_by_user_id(
        &pool, 
        &auth_user.id, 
        query.limit
    )?;
    
    let response = ApiResponse::success(locations);
    Ok(HttpResponse::Ok().json(response))
}

/// Lista as localizações de login de um usuário específico (apenas admin)
pub async fn list_user_locations(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    query: web::Query<LocationsQueryParams>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    // Verificar se o usuário é admin (já foi verificado pelo AdminAuth middleware na rota)
    let user_id = path.into_inner();
    
    info!("👮 Admin {} listando localizações de login para o usuário: {}", auth_user.id, user_id);
    
    let locations = LoginLocationRepository::find_by_user_id(
        &pool, 
        &user_id, 
        query.limit
    )?;
    
    let response = ApiResponse::success(locations);
    Ok(HttpResponse::Ok().json(response))
}

/// Remove localizações de login antigas (apenas admin)
pub async fn clean_old_locations(
    pool: web::Data<DbPool>,
    query: web::Query<CleanLocationsParams>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    info!("🧹 Admin {} limpando localizações de login antigas (> {} dias)", 
          auth_user.id, query.days);
    
    let count = LoginLocationRepository::clean_old_locations(&pool, query.days)?;
    
    let response = ApiResponse::success(serde_json::json!({
        "message": format!("🗑️ {} localizações de login removidas com sucesso!", count),
        "count": count
    }));
    
    Ok(HttpResponse::Ok().json(response))
}

/// Configuração de rotas do controlador de localizações
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        // Rota para listar minhas localizações (qualquer usuário)
        .route("", web::get().to(list_my_locations))
        
        // Rota para listar localizações de um usuário específico (admin)
        .service(
            web::resource("/users/{user_id}")
                .route(web::get().to(list_user_locations))
                .wrap(crate::middleware::auth::AdminAuth::new())
        )
        
        // Rota para limpar localizações antigas (admin)
        .service(
            web::resource("/clean")
                .route(web::delete().to(clean_old_locations))
                .wrap(crate::middleware::auth::AdminAuth::new())
        );
        
    info!("🌎 Rotas de localização configuradas!");
} 