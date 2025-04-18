use crate::db::DbPool;
use crate::errors::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::auth::AdminAuth;
use crate::models::response::ApiResponse;
use crate::services::time_pattern_service::TimePatternAnalyzer;
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize};
use tracing::{info};

#[derive(Debug, Deserialize)]
pub struct CleanPatternsParams {
    /// Número de dias para manter (padrão: 90)
    #[serde(default = "default_days")]
    pub days: u32,
}

fn default_days() -> u32 {
    90
}

/// Lista o resumo do padrão temporal de login para um usuário específico (requer admin)
pub async fn get_user_time_pattern(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    
    info!("👮 Admin {} obtendo padrão temporal de login para o usuário: {}", auth_user.id, user_id);
    
    let analyzer = TimePatternAnalyzer::default();
    let pattern_summary = analyzer.get_pattern_summary(&pool, &user_id)?;
    
    if let Some(summary) = pattern_summary {
        let response = ApiResponse::success(summary);
        Ok(HttpResponse::Ok().json(response))
    } else {
        let response = ApiResponse::success(serde_json::json!({
            "message": "Nenhum padrão temporal encontrado para este usuário 🕒"
        }));
        Ok(HttpResponse::Ok().json(response))
    }
}

/// Remove padrões temporais antigos (apenas admin)
pub async fn clean_old_patterns(
    pool: web::Data<DbPool>,
    query: web::Query<CleanPatternsParams>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    info!("🧹 Admin {} limpando padrões temporais antigos (> {} dias)", 
          auth_user.id, query.days);
    
    let analyzer = TimePatternAnalyzer::default();
    let count = analyzer.clean_old_patterns(&pool, query.days)?;
    
    let response = ApiResponse::success(serde_json::json!({
        "message": format!("🗑️ {} padrões temporais removidos com sucesso!", count),
        "count": count
    }));
    
    Ok(HttpResponse::Ok().json(response))
}

/// Configuração das rotas do controlador
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        // Rota para ver padrões temporais de um usuário específico (admin)
        .service(
            web::resource("/users/{user_id}")
                .route(web::get().to(get_user_time_pattern))
                .wrap(AdminAuth::new())
        )
        
        // Rota para limpar padrões temporais antigos (admin)
        .service(
            web::resource("/clean")
                .route(web::delete().to(clean_old_patterns))
                .wrap(AdminAuth::new())
        );
        
    info!("🕒 Rotas de padrões temporais configuradas!");
} 