use crate::db::DbPool;
use crate::errors::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::models::response::ApiResponse;
use crate::models::session_policy::{SessionLimitPolicy, SessionLimitPolicyDto};
use crate::services::session_policy_service::SessionPolicyService;
use actix_web::{web, HttpResponse, Responder};
use tracing::info;

/// # Lista detalhes da política de sessão
/// 
/// Retorna a política de sessão aplicada ao usuário autenticado
/// 
/// ## Endpoint
/// 
/// `GET /api/sessions/policy`
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "max_sessions": 5,
///     "current_sessions": 2,
///     "revoke_strategy": "RevokeOldest",
///     "is_custom": false,
///     "is_active": true
///   }
/// }
/// ```
pub async fn get_my_session_policy(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let summary = SessionPolicyService::get_policy_summary(&pool, &auth_user.id)?;
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(summary)))
}

/// # Lista detalhes da política de sessão de um usuário
/// 
/// Retorna a política de sessão aplicada a um usuário específico (admin)
/// 
/// ## Endpoint
/// 
/// `GET /api/admin/users/{user_id}/sessions/policy`
/// 
/// ## Parâmetros de URL
/// 
/// - `user_id`: ID do usuário
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "max_sessions": 5,
///     "current_sessions": 2,
///     "revoke_strategy": "RevokeOldest",
///     "is_custom": false,
///     "is_active": true
///   }
/// }
/// ```
pub async fn get_user_session_policy(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    _auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let summary = SessionPolicyService::get_policy_summary(&pool, &user_id)?;
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(summary)))
}

/// # Atualiza política global de sessão
/// 
/// Atualiza a política global de limite de sessões
/// 
/// ## Endpoint
/// 
/// `PUT /api/admin/sessions/policy`
/// 
/// ## Corpo da Requisição
/// 
/// ```json
/// {
///   "max_sessions_per_user": 5,
///   "revoke_strategy": "RevokeOldest",
///   "is_active": true
/// }
/// ```
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": "Política global de sessão atualizada com sucesso ✅",
///   "data": {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "session_limit": {
///       "max_sessions_per_user": 5,
///       "revoke_strategy": "RevokeOldest",
///       "is_active": true
///     },
///     "is_active": true,
///     "updated_at": "2023-09-15T14:30:00Z"
///   }
/// }
/// ```
pub async fn update_global_policy(
    pool: web::Data<DbPool>,
    policy_dto: web::Json<SessionLimitPolicyDto>,
    _auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    // Converter DTO para modelo
    let policy = SessionLimitPolicy {
        max_sessions_per_user: policy_dto.max_sessions_per_user,
        revoke_strategy: policy_dto.revoke_strategy,
        is_active: policy_dto.is_active,
    };
    
    // Atualizar política global
    let updated_policy = SessionPolicyService::update_global_policy(&pool, &policy)?;
    
    info!("🔄 Política global de sessão atualizada: {} sessões por usuário, estratégia {:?}",
          policy.max_sessions_per_user, policy.revoke_strategy);
    
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        updated_policy,
        "Política global de sessão atualizada com sucesso ✅"
    )))
}

/// # Define política de sessão para usuário
/// 
/// Define uma política de limite de sessões específica para um usuário
/// 
/// ## Endpoint
/// 
/// `PUT /api/admin/users/{user_id}/sessions/policy`
/// 
/// ## Parâmetros de URL
/// 
/// - `user_id`: ID do usuário
/// 
/// ## Corpo da Requisição
/// 
/// ```json
/// {
///   "max_sessions_per_user": 10,
///   "revoke_strategy": "BlockNew",
///   "is_active": true
/// }
/// ```
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": "Política de sessão para o usuário atualizada com sucesso ✅",
///   "data": {
///     "id": "550e8400-e29b-41d4-a716-446655440000",
///     "user_id": "550e8400-e29b-41d4-a716-446655440001",
///     "session_limit": {
///       "max_sessions_per_user": 10,
///       "revoke_strategy": "BlockNew",
///       "is_active": true
///     },
///     "is_active": true,
///     "created_at": "2023-09-15T14:30:00Z",
///     "updated_at": "2023-09-15T14:30:00Z"
///   }
/// }
/// ```
pub async fn set_user_policy(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    policy_dto: web::Json<SessionLimitPolicyDto>,
    _auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    // Converter DTO para modelo
    let policy = SessionLimitPolicy {
        max_sessions_per_user: policy_dto.max_sessions_per_user,
        revoke_strategy: policy_dto.revoke_strategy,
        is_active: policy_dto.is_active,
    };
    
    // Definir política para o usuário
    let user_policy = SessionPolicyService::set_user_policy(&pool, &user_id, &policy)?;
    
    info!("✅ Política de sessão definida para usuário {}: {} sessões, estratégia {:?}",
          user_id, policy.max_sessions_per_user, policy.revoke_strategy);
    
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        user_policy,
        "Política de sessão para o usuário atualizada com sucesso ✅"
    )))
}

/// # Remove política de sessão de usuário
/// 
/// Remove a política de limite de sessões específica de um usuário, voltando à política global
/// 
/// ## Endpoint
/// 
/// `DELETE /api/admin/users/{user_id}/sessions/policy`
/// 
/// ## Parâmetros de URL
/// 
/// - `user_id`: ID do usuário
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": "Política de sessão removida, usuário agora usa a política global ✅",
///   "data": null
/// }
/// ```
pub async fn remove_user_policy(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    _auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    // Remover política do usuário
    SessionPolicyService::remove_user_policy(&pool, &user_id)?;
    
    info!("🗑️ Política de sessão removida para usuário {}", user_id);
    
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        (),
        "Política de sessão removida, usuário agora usa a política global ✅"
    )))
}

/// # Lista todas as sessões ativas para um usuário
/// 
/// Retorna todas as sessões ativas para um usuário específico (admin)
/// 
/// ## Endpoint
/// 
/// `GET /api/admin/users/{user_id}/sessions`
/// 
/// ## Parâmetros de URL
/// 
/// - `user_id`: ID do usuário
/// 
/// ## Resposta
/// 
/// ```json
/// {
///   "status": "success",
///   "message": null,
///   "data": {
///     "count": 2,
///     "policy": {
///       "max_sessions": 5,
///       "current_sessions": 2,
///       "revoke_strategy": "RevokeOldest",
///       "is_custom": false,
///       "is_active": true
///     }
///   }
/// }
/// ```
pub async fn get_user_sessions_count(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    _auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let count = SessionPolicyService::count_active_sessions(&pool, &user_id)?;
    let summary = SessionPolicyService::get_policy_summary(&pool, &user_id)?;
    
    Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({
        "count": count,
        "policy": summary
    }))))
}

/// Configuração das rotas do controlador de política de sessão
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        // Rotas para usuário autenticado
        web::scope("")
            // Obter minha política de sessão
            .route("/policy", web::get().to(get_my_session_policy))
    );
    
    info!("🔒 Rotas de política de sessão configuradas");
}

/// Configuração das rotas de administração de política de sessão
pub fn admin_config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        // Rotas de administração
        web::scope("/sessions")
            // Atualizar política global
            .route("/policy", web::put().to(update_global_policy))
    )
    .service(
        // Rotas para gerenciar políticas específicas de usuários
        web::scope("/users/{user_id}/sessions")
            // Contar sessões de um usuário
            .route("", web::get().to(get_user_sessions_count))
            // Obter política de um usuário
            .route("/policy", web::get().to(get_user_session_policy))
            // Definir política para um usuário
            .route("/policy", web::put().to(set_user_policy))
            // Remover política de um usuário
            .route("/policy", web::delete().to(remove_user_policy))
    );
    
    info!("🛡️ Rotas de administração de política de sessão configuradas");
} 
