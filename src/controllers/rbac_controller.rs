use crate::{
    db::DbPool,
    errors::ApiError,
    models::{        permission::{CreatePermissionDto, Permission, UpdatePermissionDto},
        role::{CreateRoleDto, Role, UpdateRoleDto},
    },
    services::rbac_service::RbacService,
};
use actix_web::{
    delete, get, post, put,
    web::{self, Data, Json, Path},
    HttpResponse,
};
use validator::Validate;
use serde::Serialize;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::auth::AdminAuth;

// --- Structs de Resposta Específicas --- 
#[derive(Serialize)]
struct PermissionCheckResponse {
    has_permission: bool,
}

// --- Handlers de Permissão ---

#[post("/permissions")]
async fn create_permission(
    pool: Data<DbPool>,
    permission_data: Json<CreatePermissionDto>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let dto = permission_data.into_inner();
    dto.validate()?;
    let new_permission = RbacService::create_permission(&pool, dto)?;
    Ok(HttpResponse::Created().json(new_permission))
}

#[get("/permissions")]
async fn list_permissions(
    pool: Data<DbPool>,
     _user: AuthenticatedUser,
) -> Result<Json<Vec<Permission>>, ApiError> {
    let permissions = RbacService::list_permissions(&pool)?;
    Ok(Json(permissions))
}

#[get("/permissions/{id}")]
async fn get_permission_by_id(
    pool: Data<DbPool>,
    path: Path<String>,
     _user: AuthenticatedUser,
) -> Result<Json<Permission>, ApiError> {
    let permission_id = path.into_inner();
    let permission = RbacService::get_permission_by_id(&pool, &permission_id)?;
    Ok(Json(permission))
}

#[get("/permissions/by-name/{name}")]
async fn get_permission_by_name(
    pool: Data<DbPool>,
    path: Path<String>,
     _user: AuthenticatedUser,
) -> Result<Json<Permission>, ApiError> {
    let permission_name = path.into_inner();
    let permission = RbacService::get_permission_by_name(&pool, &permission_name)?;
    Ok(Json(permission))
}

#[put("/permissions/{id}")]
async fn update_permission(
    pool: Data<DbPool>,
    path: Path<String>,
    permission_data: Json<UpdatePermissionDto>,
    _user: AuthenticatedUser,
) -> Result<Json<Permission>, ApiError> {
    let dto = permission_data.into_inner();
    dto.validate()?;
    let permission_id = path.into_inner();
    let updated_permission =
        RbacService::update_permission(&pool, &permission_id, dto)?;
    Ok(Json(updated_permission))
}

#[delete("/permissions/{id}")]
async fn delete_permission(
    pool: Data<DbPool>,
    path: Path<String>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let permission_id = path.into_inner();
    RbacService::delete_permission(&pool, &permission_id)?;
    Ok(HttpResponse::NoContent().finish())
}

// --- Handlers de Papel ---

#[post("/roles")]
async fn create_role(
    pool: Data<DbPool>,
    role_data: Json<CreateRoleDto>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let dto = role_data.into_inner();
    dto.validate()?;
    let new_role = RbacService::create_role(&pool, dto)?;
    Ok(HttpResponse::Created().json(new_role))
}

#[get("/roles")]
async fn list_roles(
    pool: Data<DbPool>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<Role>>, ApiError> {
    let roles = RbacService::list_roles(&pool)?;
    Ok(Json(roles))
}

#[get("/roles/{id}")]
async fn get_role_by_id(
    pool: Data<DbPool>,
    path: Path<String>,
    _user: AuthenticatedUser,
) -> Result<Json<Role>, ApiError> {
    let role_id = path.into_inner();
    let role = RbacService::get_role_by_id(&pool, &role_id)?;
    Ok(Json(role))
}

#[get("/roles/by-name/{name}")]
async fn get_role_by_name(
    pool: Data<DbPool>,
    path: Path<String>,
    _user: AuthenticatedUser,
) -> Result<Json<Role>, ApiError> {
    let role_name = path.into_inner();
    let role = RbacService::get_role_by_name(&pool, &role_name)?;
    Ok(Json(role))
}

#[put("/roles/{id}")]
async fn update_role(
    pool: Data<DbPool>,
    path: Path<String>,
    role_data: Json<UpdateRoleDto>,
    _user: AuthenticatedUser,
) -> Result<Json<Role>, ApiError> {
    let dto = role_data.into_inner();
    dto.validate()?;
    let role_id = path.into_inner();
    let updated_role = RbacService::update_role(&pool, &role_id, dto)?;
    Ok(Json(updated_role))
}

#[delete("/roles/{id}")]
async fn delete_role(
    pool: Data<DbPool>,
    path: Path<String>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let role_id = path.into_inner();
    RbacService::delete_role(&pool, &role_id)?;
    Ok(HttpResponse::NoContent().finish())
}

// --- Handlers de Associação ---

// -- Papel <-> Permissão --

#[post("/roles/{role_id}/permissions/{permission_id}")]
async fn assign_permission_to_role_handler(
    pool: Data<DbPool>,
    path: Path<(String, String)>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let (role_id, permission_id) = path.into_inner();
    RbacService::assign_permission_to_role(&pool, &role_id, &permission_id)?;
    Ok(HttpResponse::Ok().finish()) // Ou NoContent
}

#[delete("/roles/{role_id}/permissions/{permission_id}")]
async fn revoke_permission_from_role_handler(
    pool: Data<DbPool>,
    path: Path<(String, String)>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let (role_id, permission_id) = path.into_inner();
    RbacService::revoke_permission_from_role(&pool, &role_id, &permission_id)?;
    Ok(HttpResponse::NoContent().finish())
}

#[get("/roles/{role_id}/permissions")]
async fn get_role_permissions_handler(
    pool: Data<DbPool>,
    path: Path<String>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<Permission>>, ApiError> {
    let role_id = path.into_inner();
    let permissions = RbacService::get_role_permissions(&pool, &role_id)?;
    Ok(Json(permissions))
}

// -- Usuário <-> Papel --

#[post("/users/{user_id}/roles/{role_id}")]
async fn assign_role_to_user_handler(
    pool: Data<DbPool>,
    path: Path<(String, String)>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let (user_id, role_id) = path.into_inner();
    RbacService::assign_role_to_user(&pool, &user_id, &role_id)?;
    Ok(HttpResponse::Ok().finish()) // Ou NoContent
}

#[delete("/users/{user_id}/roles/{role_id}")]
async fn revoke_role_from_user_handler(
    pool: Data<DbPool>,
    path: Path<(String, String)>,
    _user: AuthenticatedUser,
) -> Result<HttpResponse, ApiError> {
    let (user_id, role_id) = path.into_inner();
    RbacService::revoke_role_from_user(&pool, &user_id, &role_id)?;
    Ok(HttpResponse::NoContent().finish())
}

#[get("/users/{user_id}/roles")]
async fn get_user_roles_handler(
    pool: Data<DbPool>,
    path: Path<String>,
    _user: AuthenticatedUser,
) -> Result<Json<Vec<Role>>, ApiError> {
    let user_id = path.into_inner();
    let roles = RbacService::get_user_roles(&pool, &user_id)?;
    Ok(Json(roles))
}

// --- Handlers de Verificação ---

#[get("/check-permission/{user_id}/{permission_name}")]
async fn check_user_permission_handler(
    pool: Data<DbPool>,
    path: Path<(String, String)>,
    _user: AuthenticatedUser,
) -> Result<Json<PermissionCheckResponse>, ApiError> {
    let (user_id, permission_name) = path.into_inner();
    let has_permission = RbacService::check_user_permission(&pool, &user_id, &permission_name)?;
    Ok(Json(PermissionCheckResponse { has_permission }))
}

// Função para configurar o escopo das rotas RBAC
pub fn configure_rbac_routes(cfg: &mut web::ServiceConfig) {
    // Rotas de Leitura (acessíveis a usuários autenticados)
    cfg.service(list_permissions);
    cfg.service(get_permission_by_id);
    cfg.service(get_permission_by_name);
    cfg.service(list_roles);
    cfg.service(get_role_by_id);
    cfg.service(get_role_by_name);
    cfg.service(get_role_permissions_handler);
    cfg.service(get_user_roles_handler);
    cfg.service(check_user_permission_handler); // Quem pode checar? Por ora, autenticado.

    // Rotas de Escrita (requerem Admin)
    cfg.service(
        web::scope("") // Escopo vazio para aplicar middleware
            .wrap(AdminAuth::new())
            .service(create_permission)
            .service(update_permission)
            .service(delete_permission)
            .service(create_role)
            .service(update_role)
            .service(delete_role)
            .service(assign_permission_to_role_handler)
            .service(revoke_permission_from_role_handler)
            .service(assign_role_to_user_handler)
            .service(revoke_role_from_user_handler)
    );
}
