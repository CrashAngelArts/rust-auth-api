use actix_web::{web, HttpResponse, Responder, Result as ActixResult, get, post, put, delete};
// use crate::errors::ApiError; // Remover se não usado
use crate::models::{
    permission::{CreatePermissionDto, /*Permission,*/ UpdatePermissionDto}, // Remover Permission
    role::{CreateRoleDto, /*Role,*/ UpdateRoleDto}, // Remover Role
};
use crate::services::rbac_service::RbacService;
use crate::middleware::permission::PermissionAuth;
use serde::Serialize;

// --- Funções Handler para Permissões ---

#[post("/permissions")]
pub async fn create_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    dto: web::Json<CreatePermissionDto>
) -> ActixResult<impl Responder> {
    let new_permission = rbac_service.create_permission(dto.into_inner())?; // Chamar método na instância
    Ok(web::Json(new_permission))
}

#[get("/permissions")]
pub async fn list_permissions_handler(
    rbac_service: web::Data<RbacService> // Receber RbacService
) -> ActixResult<impl Responder> {
    let permissions = rbac_service.list_permissions()?; // Chamar método na instância
    Ok(web::Json(permissions))
}

#[get("/permissions/id/{permission_id}")]
pub async fn get_permission_by_id_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String> // Renomear para clareza se desejar
) -> ActixResult<impl Responder> {
    let permission_id = path.into_inner();
    let permission = rbac_service.get_permission_by_id(&permission_id)?; // Chamar método na instância
    Ok(web::Json(permission))
}

#[get("/permissions/name/{permission_name}")]
pub async fn get_permission_by_name_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let permission_name = path.into_inner();
    let permission = rbac_service.get_permission_by_name(&permission_name)?; // Chamar método na instância
    Ok(web::Json(permission))
}

#[put("/permissions/{permission_id}")]
pub async fn update_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>,
    dto: web::Json<UpdatePermissionDto>
) -> ActixResult<impl Responder> {
    let permission_id = path.into_inner();
    let updated_permission = rbac_service.update_permission(&permission_id, dto.into_inner())?; // Chamar método
    Ok(web::Json(updated_permission))
}

#[delete("/permissions/{permission_id}")]
pub async fn delete_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let permission_id = path.into_inner();
    rbac_service.delete_permission(&permission_id)?; // Chamar método
    Ok(HttpResponse::Ok().finish()) // Retornar 200 OK sem corpo
}

// --- Funções Handler para Papéis (Roles) ---

#[post("/roles")]
pub async fn create_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    dto: web::Json<CreateRoleDto>
) -> ActixResult<impl Responder> {
    let new_role = rbac_service.create_role(dto.into_inner())?; // Chamar método
    Ok(web::Json(new_role))
}

#[get("/roles")]
pub async fn list_roles_handler(
    rbac_service: web::Data<RbacService> // Receber RbacService
) -> ActixResult<impl Responder> {
    let roles = rbac_service.list_roles()?; // Chamar método
    Ok(web::Json(roles))
}

#[get("/roles/id/{role_id}")]
pub async fn get_role_by_id_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let role_id = path.into_inner();
    let role = rbac_service.get_role_by_id(&role_id)?; // Chamar método
    Ok(web::Json(role))
}

#[get("/roles/name/{role_name}")]
pub async fn get_role_by_name_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let role_name = path.into_inner();
    let role = rbac_service.get_role_by_name(&role_name)?; // Chamar método
    Ok(web::Json(role))
}

#[put("/roles/{role_id}")]
pub async fn update_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>,
    dto: web::Json<UpdateRoleDto>
) -> ActixResult<impl Responder> {
    let role_id = path.into_inner();
    // update_role agora retorna Result<(), ApiError>
    rbac_service.update_role(&role_id, dto.into_inner())?; // Chamar método
    // Retornar 200 OK sem corpo ou buscar o papel atualizado e retorná-lo
    // Opção 1: Retornar Ok sem corpo
    Ok(HttpResponse::Ok().finish())
    // Opção 2: Buscar e retornar (requer chamada extra)
    // let updated_role = rbac_service.get_role_by_id(&role_id)?;
    // Ok(web::Json(updated_role))
}

#[delete("/roles/{role_id}")]
pub async fn delete_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let role_id = path.into_inner();
    rbac_service.delete_role(&role_id)?; // Chamar método
    Ok(HttpResponse::Ok().finish()) // Retornar 200 OK sem corpo
}

// --- Funções Handler para Associações ---

#[post("/roles/{role_id}/permissions/{permission_id}")]
pub async fn assign_permission_to_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)>
) -> ActixResult<impl Responder> {
    let (role_id, permission_id) = path.into_inner();
    rbac_service.assign_permission_to_role(&role_id, &permission_id)?; // Chamar método
    Ok(HttpResponse::Ok().finish())
}

#[delete("/roles/{role_id}/permissions/{permission_id}")]
pub async fn revoke_permission_from_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)>
) -> ActixResult<impl Responder> {
    let (role_id, permission_id) = path.into_inner();
    rbac_service.revoke_permission_from_role(&role_id, &permission_id)?; // Chamar método
    Ok(HttpResponse::Ok().finish())
}

#[get("/roles/{role_id}/permissions")]
pub async fn get_role_permissions_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let role_id = path.into_inner();
    let permissions = rbac_service.get_role_permissions(&role_id)?; // Chamar método
    Ok(web::Json(permissions))
}

#[post("/users/{user_id}/roles/{role_id}")]
pub async fn assign_role_to_user_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)>
) -> ActixResult<impl Responder> {
    let (user_id, role_id) = path.into_inner();
    rbac_service.assign_role_to_user(&user_id, &role_id)?; // Chamar método
    Ok(HttpResponse::Ok().finish())
}

#[delete("/users/{user_id}/roles/{role_id}")]
pub async fn revoke_role_from_user_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)>
) -> ActixResult<impl Responder> {
    let (user_id, role_id) = path.into_inner();
    rbac_service.revoke_role_from_user(&user_id, &role_id)?; // Chamar método
    Ok(HttpResponse::Ok().finish())
}

#[get("/users/{user_id}/roles")]
pub async fn get_user_roles_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let user_id = path.into_inner();
    let roles = rbac_service.get_user_roles(&user_id)?; // Chamar método
    Ok(web::Json(roles))
}

#[get("/users/{user_id}/permissions/{permission_name}/check")]
pub async fn check_user_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)>
) -> ActixResult<impl Responder> {
    let (user_id, permission_name) = path.into_inner();
    let has_permission = rbac_service.check_user_permission(&user_id, &permission_name)?; // Chamar método
    Ok(web::Json(serde_json::json!({ "has_permission": has_permission })))
}

// Função para configurar o escopo das rotas RBAC
pub fn configure_rbac_routes(cfg: &mut web::ServiceConfig) {
    // Rotas de Leitura (acessíveis a usuários autenticados - sem wrap adicional aqui)
    cfg.service(list_permissions_handler);
    cfg.service(get_permission_by_id_handler);
    cfg.service(get_permission_by_name_handler);
    cfg.service(list_roles_handler);
    cfg.service(get_role_by_id_handler);
    cfg.service(get_role_by_name_handler);
    cfg.service(get_role_permissions_handler);
    cfg.service(get_user_roles_handler);
    cfg.service(check_user_permission_handler);

    // Rotas de Escrita (requerem permissões específicas)
    // Agrupar por tipo de permissão necessária

    // Gerenciamento de Permissões
    cfg.service(
        web::scope("/permissions") // Escopo para permissões
            .wrap(PermissionAuth::new("permissions:manage")) // Requer permissão
            .service(create_permission_handler)
            .service(update_permission_handler)
            .service(delete_permission_handler)
    );

    // Gerenciamento de Papéis
    cfg.service(
        web::scope("/roles") // Escopo para papéis
            .wrap(PermissionAuth::new("roles:manage")) // Requer permissão
            .service(create_role_handler)
            .service(update_role_handler)
            .service(delete_role_handler)
    );

    // Associações Papel <-> Permissão
    cfg.service(
        web::scope("/roles/{role_id}/permissions") // Escopo para associações
            .wrap(PermissionAuth::new("roles:assign-permission")) // Requer permissão
            .service(assign_permission_to_role_handler)       // POST /{permission_id}
            .service(revoke_permission_from_role_handler)   // DELETE /{permission_id}
            // GET já está registrado fora deste wrap
    );

     // Associações Usuário <-> Papel
    cfg.service(
        web::scope("/users/{user_id}/roles") // Escopo para associações
            .wrap(PermissionAuth::new("users:assign-role")) // Requer permissão
            .service(assign_role_to_user_handler)       // POST /{role_id}
            .service(revoke_role_from_user_handler)   // DELETE /{role_id}
             // GET já está registrado fora deste wrap
    );
}
