use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::TokenClaims;
use crate::models::response::{ApiResponse, PaginatedResponse};
use crate::models::user::{ChangePasswordDto, UpdateUserDto, UserResponse};
use crate::services::user_service::UserService;
use actix_web::{web, HttpResponse, Responder};
use validator::Validate;
use crate::models::temporary_password::CreateTemporaryPasswordDto;
use crate::config::Config;
// use std::sync::Arc; // Removido

// Lista todos os usuários (admin)
pub async fn list_users(
    pool: web::Data<DbPool>,
    query: web::Query<ListUsersQuery>,
) -> Result<impl Responder, ApiError> {
    // Obtém os parâmetros de paginação
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(10);

    // Lista os usuários
    let (users, total) = UserService::list_users(&pool, page, page_size)?;

    // Retorna a resposta paginada
    Ok(HttpResponse::Ok().json(PaginatedResponse::new(
        users,
        total,
        page,
        page_size,
    )))
}

// Obtém um usuário específico
pub async fn get_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    let claims = claims.into_inner();

    // Verifica se o usuário está tentando acessar seus próprios dados ou é admin
    if claims.sub != user_id && !claims.is_admin {
        return Err(ApiError::AuthorizationError(
            "Você não tem permissão para acessar os dados deste usuário".to_string(),
        ));
    }

    // Obtém o usuário
    let user = UserService::get_user_by_id(&pool, &user_id)?;

    // Converte para a resposta
    let user_response = UserResponse::from(user);

    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(user_response)))
}

// Atualiza um usuário
pub async fn update_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    update_dto: web::Json<UpdateUserDto>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    let update_dto = update_dto.into_inner();
    let claims = claims.into_inner();

    // Valida os dados
    update_dto.validate()?;

    // Verifica se o usuário está tentando atualizar seus próprios dados ou é admin
    if claims.sub != user_id && !claims.is_admin {
        return Err(ApiError::AuthorizationError(
            "Você não tem permissão para atualizar os dados deste usuário".to_string(),
        ));
    }

    // Verifica se está tentando alterar o status de ativação e se tem permissão
    // Renomear para _is_active para silenciar o aviso, pois só verificamos a presença
    if let Some(_is_active) = update_dto.is_active {
        if !claims.is_admin {
            return Err(ApiError::AuthorizationError(
                "Apenas administradores podem alterar o status de ativação de um usuário".to_string(),
            ));
        }
    }

    // Atualiza o usuário
    let user = UserService::update_user(&pool, &user_id, update_dto)?;

    // Converte para a resposta
    let user_response = UserResponse::from(user);

    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        user_response,
        "Usuário atualizado com sucesso",
    )))
}

// Altera a senha de um usuário
pub async fn change_password(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    change_dto: web::Json<ChangePasswordDto>,
    claims: web::ReqData<TokenClaims>,
    config: web::Data<crate::config::Config>,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    let change_dto = change_dto.into_inner();
    let claims = claims.into_inner();

    // Valida os dados
    change_dto.validate()?;

    // Verifica se o usuário está tentando alterar sua própria senha
    if claims.sub != user_id {
        return Err(ApiError::AuthorizationError(
            "Você só pode alterar sua própria senha".to_string(),
        ));
    }

    // Altera a senha
    UserService::change_password(
        &pool,
        &user_id,
        change_dto,
        config.security.password_salt_rounds,
    )?;

    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "Senha alterada com sucesso",
    )))
}

// Remove um usuário
pub async fn delete_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    let claims = claims.into_inner();

    // Verifica se o usuário está tentando excluir sua própria conta ou é admin
    // CUIDADO: Permitir que o usuário se exclua pode ter implicações.
    // if claims.sub == user_id {
    //     return Err(ApiError::BadRequestError("Você não pode excluir sua própria conta por esta rota.".to_string()));
    // }
    if !claims.is_admin { // Apenas admin pode excluir
        return Err(ApiError::AuthorizationError(
            "Você não tem permissão para excluir este usuário".to_string(),
        ));
    }

    // Remove o usuário
    UserService::delete_user(&pool, &user_id)?;

    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "Usuário removido com sucesso",
    )))
}

// ✨ Define uma senha temporária para o usuário autenticado
pub async fn set_temporary_password_handler(
    pool: web::Data<DbPool>, 
    dto: web::Json<CreateTemporaryPasswordDto>,
    claims: web::ReqData<TokenClaims>,
    config: web::Data<Config>,
) -> Result<HttpResponse, ApiError> {
    // Extrair ID do usuário autenticado a partir do token JWT
    let user_id = claims.sub.clone();
    
    // Verificar se o usuário existe (opcional, mas recomendado)
    let user = UserService::get_user_by_id(&pool, &user_id)?;
    
    // Verificar se a conta está ativa 
    if !user.is_active {
        return Err(ApiError::BadRequestError("Não é possível criar senha temporária para conta inativa ❌".to_string()));
    }
    
    // Chamar o serviço para criar a senha temporária
    let temp_password_response = UserService::set_temporary_password(
        pool.into_inner(),
        &user_id,
        dto.into_inner(),
        &config,
    ).await?;
    
    // Salvar o limite de uso antes de mover o temp_password_response
    let usage_limit = temp_password_response.usage_limit;
    
    // Retornar resposta de sucesso com detalhes da senha temporária
    Ok(HttpResponse::Created().json(ApiResponse::success_with_message(
        temp_password_response,
        &format!("Senha temporária criada com sucesso! 🎉🔑 (Limite de uso: {} vezes)", usage_limit)
    )))
}

// Estrutura para parâmetros de paginação
#[derive(serde::Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}
