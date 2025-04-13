use crate::config::Config;
use crate::db::DbPool;
use crate::errors::ApiError;
use crate::middleware::auth::{AdminAuth, AuthenticatedUser};
use crate::models::auth::TokenClaims;
use crate::models::response::{ApiResponse, PaginatedResponse};
use crate::models::user::{ChangePasswordDto, UpdateUserDto, UserResponse};
use crate::services::user_service::UserService;
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use validator::Validate;

// Estrutura para a resposta do código de recuperação
#[derive(serde::Serialize)]
struct RecoveryCodeResponse {
    recovery_code: String,
    message: String,
}

// Estrutura para verificar o código de recuperação
#[derive(Deserialize)]
struct VerifyRecoveryCodeDto {
    code: String,
}

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
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();

    // Verificar se o usuário autenticado é admin ou o próprio usuário
    if !auth_user.is_admin && auth_user.id != user_id {
        return Err(ApiError::AuthorizationError("Acesso negado".to_string()));
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
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();

    // Verificar se o usuário autenticado é admin ou o próprio usuário
    if !auth_user.is_admin && auth_user.id != user_id {
        return Err(ApiError::AuthorizationError("Acesso negado".to_string()));
    }

    // Valida os dados
    update_dto.validate()?;

    // Verifica se está tentando alterar o status de ativação e se tem permissão
    // Renomear para _is_active para silenciar o aviso, pois só verificamos a presença
    if let Some(_is_active) = update_dto.is_active {
        if !auth_user.is_admin {
            return Err(ApiError::AuthorizationError(
                "Apenas administradores podem alterar o status de ativação de um usuário".to_string(),
            ));
        }
    }

    // Atualiza o usuário
    let user = UserService::update_user(&pool, &user_id, update_dto.into_inner())?;

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
    auth_user: AuthenticatedUser,
    req: HttpRequest,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    let config = req.app_data::<web::Data<Config>>().unwrap().get_ref();

    // Apenas o próprio usuário pode mudar sua senha
    if auth_user.id != user_id {
        return Err(ApiError::AuthorizationError("Acesso negado".to_string()));
    }

    change_dto.validate()?;
    UserService::change_password(
        &pool, 
        &user_id, 
        &change_dto.current_password, 
        &change_dto.new_password, 
        config.security.password_salt_rounds
    )?;
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "Senha alterada com sucesso",
    )))
}

// Remove um usuário
pub async fn delete_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();

    // Verifica se o usuário está tentando excluir sua própria conta ou é admin
    // CUIDADO: Permitir que o usuário se exclua pode ter implicações.
    // if auth_user.id == user_id {
    //     return Err(ApiError::BadRequestError("Você não pode excluir sua própria conta por esta rota.".to_string()));
    // }
    if !auth_user.is_admin { // Apenas admin pode excluir
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

// Estrutura para parâmetros de paginação
#[derive(serde::Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
}

// --- Handlers para Código Único de Recuperação ---

#[post("/{id}/recovery-code")]
pub async fn generate_recovery_code_handler(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    auth_user: AuthenticatedUser,
    req: HttpRequest,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    let config = req.app_data::<web::Data<Config>>().unwrap().get_ref();

    // Apenas o próprio usuário (ou admin) pode gerar
    if !auth_user.is_admin && auth_user.id != user_id {
        return Err(ApiError::AuthorizationError("Acesso negado".to_string()));
    }

    // Gerar o código (UserService fará o hash e salvará)
    let recovery_code = UserService::generate_recovery_code(
        &pool, 
        &user_id, 
        config.security.password_salt_rounds
    )?;

    let response = RecoveryCodeResponse {
        recovery_code,
        message: "Código único de recuperação gerado. Guarde-o em um local seguro! Ele não será mostrado novamente.".to_string(),
    };

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

// Rota para verificar o código (pode ser pública se usada ANTES do login no fluxo de recuperação)
// Ou pode ser protegida se usada para verificar o código como um passo pós-login
// Vamos deixá-la pública por enquanto, assumindo que será usada em um fluxo de recuperação
#[post("/recovery/verify-code/{user_id}")] // Rota pública temporária
pub async fn verify_recovery_code_handler(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    dto: web::Json<VerifyRecoveryCodeDto>,
) -> Result<impl Responder, ApiError> {
    let user_id = path.into_inner();
    
    let is_valid = UserService::verify_recovery_code(&pool, &user_id, &dto.code)?;
    
    if is_valid {
        // Opcional: Limpar o código após verificação bem-sucedida? 
        // Depende do fluxo: Se isso dá acesso direto, sim. Se é só um passo, talvez não.
        // UserService::clear_recovery_code(&pool, &user_id)?;
        Ok(HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({ "valid": true }))))
    } else {
        // Usar um erro genérico para não vazar se o usuário/código existe
        Err(ApiError::AuthenticationError("Código de recuperação inválido ou expirado.".to_string()))
    }
}
