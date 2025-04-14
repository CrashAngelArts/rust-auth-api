use actix_web::{delete, get, post, put, web, HttpResponse};
use actix_web_grants::proc_macro::has_permissions;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::security_question::{
    CreateSecurityQuestionDto, CreateUserSecurityAnswerDto, UpdateSecurityQuestionDto
};
use crate::services::security_question_service::SecurityQuestionService;
use crate::utils::jwt::JwtUtils;
use std::env;
use validator::Validate;

// === Rotas para administradores (gerenciamento de perguntas) ===

#[post("/admin/questions")]
#[has_permissions("ADMIN")]
pub async fn create_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    dto: web::Json<CreateSecurityQuestionDto>,
) -> Result<HttpResponse, ApiError> {
    // Validar DTO
    dto.validate()?;
    
    // Processar a requisição
    let question = SecurityQuestionService::create_question(&pool, dto.into_inner())?;
    
    Ok(HttpResponse::Created().json(question))
}

#[get("/admin/questions/{id}")]
#[has_permissions("ADMIN")]
pub async fn get_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    let question = SecurityQuestionService::get_question_by_id(&pool, &id)?;
    
    Ok(HttpResponse::Ok().json(question))
}

#[get("/admin/questions")]
#[has_permissions("ADMIN")]
pub async fn list_questions(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    query: web::Query<ListQuestionsQuery>,
) -> Result<HttpResponse, ApiError> {
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(10);
    let only_active = query.only_active.unwrap_or(false);
    
    let (questions, total) = SecurityQuestionService::list_questions(
        &pool, page, page_size, only_active,
    )?;
    
    Ok(HttpResponse::Ok().json(ListResponse {
        data: questions,
        page,
        page_size,
        total,
    }))
}

#[put("/admin/questions/{id}")]
#[has_permissions("ADMIN")]
pub async fn update_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
    dto: web::Json<UpdateSecurityQuestionDto>,
) -> Result<HttpResponse, ApiError> {
    // Validar DTO
    dto.validate()?;
    
    let id = path.into_inner();
    let question = SecurityQuestionService::update_question(&pool, &id, dto.into_inner())?;
    
    Ok(HttpResponse::Ok().json(question))
}

#[delete("/admin/questions/{id}")]
#[has_permissions("ADMIN")]
pub async fn delete_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let id = path.into_inner();
    SecurityQuestionService::delete_question(&pool, &id)?;
    
    Ok(HttpResponse::NoContent().finish())
}

// === Rotas para usuários (perguntas e respostas) ===

#[get("/questions")]
pub async fn list_active_questions(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    query: web::Query<ListQuestionsQuery>,
) -> Result<HttpResponse, ApiError> {
    // Verificar token JWT
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET deve estar definido");
    let _claims = JwtUtils::verify(&jwt_secret, &auth.token())?;
    
    let page = query.page.unwrap_or(1);
    let page_size = query.page_size.unwrap_or(10);
    
    // Apenas perguntas ativas para usuários comuns
    let (questions, total) = SecurityQuestionService::list_questions(
        &pool, page, page_size, true,
    )?;
    
    Ok(HttpResponse::Ok().json(ListResponse {
        data: questions,
        page,
        page_size,
        total,
    }))
}

#[post("/users/me/security-answers")]
pub async fn add_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    dto: web::Json<CreateUserSecurityAnswerDto>,
) -> Result<HttpResponse, ApiError> {
    // Verificar token JWT
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET deve estar definido");
    let claims = JwtUtils::verify(&jwt_secret, &auth.token())?;
    
    // Validar DTO
    dto.validate()?;
    
    // Obter salt rounds para bcrypt
    let salt_rounds = env::var("BCRYPT_SALT_ROUNDS")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<u32>()
        .unwrap_or(10);
        
    // Processar a requisição
    let answer = SecurityQuestionService::add_user_answer(
        &pool, &claims.sub, dto.into_inner(), salt_rounds,
    )?;
    
    Ok(HttpResponse::Created().json(answer))
}

#[get("/users/me/security-answers")]
pub async fn list_user_answers(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
) -> Result<HttpResponse, ApiError> {
    // Verificar token JWT
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET deve estar definido");
    let claims = JwtUtils::verify(&jwt_secret, &auth.token())?;
    
    let answers = SecurityQuestionService::list_user_answers(&pool, &claims.sub)?;
    
    Ok(HttpResponse::Ok().json(answers))
}

#[put("/users/me/security-answers/{id}")]
pub async fn update_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    path: web::Path<String>,
    dto: web::Json<UpdateSecurityAnswerDto>,
) -> Result<HttpResponse, ApiError> {
    // Verificar token JWT
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET deve estar definido");
    let claims = JwtUtils::verify(&jwt_secret, &auth.token())?;
    
    // Validar DTO
    dto.validate()?;
    
    // Obter salt rounds para bcrypt
    let salt_rounds = env::var("BCRYPT_SALT_ROUNDS")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<u32>()
        .unwrap_or(10);
    
    let id = path.into_inner();
    let answer = SecurityQuestionService::update_user_answer(
        &pool, &claims.sub, &id, &dto.answer, salt_rounds,
    )?;
    
    Ok(HttpResponse::Ok().json(answer))
}

#[delete("/users/me/security-answers/{id}")]
pub async fn delete_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    // Verificar token JWT
    let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET deve estar definido");
    let claims = JwtUtils::verify(&jwt_secret, &auth.token())?;
    
    let id = path.into_inner();
    SecurityQuestionService::delete_user_answer(&pool, &claims.sub, &id)?;
    
    Ok(HttpResponse::NoContent().finish())
}

// === DTOs auxiliares ===

#[derive(serde::Deserialize)]
pub struct ListQuestionsQuery {
    pub page: Option<u64>,
    pub page_size: Option<u64>,
    pub only_active: Option<bool>,
}

#[derive(serde::Serialize)]
pub struct ListResponse<T> {
    pub data: T,
    pub page: u64,
    pub page_size: u64,
    pub total: u64,
}

#[derive(serde::Deserialize, Validate)]
pub struct UpdateSecurityAnswerDto {
    #[validate(length(min = 2, max = 100, message = "A resposta deve ter entre 2 e 100 caracteres"))]
    pub answer: String,
}

// === Configuração de rotas ===

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/security-questions")
            .service(create_question)
            .service(get_question)
            .service(list_questions)
            .service(update_question)
            .service(delete_question)
            .service(list_active_questions)
            .service(add_security_answer)
            .service(list_user_answers)
            .service(update_security_answer)
            .service(delete_security_answer)
    );
} 