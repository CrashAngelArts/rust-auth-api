use actix_web::{web, HttpResponse, Responder, Result as ActixResult, get, post, put, delete};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::errors::ApiError;
use crate::services::security_question_service::SecurityQuestionService;
use crate::middleware::permission::PermissionAuth;

// ----- DTOs para Perguntas de Segurança -----

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSecurityQuestionDto {
    pub text: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateSecurityQuestionDto {
    pub text: String,
    pub active: bool,
}

// ----- DTOs para Respostas de Usuários -----

#[derive(Debug, Serialize, Deserialize)]
pub struct SetUserAnswerDto {
    pub answer: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyAnswerDto {
    pub answer: String,
}

// ----- Handlers para Perguntas de Segurança -----

#[post("/security-questions")]
pub async fn create_security_question_handler(
    service: web::Data<SecurityQuestionService>,
    dto: web::Json<CreateSecurityQuestionDto>
) -> ActixResult<impl Responder> {
    let new_question = service.create_security_question(dto.text.clone())?;
    Ok(web::Json(new_question))
}

#[get("/security-questions")]
pub async fn list_security_questions_handler(
    service: web::Data<SecurityQuestionService>,
    query: web::Query<ListQuestionsQuery>,
) -> ActixResult<impl Responder> {
    let questions = service.list_security_questions(query.only_active.unwrap_or(false))?;
    Ok(web::Json(questions))
}

#[derive(Debug, Deserialize)]
pub struct ListQuestionsQuery {
    pub only_active: Option<bool>,
}

#[get("/security-questions/{question_id}")]
pub async fn get_security_question_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let question_id = path.into_inner();
    let question_uuid = Uuid::parse_str(&question_id)
        .map_err(|_| ApiError::BadRequest("ID da pergunta inválido 🚫".to_string()))?;
    
    let question = service.get_security_question_by_id(&question_uuid)?;
    Ok(web::Json(question))
}

#[put("/security-questions/{question_id}")]
pub async fn update_security_question_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<String>,
    dto: web::Json<UpdateSecurityQuestionDto>
) -> ActixResult<impl Responder> {
    let question_id = path.into_inner();
    let question_uuid = Uuid::parse_str(&question_id)
        .map_err(|_| ApiError::BadRequest("ID da pergunta inválido 🚫".to_string()))?;
    
    let updated_question = service.update_security_question(
        &question_uuid, 
        dto.text.clone(), 
        dto.active
    )?;
    
    Ok(web::Json(updated_question))
}

#[delete("/security-questions/{question_id}")]
pub async fn delete_security_question_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let question_id = path.into_inner();
    let question_uuid = Uuid::parse_str(&question_id)
        .map_err(|_| ApiError::BadRequest("ID da pergunta inválido 🚫".to_string()))?;
    
    service.delete_security_question(&question_uuid)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Pergunta de segurança excluída com sucesso ✅" })))
}

#[put("/security-questions/{question_id}/deactivate")]
pub async fn deactivate_security_question_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let question_id = path.into_inner();
    let question_uuid = Uuid::parse_str(&question_id)
        .map_err(|_| ApiError::BadRequest("ID da pergunta inválido 🚫".to_string()))?;
    
    let updated_question = service.deactivate_security_question(&question_uuid)?;
    Ok(web::Json(updated_question))
}

// ----- Handlers para Respostas de Usuários -----

#[post("/users/{user_id}/security-questions/{question_id}/answers")]
pub async fn set_user_answer_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<(String, String)>,
    dto: web::Json<SetUserAnswerDto>
) -> ActixResult<impl Responder> {
    let (user_id, question_id) = path.into_inner();
    
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("ID do usuário inválido 🚫".to_string()))?;
    
    let question_uuid = Uuid::parse_str(&question_id)
        .map_err(|_| ApiError::BadRequest("ID da pergunta inválido 🚫".to_string()))?;
    
    service.set_user_security_answer(&user_uuid, &question_uuid, &dto.answer)?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Resposta de segurança configurada com sucesso ✅" })))
}

#[get("/users/{user_id}/security-questions/answers")]
pub async fn get_user_answers_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let user_id = path.into_inner();
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("ID do usuário inválido 🚫".to_string()))?;
    
    let answers = service.get_user_security_answers(&user_uuid)?;
    Ok(web::Json(answers))
}

#[post("/users/{user_id}/security-questions/{question_id}/verify")]
pub async fn verify_user_answer_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<(String, String)>,
    dto: web::Json<VerifyAnswerDto>
) -> ActixResult<impl Responder> {
    let (user_id, question_id) = path.into_inner();
    
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("ID do usuário inválido 🚫".to_string()))?;
    
    let question_uuid = Uuid::parse_str(&question_id)
        .map_err(|_| ApiError::BadRequest("ID da pergunta inválido 🚫".to_string()))?;
    
    let is_valid = service.verify_security_answer(&user_uuid, &question_uuid, &dto.answer)?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({ "is_valid": is_valid })))
}

#[delete("/users/{user_id}/security-questions/{question_id}/answers")]
pub async fn delete_user_answer_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<(String, String)>
) -> ActixResult<impl Responder> {
    let (user_id, question_id) = path.into_inner();
    
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("ID do usuário inválido 🚫".to_string()))?;
    
    let question_uuid = Uuid::parse_str(&question_id)
        .map_err(|_| ApiError::BadRequest("ID da pergunta inválido 🚫".to_string()))?;
    
    service.delete_user_security_answer(&user_uuid, &question_uuid)?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Resposta de segurança removida com sucesso ✅" })))
}

#[delete("/users/{user_id}/security-questions/answers")]
pub async fn delete_all_user_answers_handler(
    service: web::Data<SecurityQuestionService>,
    path: web::Path<String>
) -> ActixResult<impl Responder> {
    let user_id = path.into_inner();
    let user_uuid = Uuid::parse_str(&user_id)
        .map_err(|_| ApiError::BadRequest("ID do usuário inválido 🚫".to_string()))?;
    
    service.delete_all_user_security_answers(&user_uuid)?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({ "message": "Todas as respostas de segurança removidas com sucesso ✅" })))
}

// Função para configurar as rotas de perguntas de segurança
pub fn configure_security_question_routes(cfg: &mut web::ServiceConfig) {
    // Rotas para administradores (gerenciar perguntas de segurança)
    cfg.service(
        web::scope("/admin")
            .wrap(PermissionAuth::new("security_questions:manage"))
            .service(create_security_question_handler)
            .service(update_security_question_handler)
            .service(delete_security_question_handler)
            .service(deactivate_security_question_handler)
    );
    
    // Rotas públicas (listar perguntas ativas)
    cfg.service(list_security_questions_handler);
    cfg.service(get_security_question_handler);
    
    // Rotas para usuários autenticados (gerenciar suas próprias respostas)
    cfg.service(set_user_answer_handler);
    cfg.service(get_user_answers_handler);
    cfg.service(verify_user_answer_handler);
    cfg.service(delete_user_answer_handler);
    cfg.service(delete_all_user_answers_handler);
} 