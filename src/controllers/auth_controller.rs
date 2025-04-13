use crate::config::Config; // Importar Config
use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::{
    ForgotPasswordDto, LoginDto, RefreshTokenDto, RegisterDto, ResetPasswordDto, TokenClaims, // Adicionar RefreshTokenDto
    UnlockAccountDto,
};
use crate::models::response::ApiResponse;
use crate::models::user::UserResponse;
use crate::services::{auth_service::AuthService, email_service::EmailService, user_service::UserService};
use crate::services::security_question_service::SecurityQuestionService; // Importar serviço de perguntas de segurança
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use tracing::{error, warn};
use validator::Validate;
use serde::{Deserialize, Serialize};
use serde_json::json;

// Novos DTOs para perguntas de segurança na recuperação de senha
#[derive(Debug, Deserialize, Validate)]
pub struct GetSecurityQuestionsDto {
    #[validate(email(message = "Email inválido"))]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct VerifySecurityQuestionDto {
    #[validate(email(message = "Email inválido"))]
    pub email: String,
    pub question_id: String,
    pub answer: String,
}

// Registra um novo usuário
pub async fn register(
    pool: web::Data<DbPool>,
    register_dto: web::Json<RegisterDto>,
    config: web::Data<Config>, // Usar Config importado
    email_service: web::Data<EmailService>,
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    register_dto.validate()?;

    // Registra o usuário
    let user = AuthService::register(
        &pool,
        register_dto.into_inner(),
        config.security.password_salt_rounds,
    )?;

    // Envia email de boas-vindas
    if config.email.enabled { // Verificar se email está habilitado na config
        // Usar .await na chamada assíncrona
        if let Err(e) = email_service.send_welcome_email(&user).await {
            error!("❌ Erro ao enviar email de boas-vindas: {}", e);
            // Não retornar erro aqui, o registro foi bem-sucedido
        }
    }

    // Converte para a resposta
    let user_response = UserResponse::from(user);

    // Retorna a resposta
    Ok(HttpResponse::Created().json(ApiResponse::success_with_message(
        user_response,
        "Usuário registrado com sucesso",
    )))
}

// Atualiza o token de acesso usando um refresh token
pub async fn refresh_token(
    pool: web::Data<DbPool>,
    refresh_dto: web::Json<RefreshTokenDto>,
    config: web::Data<Config>,
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    refresh_dto.validate()?;

    // Tenta atualizar o token
    let auth_response = AuthService::refresh_token(&pool, refresh_dto.into_inner(), &config)?;

    // Retorna a nova resposta de autenticação
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        auth_response,
        "Token atualizado com sucesso",
    )))
}

// Autentica um usuário
pub async fn login(
    pool: web::Data<DbPool>,
    login_dto: web::Json<LoginDto>,
    config: web::Data<Config>, // Usar Config importado
    email_service: web::Data<EmailService>, // Adicionar EmailService
    req: HttpRequest,
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    login_dto.validate()?;

    // Extrai informações da requisição
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_owned());

    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned());

    // Autentica o usuário, passando config e email_service
    // Usar .await na chamada assíncrona
    let auth_response = AuthService::login(
        &pool,
        login_dto.into_inner(),
        &config, // Passar a referência da configuração
        ip_address,
        user_agent,
        &email_service, // Passar a referência do serviço de email
    ).await?;

    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success_with_message(
        auth_response,
        "Login realizado com sucesso",
    )))
}

// Solicita a recuperação de senha
pub async fn forgot_password(
    pool: web::Data<DbPool>,
    forgot_dto: web::Json<ForgotPasswordDto>,
    email_service: web::Data<EmailService>,
    config: web::Data<Config>, // Adicionar Config para verificar se email está habilitado
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    forgot_dto.validate()?;

    // Solicita a recuperação de senha (apenas se email estiver habilitado)
    if config.email.enabled {
        // Usar .await na chamada assíncrona
        AuthService::forgot_password(&pool, forgot_dto.into_inner(), &email_service, None).await?;
    } else {
        warn!("⚠️ Tentativa de recuperação de senha com emails desabilitados.");
        // Retornar a mesma mensagem genérica para não vazar informação
    }

    // Retorna a resposta genérica
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "Se o email estiver cadastrado e ativo, você receberá instruções para redefinir sua senha",
    )))
}

// Redefine a senha
pub async fn reset_password(
    pool: web::Data<DbPool>,
    reset_dto: web::Json<ResetPasswordDto>,
    config: web::Data<Config>, // Usar Config importado
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    reset_dto.validate()?;

    // Redefine a senha
    AuthService::reset_password(&pool, reset_dto.into_inner(), config.security.password_salt_rounds, None)?;

    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "Senha redefinida com sucesso",
    )))
}

// Desbloqueia a conta usando um token
pub async fn unlock_account(
    pool: web::Data<DbPool>,
    unlock_dto: web::Json<UnlockAccountDto>,
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    unlock_dto.validate()?;

    // Tenta desbloquear a conta
    AuthService::unlock_account(&pool, unlock_dto.into_inner())?;

    // Retorna a resposta de sucesso
    Ok(HttpResponse::Ok().json(ApiResponse::<()>::message(
        "Conta desbloqueada com sucesso. Você já pode tentar fazer login novamente.",
    )))
}


// Obtém informações do usuário atual (requer autenticação)
pub async fn me(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>, // Extrai claims do middleware JwtAuth
) -> Result<impl Responder, ApiError> {
    // Obtém o usuário pelo ID (sub) presente nas claims do token JWT
    let claims = claims.into_inner();
    let user = UserService::get_user_by_id(&pool, &claims.sub)?;

    // Converte para a resposta segura (sem dados sensíveis)
    let user_response = UserResponse::from(user);

    // Retorna a resposta
    Ok(HttpResponse::Ok().json(ApiResponse::success(user_response)))
}

// Novo endpoint para obter perguntas de segurança para um email
pub async fn get_security_questions(
    pool: web::Data<DbPool>,
    dto: web::Json<GetSecurityQuestionsDto>,
    security_question_service: web::Data<SecurityQuestionService>,
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    dto.validate()?;

    // Obter perguntas de segurança para o usuário
    match AuthService::get_security_questions_for_recovery(&pool, &dto.email, &security_question_service) {
        Ok(questions) => {
            // Formatar as perguntas para o frontend
            let formatted_questions: Vec<serde_json::Value> = questions
                .into_iter()
                .map(|(id, text)| {
                    json!({
                        "id": id.to_string(),
                        "text": text
                    })
                })
                .collect();

            Ok(HttpResponse::Ok().json(json!({
                "questions": formatted_questions,
                "message": "Perguntas de segurança disponíveis 🔐"
            })))
        },
        Err(e) => {
            // Converter NotFound para um erro mais genérico para evitar enumeração de usuários
            match e {
                ApiError::NotFound(_) => {
                    Ok(HttpResponse::Ok().json(json!({
                        "questions": [],
                        "message": "Nenhuma pergunta de segurança encontrada 🔍"
                    })))
                },
                _ => Err(e),
            }
        }
    }
}

// Novo endpoint para verificar resposta a uma pergunta de segurança
pub async fn verify_security_question(
    pool: web::Data<DbPool>,
    dto: web::Json<VerifySecurityQuestionDto>,
    security_question_service: web::Data<SecurityQuestionService>,
) -> Result<impl Responder, ApiError> {
    // Valida os dados de entrada
    dto.validate()?;

    // Verificar a resposta
    let is_valid = AuthService::verify_security_question_for_reset(
        &pool,
        &dto.email,
        &dto.question_id,
        &dto.answer,
        &security_question_service,
    )?;

    Ok(HttpResponse::Ok().json(json!({
        "verified": is_valid,
        "message": if is_valid { 
            "Resposta verificada com sucesso ✅" 
        } else { 
            "Resposta incorreta ❌" 
        }
    })))
}
