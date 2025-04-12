use crate::config::Config;
use crate::controllers::{
    auth_controller,
    health_controller,
    user_controller,
    two_factor_controller,
    token_controller,
    keystroke_controller,
    email_verification_controller, // Novo controlador de verificação por email 
};
use crate::middleware::{
    auth::{AdminAuth, JwtAuth},
    cors::configure_cors,
    error::ErrorHandler,
    logger::RequestLogger,
    rate_limiter::RateLimiter,
    keystroke_rate_limiter::KeystrokeRateLimiter,
    email_verification::EmailVerificationCheck, // Novo middleware de verificação por email 
};
use crate::services::keystroke_security_service::KeystrokeSecurityService;
use actix_web::{web, HttpResponse};
use tracing::info;
use std::time::Duration;

// Configura as rotas da API
pub fn configure_routes(cfg: &mut web::ServiceConfig, config: &Config) {
    // Configura o CORS
    let cors = configure_cors(config);

    // Configura os middlewares
    let jwt_auth = JwtAuth::new(config.jwt.secret.clone());
    let admin_auth = AdminAuth::new();
    let error_handler = ErrorHandler::new();
    let request_logger = RequestLogger::new();
    let rate_limiter = RateLimiter::new(
        config.security.rate_limit_requests,
        config.security.rate_limit_duration,
    );
    let email_verification_check = EmailVerificationCheck::new(); // Middleware de verificação por email 📧
    
    // Configurar middleware específico para keystroke dynamics
    let keystroke_rate_limiter = KeystrokeRateLimiter::new(
        config.security.keystroke_rate_limit_requests.unwrap_or(5),
        Duration::from_secs(config.security.keystroke_rate_limit_duration.unwrap_or(60)),
        Duration::from_secs(config.security.keystroke_block_duration.unwrap_or(300)),
    );
    
    // Configurar serviço de segurança para keystroke dynamics
    let keystroke_security_service = KeystrokeSecurityService::default();
    
    // Registrar o serviço de segurança como um dado compartilhado
    cfg.app_data(web::Data::new(keystroke_security_service.clone()));

    // Configura as rotas
    cfg.service(
        web::scope("/api")
            .wrap(cors)
            .wrap(error_handler)
            .wrap(request_logger)
            .wrap(rate_limiter) // Aplicar rate limiter a todas as rotas /api
            .service(
                web::scope("/auth")
                    .route("/register", web::post().to(auth_controller::register))
                    .route("/login", web::post().to(auth_controller::login))
                    .route("/forgot-password", web::post().to(auth_controller::forgot_password))
                    .route("/reset-password", web::post().to(auth_controller::reset_password))
                    .route("/unlock", web::post().to(auth_controller::unlock_account)) // <-- Nova rota de desbloqueio
                    .route("/refresh", web::post().to(auth_controller::refresh_token)) // <-- Nova rota de refresh token
                    // Rotas para rotação de tokens
                    .route("/token/rotate", web::post().to(token_controller::rotate_token))
                    .route("/token/revoke", web::post().to(token_controller::revoke_token))
                    .service(
                        // Rotas que exigem autenticação JWT
                        web::scope("")
                            .wrap(jwt_auth.clone())
                            .route("/me", web::get().to(auth_controller::me))
                            // Rota para revogar todos os tokens (logout de todos os dispositivos)
                            .route("/revoke-all/{id}", web::post().to(token_controller::revoke_all_tokens)),
                    )
                    // Rotas para verificação por email após login 📧
                    .service(
                        web::scope("/email-verification")
                            .wrap(jwt_auth.clone())
                            .route("/verify", web::post().to(email_verification_controller::verify_email_code))
                            .route("/resend", web::post().to(email_verification_controller::resend_verification_code)),
                    ),
            )
            .service(
                web::scope("/users")
                    .wrap(jwt_auth.clone()) // Proteger todas as rotas de usuário
                    .wrap(email_verification_check.clone()) // Verificar se o usuário confirmou o código de email 📧
                    .service(
                        web::resource("")
                            .wrap(admin_auth.clone()) // Apenas admin pode listar todos
                            .route(web::get().to(user_controller::list_users)),
                    )
                    .service(
                        web::resource("/{id}")
                            // GET /users/{id} - Admin ou o próprio usuário podem acessar
                            .route(web::get().to(user_controller::get_user))
                            // PUT /users/{id} - Admin ou o próprio usuário podem atualizar
                            .route(web::put().to(user_controller::update_user))
                            // DELETE /users/{id} - Apenas admin pode deletar
                            .route(web::delete().wrap(admin_auth.clone()).to(user_controller::delete_user)),
                    )
                    // POST /users/{id}/change-password - Apenas o próprio usuário pode mudar a senha
                    .route("/{id}/change-password", web::post().to(user_controller::change_password))
                    // Rotas para autenticação de dois fatores (2FA)
                    .service(
                        web::scope("/{id}/2fa")
                            // GET /users/{id}/2fa/setup - Inicia a configuração 2FA
                            .route("/setup", web::get().to(two_factor_controller::setup_2fa))
                            // POST /users/{id}/2fa/enable - Ativa 2FA
                            .route("/enable", web::post().to(two_factor_controller::enable_2fa))
                            // POST /users/{id}/2fa/disable - Desativa 2FA
                            .route("/disable", web::post().to(two_factor_controller::disable_2fa))
                            // POST /users/{id}/2fa/backup-codes - Regenera códigos de backup
                            .route("/backup-codes", web::post().to(two_factor_controller::regenerate_backup_codes))
                            // GET /users/{id}/2fa/status - Verifica o status do 2FA
                            .route("/status", web::get().to(two_factor_controller::get_2fa_status)),
                    )
                    // Rotas para verificação de ritmo de digitação (keystroke dynamics)
                    .service(
                        web::scope("/{id}/keystroke")
                            // Aplicar rate limiter específico para keystroke
                            .wrap(keystroke_rate_limiter.clone())
                            // POST /users/{id}/keystroke/register - Registra um novo padrão de digitação
                            .route("/register", web::post().to(keystroke_controller::register_keystroke_pattern))
                            // POST /users/{id}/keystroke/verify - Verifica um padrão de digitação
                            .route("/verify", web::post().to(keystroke_controller::verify_keystroke_pattern))
                            // PUT /users/{id}/keystroke/toggle - Habilita/desabilita a verificação
                            .route("/toggle", web::put().to(keystroke_controller::toggle_keystroke_verification))
                            // GET /users/{id}/keystroke/status - Verifica o status da verificação
                            .route("/status", web::get().to(keystroke_controller::get_keystroke_status)),
                    ),
            )
            .service(
                web::scope("/health")
                    .route("", web::get().to(health_controller::health_check))
                    .route("/version", web::get().to(health_controller::version)),
            )
            // Rota de manutenção para limpar tokens expirados (protegida por admin)
            .service(
                web::scope("/admin")
                    .wrap(jwt_auth.clone())
                    .wrap(admin_auth.clone())
                    .route("/clean-tokens", web::post().to(token_controller::clean_expired_tokens))
                    .route("/clean-verification-codes", web::post().to(email_verification_controller::clean_expired_codes)),
            ),
    )
    .service(
        // Rota raiz para uma mensagem simples
        web::resource("/").route(web::get().to(|| async {
            HttpResponse::Ok().body("API REST em Rust - Acesse /api para utilizar a API")
        })),
    );

    info!("🚀 Rotas configuradas com sucesso! Segurança de keystroke ativada 🔒");
}
