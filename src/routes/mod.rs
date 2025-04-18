use crate::config::Config;
use crate::controllers::{
    auth_controller,
    health_controller,
    user_controller,
    two_factor_controller,
    token_controller,
    keystroke_controller,
    email_verification_controller, // Novo controlador de verificação por email 
    device_controller, // Novo controlador de gerenciamento de dispositivos 📱
    recovery_email_controller, // Novo controlador de emails de recuperação 📧
    oauth_controller, // Novo controlador de autenticação OAuth 🔑
    rbac_controller, // <-- Adicionar import para rbac_controller
    security_question_controller, // <-- Adicionar import para security_question_controller
    webhook_controller, // <-- Novo controlador de webhooks 🚨
    webauthn_controller, // <-- Novo controlador de WebAuthn 🔐
    recovery_code_controller, // <-- Novo controlador de códigos de recuperação 🔑
    location_controller, // <-- Novo controlador de localizações de login 🌎
    time_pattern_controller, // <-- Adicionar import para time_pattern_controller
};
use crate::middleware::{
    auth::{AdminAuth, JwtAuth},
    cors::configure_cors,
    error::ErrorHandler,
    logger::RequestLogger,
    rate_limiter::RateLimiter,
    keystroke_rate_limiter::KeystrokeRateLimiter,
    email_verification::EmailVerificationCheck, // Novo middleware de verificação por email 
    csrf::CsrfProtect, // <-- Adicionado middleware CSRF 🛡️🍪
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
        config.security.rate_limit_capacity,
        config.security.rate_limit_refill_rate,
    );
    let email_verification_check = EmailVerificationCheck::new(); // Middleware de verificação por email 📧
    let csrf_protect = CsrfProtect::from_config(config); // <-- Instanciado middleware CSRF 🛡️🍪
    
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
            // --- Webhooks ---
            .service(webhook_controller::list_webhooks)
            .service(webhook_controller::register_webhook)
            .service(webhook_controller::remove_webhook)
            // --- WebAuthn ---
            .service(webauthn_controller::register_webauthn)
            .service(webauthn_controller::list_webauthn)
            .wrap(cors)
            .wrap(error_handler)
            .wrap(request_logger)
            .wrap(rate_limiter) // Aplicar rate limiter a todas as rotas /api
            .wrap(csrf_protect) // <-- Aplicado middleware CSRF a todas as rotas /api 🛡️🍪
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
                            .route("/revoke-all/{id}", web::post().to(token_controller::revoke_all_tokens))
                            // Rotas para gerenciamento de dispositivos 📱
                            .service(
                                web::scope("/devices")
                                    .route("", web::get().to(device_controller::list_devices))
                                    .route("/{id}", web::get().to(device_controller::get_device))
                                    .route("/{id}", web::put().to(device_controller::update_device))
                                    .route("/{id}", web::delete().to(device_controller::revoke_device)),
                            )
                            // Rotas para gerenciamento de emails de recuperação 📧
                            .service(
                                web::scope("/recovery-emails")
                                    .service(recovery_email_controller::list_recovery_emails)
                                    .service(recovery_email_controller::add_recovery_email)
                                    .service(recovery_email_controller::verify_recovery_email)
                                    .service(recovery_email_controller::remove_recovery_email)
                                    .service(recovery_email_controller::resend_verification_email),
                            ),
                    )
                    // Rotas para verificação por email após login 📧
                    .service(
                        web::scope("/email-verification")
                            .wrap(jwt_auth.clone())
                            .route("/verify", web::post().to(email_verification_controller::verify_email_code))
                            .route("/resend", web::post().to(email_verification_controller::resend_verification_code)),
                    )
                    // Rotas para autenticação OAuth 🔑
                    .service(
                        web::scope("/oauth")
                            // Iniciar login OAuth (não requer autenticação)
                            .route("/login", web::post().to(oauth_controller::oauth_login))
                            // Callback OAuth (não requer autenticação)
                            .route("/callback", web::get().to(oauth_controller::oauth_callback))
                            // Rotas que exigem autenticação JWT
                            .service(
                                web::scope("")
                                    .wrap(jwt_auth.clone())
                                    .wrap(email_verification_check.clone())
                                    // Listar conexões OAuth do usuário
                                    .route("/connections/{user_id}", web::get().to(oauth_controller::list_oauth_connections))
                                    // Remover conexão OAuth
                                    .route("/connections/{user_id}/{connection_id}", web::delete().to(oauth_controller::remove_oauth_connection)),
                            ),
                    ),
            )
            .service(
                web::scope("/users")
                    .wrap(jwt_auth.clone())
                    .wrap(email_verification_check.clone())
                    // Rota para listar todos (apenas admin)
                    .service(
                        web::resource("")
                            .wrap(admin_auth.clone())
                            .route(web::get().to(user_controller::list_users))
                    )
                    // Rotas específicas por ID
                    .service(
                        web::resource("/{id}")
                            .route(web::get().to(user_controller::get_user))
                            .route(web::put().to(user_controller::update_user))
                            .route(web::delete().wrap(admin_auth.clone()).to(user_controller::delete_user))
                    )
                    // Rota para alterar senha (usa ID na URL)
                    .service(
                        web::resource("/{id}/change-password")
                            .route(web::post().to(user_controller::change_password))
                    )
                    // ✨ Rota para definir senha temporária (rota "/me/")
                    .service(
                        web::resource("/me/temporary-password")
                            .route(web::post().to(user_controller::set_temporary_password_handler))
                    )
                    // Rotas para autenticação de dois fatores (2FA) - Usam {id}
                    .service(
                        web::scope("/{id}/2fa")
                            .route("/setup", web::get().to(two_factor_controller::setup_2fa))
                            .route("/enable", web::post().to(two_factor_controller::enable_2fa))
                            .route("/disable", web::post().to(two_factor_controller::disable_2fa))
                            .route("/backup-codes", web::post().to(two_factor_controller::regenerate_backup_codes))
                            .route("/status", web::get().to(two_factor_controller::get_2fa_status))
                    )
                    // Rotas para verificação de ritmo de digitação - Usam {id}
                    .service(
                        web::scope("/{id}/keystroke")
                            .wrap(keystroke_rate_limiter.clone())
                            .route("/register", web::post().to(keystroke_controller::register_keystroke_pattern))
                            .route("/verify", web::post().to(keystroke_controller::verify_keystroke_pattern))
                            .route("/toggle", web::put().to(keystroke_controller::toggle_keystroke_verification))
                            .route("/status", web::get().to(keystroke_controller::get_keystroke_status))
                    )
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
                    .route("/clean-verification-codes", web::post().to(email_verification_controller::clean_expired_codes))
                    .route("/clean-sessions", web::post().to(device_controller::clean_expired_sessions)),
            )
            // Adicionar o escopo para RBAC
            .service(
                web::scope("/rbac") // Criar um escopo interno para aplicar o wrap
                    .wrap(jwt_auth.clone()) // Aplicar JwtAuth a todas as rotas /api/rbac
                    .configure(rbac_controller::configure_rbac_routes) // Usar .configure para registrar as rotas
            )
            // Rotas para perguntas de segurança
            .service(
                web::scope("/security-questions")
                    .wrap(jwt_auth.clone())
                    .configure(security_question_controller::config) // Usar a função config para configurar as rotas
            )
            // Rotas para códigos de recuperação 🔑
            .service(
                web::scope("/recovery-codes")
                    .wrap(jwt_auth.clone())
                    .configure(recovery_code_controller::config) // Usar a função config para configurar as rotas
            )
            // Rotas para localizações de login 🌎
            .service(
                web::scope("/locations")
                    .wrap(jwt_auth.clone())
                    .configure(location_controller::config) // Usar a função config para configurar as rotas
            )
            // Rotas de verificação de email
            .service(
                web::scope("/verification")
                    .wrap(jwt_auth.clone())
                    .configure(email_verification_controller::config)
            )
            // Rotas de padrões temporais
            .service(
                web::scope("/time-patterns")
                    .wrap(jwt_auth.clone())
                    .configure(time_pattern_controller::config)
            )
    )
    .service(
        // Rota raiz para servir o arquivo index.html da pasta static
        web::resource("/").route(web::get().to(|| async {
            // Ler o arquivo index.html da pasta static
            match std::fs::read_to_string("static/index.html") {
                Ok(content) => HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(content),
                Err(_) => HttpResponse::InternalServerError()
                    .body("Erro ao carregar a página inicial 😢")
            }
        })),
    );

    info!("🚀 Rotas configuradas com sucesso! Segurança de keystroke ativada 🔒");
}
