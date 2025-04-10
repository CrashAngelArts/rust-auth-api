use crate::config::Config;
use crate::controllers::{
    auth_controller,
    health_controller,
    user_controller,
};
use crate::middleware::{
    auth::{AdminAuth, JwtAuth},
    cors::configure_cors,
    error::ErrorHandler,
    logger::RequestLogger,
    rate_limiter::RateLimiter,
};
use actix_web::{web, HttpResponse};
use log::info;

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
                    .service(
                        // Rotas que exigem autenticação JWT
                        web::scope("")
                            .wrap(jwt_auth.clone())
                            .route("/me", web::get().to(auth_controller::me)),
                            // Adicionar outras rotas autenticadas aqui se necessário
                    ),
            )
            .service(
                web::scope("/users")
                    .wrap(jwt_auth.clone()) // Proteger todas as rotas de usuário
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
                    .route("/{id}/change-password", web::post().to(user_controller::change_password)),
            )
            .service(
                web::scope("/health")
                    .route("", web::get().to(health_controller::health_check))
                    .route("/version", web::get().to(health_controller::version)),
            ),
    )
    .service(
        // Rota raiz para uma mensagem simples
        web::resource("/").route(web::get().to(|| async {
            HttpResponse::Ok().body("API REST em Rust - Acesse /api para utilizar a API")
        })),
    );

    info!("🚀 Rotas configuradas com sucesso!");
}
