//! Controller para endpoints de gerenciamento de webhooks (stub inicial) 🚨
use actix_web::{get, post, delete, web, HttpResponse, Responder};
use crate::models::webhook::WebhookConfig;
use crate::services::webhook_service::WebhookService;

#[get("/api/webhooks")]
pub async fn list_webhooks() -> impl Responder {
    let hooks = WebhookService::list_webhooks();
    HttpResponse::Ok().json(hooks)
}

#[post("/api/webhooks")]
pub async fn register_webhook(web::Json(cfg): web::Json<WebhookConfig>) -> impl Responder {
    WebhookService::register_webhook(cfg);
    HttpResponse::Ok().body("Webhook cadastrado com sucesso! 🚨")
}

#[delete("/api/webhooks/{id}")]
pub async fn remove_webhook(id: web::Path<String>) -> impl Responder {
    WebhookService::remove_webhook(&id.into_inner());
    HttpResponse::Ok().body("Webhook removido com sucesso! 🚨")
}
