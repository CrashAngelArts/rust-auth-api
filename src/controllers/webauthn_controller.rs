//! Controller stub para endpoints WebAuthn/Passkeys 🔐
use actix_web::{get, post, web, HttpResponse, Responder};
use crate::models::webauthn::WebauthnCredential;
use crate::services::webauthn_service::WebauthnService;

#[post("/api/webauthn/register")]
pub async fn register_webauthn(web::Json(cred): web::Json<WebauthnCredential>) -> impl Responder {
    WebauthnService::register_credential(cred);
    HttpResponse::Ok().body("Credencial WebAuthn registrada com sucesso! 🔐")
}

#[get("/api/webauthn/credentials/{user_id}")]
pub async fn list_webauthn(user_id: web::Path<String>) -> impl Responder {
    let creds = WebauthnService::list_credentials(&user_id);
    HttpResponse::Ok().json(creds)
}
