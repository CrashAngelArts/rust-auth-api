//! Serviço stub para gerenciamento de credenciais WebAuthn 🔐
use crate::models::webauthn::WebauthnCredential;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref CREDENTIALS: Mutex<Vec<WebauthnCredential>> = Mutex::new(Vec::new());
}

pub struct WebauthnService;

impl WebauthnService {
    pub fn register_credential(cred: WebauthnCredential) {
        let mut creds = CREDENTIALS.lock().unwrap();
        creds.push(cred);
    }
    pub fn list_credentials(user_id: &str) -> Vec<WebauthnCredential> {
        let creds = CREDENTIALS.lock().unwrap();
        creds.iter().filter(|c| c.user_id == user_id).cloned().collect()
    }
}
