//! Modelo para credenciais WebAuthn/Passkeys 🔐
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredential {
    pub id: String,         // UUID
    pub user_id: String,    // ID do usuário
    pub cred_id: String,    // ID da credencial (base64)
    pub public_key: String, // Chave pública (base64)
    pub sign_count: u32,    // Contador de assinaturas
    pub nickname: Option<String>, // Nome amigável
    pub created_at: String, // ISO8601
}
