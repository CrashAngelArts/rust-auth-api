//! Modelo para configuração de Webhooks de eventos de segurança 🚨
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: String, // UUID
    pub url: String,
    pub event_type: String, // Ex: "login_suspeito", "senha_alterada"
    pub enabled: bool,
}
