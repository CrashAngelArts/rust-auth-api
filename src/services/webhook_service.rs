//! Serviço para gerenciamento e disparo de Webhooks (stub inicial) 🚨
use crate::models::webhook::WebhookConfig;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref WEBHOOKS: Mutex<Vec<WebhookConfig>> = Mutex::new(Vec::new());
}

pub struct WebhookService;

impl WebhookService {
    pub fn register_webhook(cfg: WebhookConfig) {
        let mut hooks = WEBHOOKS.lock().unwrap();
        hooks.push(cfg);
    }
    pub fn remove_webhook(id: &str) {
        let mut hooks = WEBHOOKS.lock().unwrap();
        hooks.retain(|w| w.id != id);
    }
    pub fn trigger_event(event_type: &str, payload: &str) {
        let hooks = WEBHOOKS.lock().unwrap();
        for hook in hooks.iter().filter(|h| h.enabled && h.event_type == event_type) {
            // Aqui só loga, integração real virá depois
            log::info!("🚨 Disparando webhook para {}: {}", hook.url, payload);
        }
    }
    pub fn list_webhooks() -> Vec<WebhookConfig> {
        WEBHOOKS.lock().unwrap().clone()
    }
}
