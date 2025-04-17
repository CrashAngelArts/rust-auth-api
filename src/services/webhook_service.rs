//! Serviço para gerenciamento e disparo de Webhooks (stub inicial) 🚨
use crate::models::webhook::WebhookConfig;
use std::{fs, sync::Mutex};
use lazy_static::lazy_static;

const WEBHOOKS_FILE: &str = "webhooks.json";

lazy_static! {
    static ref WEBHOOKS: Mutex<Vec<WebhookConfig>> = Mutex::new(load_webhooks_from_file());
}

fn load_webhooks_from_file() -> Vec<WebhookConfig> {
    match fs::read_to_string(WEBHOOKS_FILE) {
        Ok(data) => {
            serde_json::from_str(&data).unwrap_or_else(|_| {
                log::warn!("Falha ao desserializar webhooks.json, iniciando vazio 😅");
                Vec::new()
            })
        },
        Err(_) => {
            log::info!("Arquivo webhooks.json não encontrado, iniciando vazio 📄");
            Vec::new()
        }
    }
}

fn save_webhooks_to_file(hooks: &Vec<WebhookConfig>) {
    match serde_json::to_string_pretty(hooks) {
        Ok(json) => {
            if let Err(e) = fs::write(WEBHOOKS_FILE, json) {
                log::error!("Erro ao salvar webhooks.json: {} ❌", e);
            } else {
                log::info!("Webhooks salvos em disco com sucesso! 💾");
            }
        },
        Err(e) => log::error!("Erro ao serializar webhooks: {} ❌", e),
    }
}


pub struct WebhookService;

impl WebhookService {
    pub fn register_webhook(cfg: WebhookConfig) {
        let mut hooks = WEBHOOKS.lock().unwrap();
        hooks.push(cfg);
        save_webhooks_to_file(&hooks);
        log::info!("Webhook cadastrado e persistido! 🚨💾");
    }
    pub fn remove_webhook(id: &str) {
        let mut hooks = WEBHOOKS.lock().unwrap();
        hooks.retain(|w| w.id != id);
        save_webhooks_to_file(&hooks);
        log::info!("Webhook removido e persistência atualizada! 🚨🗑️");
    }
    pub async fn trigger_event(event_type: &str, payload: &str) {
        let hooks = WEBHOOKS.lock().unwrap().clone();
        let client = reqwest::Client::new();
        for hook in hooks.into_iter().filter(|h| h.enabled && h.event_type == event_type) {
            let url = hook.url.clone();
            let payload = payload.to_string();
            let client = client.clone();
            // Disparo assíncrono
            actix_web::rt::spawn(async move {
                let res = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(payload.clone())
                    .send()
                    .await;
                match res {
                    Ok(resp) if resp.status().is_success() => {
                        log::info!("🚀 Webhook enviado com sucesso para {}!", url);
                    }
                    Ok(resp) => {
                        log::warn!("⚠️ Webhook para {} respondeu com status {}", url, resp.status());
                    }
                    Err(e) => {
                        log::error!("❌ Falha ao enviar webhook para {}: {}", url, e);
                    }
                }
            });
        }
    }
    pub fn list_webhooks() -> Vec<WebhookConfig> {
        WEBHOOKS.lock().unwrap().clone()
    }
}
