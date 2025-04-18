use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Modelo para localizações de login dos usuários
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginLocation {
    pub id: String,
    pub user_id: String,
    pub ip_address: String,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub accuracy_radius: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub risk_score: Option<f64>,
    pub is_suspicious: bool,
    pub suspicious_reason: Option<String>,
}

impl LoginLocation {
    /// Cria um novo registro de localização de login
    pub fn new(
        user_id: String,
        ip_address: String,
        country_code: Option<String>,
        city: Option<String>,
        latitude: Option<f64>,
        longitude: Option<f64>,
        accuracy_radius: Option<i32>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            ip_address,
            country_code,
            city,
            latitude,
            longitude,
            accuracy_radius,
            created_at: Utc::now(),
            risk_score: None,
            is_suspicious: false,
            suspicious_reason: None,
        }
    }

    /// Marca a localização como suspeita
    pub fn mark_as_suspicious(&mut self, risk_score: f64, reason: &str) {
        self.risk_score = Some(risk_score);
        self.is_suspicious = true;
        self.suspicious_reason = Some(reason.to_string());
    }
}

/// Informações resumidas sobre a localização para respostas da API
#[derive(Debug, Serialize)]
pub struct LocationSummary {
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub is_suspicious: bool,
    pub suspicious_reason: Option<String>,
    pub login_time: DateTime<Utc>,
}

impl From<&LoginLocation> for LocationSummary {
    fn from(location: &LoginLocation) -> Self {
        Self {
            country_code: location.country_code.clone(),
            city: location.city.clone(),
            is_suspicious: location.is_suspicious,
            suspicious_reason: location.suspicious_reason.clone(),
            login_time: location.created_at,
        }
    }
}

/// Resposta para uma lista de localizações de login
#[derive(Debug, Serialize)]
pub struct LocationListResponse {
    pub locations: Vec<LocationSummary>,
    pub total_count: usize,
    pub suspicious_count: usize,
} 