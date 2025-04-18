use crate::errors::ApiError;
use crate::models::login_location::LoginLocation;
use crate::repositories::login_location_repository::LoginLocationRepository;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};
use haversine::Units;
use std::collections::HashMap;
use uuid::Uuid;
use chrono;
use r2d2_sqlite::SqliteConnectionManager;
use r2d2::Pool;
use std::path::Path;

/// Estrutura para analisar riscos baseados em localização geográfica
pub struct LocationRiskAnalyzer {
    pub velocity_threshold_km_h: f64,
    pub risk_threshold_distance_km: u32,
    pub max_accuracy_radius_km: u32,
}

impl Default for LocationRiskAnalyzer {
    fn default() -> Self {
        Self {
            velocity_threshold_km_h: 800.0, // Velocidade máxima plausível em km/h
            risk_threshold_distance_km: 2000, // Distância em km que representa mudança significativa
            max_accuracy_radius_km: 200, // Precisão máxima confiável para análise de localização
        }
    }
}

impl LocationRiskAnalyzer {
    /// Inicializa o banco de dados GeoIP
    pub fn init_geoip_db(db_path: &str) -> Result<(), ApiError> {
        // Verifica se o arquivo existe
        if !Path::new(db_path).exists() {
            warn!("⚠️ Banco de dados GeoIP não encontrado: {}", db_path);
            return Err(ApiError::InternalServerError(format!(
                "Banco de dados GeoIP não encontrado: {}",
                db_path
            )));
        }
        
        // Em uma implementação real, carregaríamos o banco de dados MaxMind aqui
        info!("🌎 Banco de dados GeoIP inicializado com sucesso: {}", db_path);
        Ok(())
    }

    /// Analisa o risco com base na localização atual do IP e nos dados históricos
    pub fn analyze(&self, pool: &Arc<Pool<SqliteConnectionManager>>, user_id: &str, ip_str: &str) -> Result<LoginLocation, ApiError> {
        debug!("🔍 Analisando risco para IP: {} do usuário {}", ip_str, user_id);
        
        // Converter string IP para IpAddr
        let ip = match IpAddr::from_str(ip_str) {
            Ok(addr) => addr,
            Err(e) => {
                warn!("⚠️ IP inválido fornecido: {}: {}", ip_str, e);
                let mut errors = HashMap::new();
                errors.insert("ip".to_string(), vec![format!("IP inválido: {}", e)]);
                return Err(ApiError::ValidationError(errors));
            }
        };
        
        // Buscar última localização do usuário
        let latest_location = LoginLocationRepository::find_latest(pool, user_id)?;
        
        // Em uma implementação real, consultaríamos um serviço de GeoIP aqui
        // Por agora, simulamos alguns dados de localização
        let country = "BR";
        let city_name = "São Paulo";
        let latitude = -23.5505;
        let longitude = -46.6333;
        let accuracy_radius = 10;
        
        debug!("📍 Localização detectada: {}, {}", city_name, country);
        
        // Converte string de user_id para UUID
        let user_uuid = match Uuid::parse_str(user_id) {
            Ok(uuid) => uuid,
            Err(e) => {
                warn!("⚠️ UUID inválido para user_id: {}: {}", user_id, e);
                let mut errors = HashMap::new();
                errors.insert("user_id".to_string(), vec![format!("User ID inválido: {}", e)]);
                return Err(ApiError::ValidationError(errors));
            }
        };
        
        // Cria o objeto de localização padrão
        let mut login_location = LoginLocation {
            id: Uuid::new_v4().to_string(),
            user_id: user_uuid.to_string(),
            ip_address: ip.to_string(),
            country_code: Some(country.to_string()),
            city: Some(city_name.to_string()),
            latitude: Some(latitude),
            longitude: Some(longitude),
            accuracy_radius: Some(accuracy_radius as i32),
            created_at: chrono::Utc::now(),
            risk_score: Some(0.0),
            is_suspicious: false,
            suspicious_reason: None,
        };
        
        // Se não houver localização anterior, salva e retorna a localização atual sem análise adicional
        let latest = match latest_location {
            Some(loc) => loc,
            None => {
                debug!("🆕 Primeira localização para este usuário");
                LoginLocationRepository::save(pool, &login_location)?;
                return Ok(login_location);
            }
        };
        
        // Análise de risco baseada em distância e tempo
        let mut risk_factors = Vec::new();
        let mut total_risk_score = 0.0;
        
        // 1. Verifique o raio de precisão - localizações muito imprecisas podem ser suspeitas
        if let Some(radius) = login_location.accuracy_radius {
            if (radius as u32) > self.max_accuracy_radius_km {
                risk_factors.push(format!("Localização imprecisa (raio de {}km)", radius));
                total_risk_score += 10.0;
            }
        }
        
        // 2. Cálculo da distância usando haversine
        if let (Some(lat1), Some(lon1), Some(lat2), Some(lon2)) = (latest.latitude, latest.longitude, login_location.latitude, login_location.longitude) {
            let point1 = haversine::Location { latitude: lat1, longitude: lon1 };
            let point2 = haversine::Location { latitude: lat2, longitude: lon2 };
            let distance_km = haversine::distance(point1, point2, Units::Kilometers);
            
            debug!("📏 Distância da última localização: {:.2}km", distance_km);
            
            // 3. Cálculo do tempo desde o último login
            let duration_since_last = login_location.created_at - latest.created_at;
            let hours_since_last = duration_since_last.num_hours() as f64 
                + (duration_since_last.num_minutes() % 60) as f64 / 60.0;
            
            debug!("⏱️ Tempo desde o último login: {:.2} horas", hours_since_last);
            
            // 4. Velocidade (km/h) = distância (km) / tempo (h)
            let velocity = if hours_since_last > 0.0 {
                distance_km / hours_since_last
            } else {
                // Evita divisão por zero
                f64::MAX
            };
            
            debug!("🚀 Velocidade calculada: {:.2} km/h", velocity);
            
            // 5. Análise de risco baseada na velocidade
            if velocity > self.velocity_threshold_km_h && distance_km > self.risk_threshold_distance_km as f64 {
                risk_factors.push(format!(
                    "Velocidade improvável ({:.2} km/h, distância de {:.2} km)",
                    velocity, distance_km
                ));
                
                // Ajuste o score de risco com base na velocidade
                let velocity_risk = (velocity / self.velocity_threshold_km_h).min(100.0);
                total_risk_score += velocity_risk;
                
                // Se a velocidade for extremamente alta, marque como suspeito
                if velocity > self.velocity_threshold_km_h * 2.0 {
                    login_location.is_suspicious = true;
                }
            }
            
            // 6. Verificação do país
            if latest.country_code != login_location.country_code {
                risk_factors.push(format!(
                    "Mudança de país (de {:?} para {:?})",
                    latest.country_code, login_location.country_code
                ));
                total_risk_score += 25.0;
            }
        }
        
        // 7. Atualiza as informações de risco
        login_location.risk_score = Some(total_risk_score);
        
        // 8. Se o score for muito alto, marque como suspeito
        if total_risk_score > 50.0 && !login_location.is_suspicious {
            login_location.is_suspicious = true;
        }
        
        // 9. Se for suspeito, adicione os motivos
        if login_location.is_suspicious && !risk_factors.is_empty() {
            login_location.suspicious_reason = Some(risk_factors.join("; "));
        }
        
        debug!(
            "🔒 Análise concluída: score de risco {:?}, suspeito: {}",
            login_location.risk_score, login_location.is_suspicious
        );
        
        // Salva a localização no banco de dados
        LoginLocationRepository::save(pool, &login_location)?;
        
        Ok(login_location)
    }
} 