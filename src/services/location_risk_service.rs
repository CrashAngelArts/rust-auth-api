use tracing::{debug, error, info};
use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::login_location::LoginLocation;
use crate::repositories::login_location_repository::LoginLocationRepository;
use chrono::Utc;
use haversine::{self, Units};
use maxminddb::geoip2;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;
use lazy_static::lazy_static;

// Variável global para armazenar o caminho do banco de dados GeoIP
lazy_static! {
    static ref GEOIP_DB_PATH: RwLock<String> = RwLock::new(String::from("data/GeoLite2-City.mmdb"));
}

/// Estrutura para analisar riscos baseados em localização geográfica
pub struct LocationRiskAnalyzer {
    pub velocity_threshold_km_h: f64,
    pub risk_threshold_distance_km: u32,
    pub max_accuracy_radius_km: u32,
}

impl Default for LocationRiskAnalyzer {
    fn default() -> Self {
        Self {
            velocity_threshold_km_h: 900.0, // 900 km/h (velocidade aproximada de avião)
            risk_threshold_distance_km: 100, // Distância mínima para considerar risco
            max_accuracy_radius_km: 200,    // Raio máximo de precisão aceitável
        }
    }
}

// Estrutura simplificada para armazenar informações de geolocalização
#[derive(Debug, Default)]
struct GeoInfo {
    country_code: Option<String>,
    city_name: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    accuracy_radius: Option<i32>,
}

impl LocationRiskAnalyzer {
    /// Inicializa o banco de dados GeoIP
    pub fn init_geoip_db(db_path: &str) -> Result<(), ApiError> {
        match std::fs::metadata(db_path) {
            Ok(_) => {
                info!("📍 Banco de dados GeoIP encontrado em: {}", db_path);
                // Tenta carregar o banco para verificar se é válido
                match maxminddb::Reader::open_readfile(db_path) {
                    Ok(_) => {
                        info!("✅ Banco de dados GeoIP carregado com sucesso!");
                        // Armazena o caminho na variável global
                        if let Ok(mut path) = GEOIP_DB_PATH.write() {
                            *path = db_path.to_string();
                        }
                        Ok(())
                    },
                    Err(e) => {
                        error!("❌ Erro ao carregar banco de dados GeoIP: {}", e);
                        Err(ApiError::InternalServerError(format!("Erro ao carregar banco de dados GeoIP: {}", e)))
                    }
                }
            },
            Err(e) => {
                error!("❌ Banco de dados GeoIP não encontrado em {}: {}", db_path, e);
                Err(ApiError::InternalServerError(format!("Banco de dados GeoIP não encontrado em {}: {}", db_path, e)))
            }
        }
    }

    /// Analisa o risco com base na localização atual do IP e nos dados históricos
    pub fn analyze(&self, pool: &DbPool, user_id: &str, ip_str: &str) -> Result<LoginLocation, ApiError> {
        debug!("🔍 Analisando risco para IP: {} do usuário {}", ip_str, user_id);
        
        // Busca informações de geolocalização do IP
        let geo_info = self.lookup_geoip(ip_str)?;
        
        // 2. Obtém a localização mais recente do usuário
        let latest_location = LoginLocationRepository::find_latest(pool, user_id)?;
        
        // 3. Cria a localização atual para análise
        let mut login_location = LoginLocation {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            ip_address: ip_str.to_string(),
            country_code: geo_info.country_code,
            city: geo_info.city_name,
            latitude: geo_info.latitude,
            longitude: geo_info.longitude,
            accuracy_radius: geo_info.accuracy_radius,
            created_at: Utc::now(),
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
    
    // Busca informações de geolocalização a partir de um IP
    fn lookup_geoip(&self, ip_str: &str) -> Result<GeoInfo, ApiError> {
        // Obtém o caminho do banco de dados GeoIP da variável global
        let geoip_path = match GEOIP_DB_PATH.read() {
            Ok(path) => path.clone(),
            Err(_) => {
                error!("❌ Erro ao acessar caminho do banco de dados GeoIP");
                return Err(ApiError::InternalServerError("Erro ao acessar configuração de geolocalização".to_string()));
            }
        };
        
        // Converte a string de IP para IpAddr
        let ip: IpAddr = match IpAddr::from_str(ip_str) {
            Ok(ip) => ip,
            Err(e) => {
                error!("❌ IP inválido: {} - {}", ip_str, e);
                return Err(ApiError::BadRequest(format!("IP inválido: {}", ip_str)));
            }
        };
        
        // Carrega o banco de dados MaxMind
        let reader = match maxminddb::Reader::open_readfile(&geoip_path) {
            Ok(r) => r,
            Err(e) => {
                error!("❌ Erro ao abrir banco de dados GeoIP: {}", e);
                return Err(ApiError::InternalServerError("Erro ao acessar banco de dados de geolocalização".to_string()));
            }
        };
        
        // Busca informações do IP
        let mut geo_info = GeoInfo::default();
        
        match reader.lookup::<maxminddb::geoip2::City>(ip) {
            Ok(city_option) => {
                if let Some(city) = city_option {
                    // Extrair dados relevantes
                    geo_info.country_code = city.country.as_ref().and_then(|c| c.iso_code.map(|s| s.to_string()));
                    geo_info.city_name = city.city.as_ref().and_then(|c| 
                        c.names.as_ref().and_then(|n| 
                            n.get("pt").or_else(|| n.get("en")).map(|s| s.to_string())
                        )
                    );
                    geo_info.latitude = city.location.as_ref().and_then(|l| l.latitude);
                    geo_info.longitude = city.location.as_ref().and_then(|l| l.longitude);
                    geo_info.accuracy_radius = city.location.as_ref().and_then(|l| l.accuracy_radius.map(|r| r as i32));
                    
                    debug!("📍 Informações de geolocalização encontradas: {:?}", geo_info);
                }
                
                Ok(geo_info)
            },
            Err(e) => {
                error!("❌ Erro ao buscar informações de geolocalização: {}", e);
                Err(ApiError::InternalServerError("Erro ao buscar informações de geolocalização".to_string()))
            }
        }
    }
} 