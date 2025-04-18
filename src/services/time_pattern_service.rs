use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::time_pattern::{TimeAnomaly, TimeAnomalyType, TimePatternSummary, UserTimePattern};
use crate::repositories::time_pattern_repository::TimePatternRepository;
use chrono::{DateTime, Datelike, Duration, NaiveTime, TimeZone, Timelike, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Serviço para análise de padrões temporais de login
pub struct TimePatternAnalyzer {
    /// Limiar de coincidência de hora (em horas) para considerar um login anômalo
    hour_threshold: f64,
    
    /// Número mínimo de logins registrados antes de começar a analisar anomalias
    min_logins_threshold: u32,
}

impl Default for TimePatternAnalyzer {
    fn default() -> Self {
        Self {
            hour_threshold: 3.0,        // Considerar anômalo se o login for feito mais de 3 horas fora do horário típico
            min_logins_threshold: 5,    // Começar a analisar após 5 logins registrados
        }
    }
}

impl TimePatternAnalyzer {
    /// Cria uma nova instância com parâmetros personalizados
    pub fn new(hour_threshold: f64, min_logins_threshold: u32) -> Self {
        Self {
            hour_threshold,
            min_logins_threshold,
        }
    }
    
    /// Registra um novo login e atualiza o padrão temporal
    pub fn register_login(
        &self,
        pool: &DbPool,
        user_id: &str,
        login_time: DateTime<Utc>,
        timezone: Option<String>,
    ) -> Result<UserTimePattern, ApiError> {
        debug!("📊 Registrando login para análise temporal: usuário {}", user_id);
        
        // Atualizar padrão com novo login
        let updated_pattern = TimePatternRepository::update_with_login(
            pool,
            user_id,
            login_time,
            timezone,
        )?;
        
        info!("✅ Padrão temporal atualizado para usuário {}", user_id);
        Ok(updated_pattern)
    }
    
    /// Analisa um login para detectar anomalias temporais
    pub fn analyze_login(
        &self,
        pool: &DbPool,
        user_id: &str,
        login_time: DateTime<Utc>,
        timezone: Option<String>,
    ) -> Result<Vec<TimeAnomaly>, ApiError> {
        debug!("🔍 Analisando padrão temporal para login: usuário {}", user_id);
        
        // Buscar padrão existente
        let pattern_opt = TimePatternRepository::find_by_user_id(pool, user_id)?;
        
        // Se não houver padrão ou poucos logins, registrar e retornar sem anomalias
        let pattern = match pattern_opt {
            Some(p) if p.total_logins >= self.min_logins_threshold => p,
            _ => {
                // Registrar o login, mas não analisar ainda
                let _ = self.register_login(pool, user_id, login_time, timezone)?;
                debug!("ℹ️ Poucos logins para análise temporal precisa para {}", user_id);
                return Ok(Vec::new()); // Retorna lista vazia (sem anomalias)
            }
        };
        
        // Lista de anomalias detectadas
        let mut anomalies = Vec::new();
        
        // 1. Verificar anomalia de hora do dia
        if let Some(ref avg_time) = pattern.average_login_time {
            let login_hour = login_time.hour() as u32;
            let avg_hour = avg_time.hour();
            
            // Calcular diferença de horas (considerando ciclo de 24h)
            let hour_diff = if login_hour >= avg_hour {
                login_hour - avg_hour
            } else {
                24 - avg_hour + login_hour
            };
            
            if hour_diff as f64 > self.hour_threshold {
                anomalies.push(TimeAnomaly {
                    anomaly_type: TimeAnomalyType::UnusualHour,
                    risk_level: (hour_diff as f64 / 12.0).min(1.0), // Normalizar para 0-1
                    description: format!("Login em horário incomum 🕒"),
                    login_time,
                    expected_value: Some(format!("~{:02}:00", avg_hour)),
                    detected_value: format!("{:02}:00", login_hour),
                });
                
                debug!("⚠️ Anomalia de horário detectada para {}: {}h vs típico {}h", 
                    user_id, login_hour, avg_hour);
            }
        }
        
        // 2. Verificar anomalia de dia da semana
        let weekday_num = match login_time.weekday() {
            chrono::Weekday::Mon => 0,
            chrono::Weekday::Tue => 1,
            chrono::Weekday::Wed => 2,
            chrono::Weekday::Thu => 3,
            chrono::Weekday::Fri => 4,
            chrono::Weekday::Sat => 5,
            chrono::Weekday::Sun => 6,
        };
        
        // Verificar se este dia da semana tem baixa frequência
        let day_frequency = pattern.weekday_frequency.get(&(weekday_num as u8)).unwrap_or(&0);
        let total_weekdays_with_logins = pattern.weekday_frequency.len();
        
        if *day_frequency == 0 && total_weekdays_with_logins >= 3 {
            // Nunca logou neste dia e já tem registro em pelo menos 3 outros dias
            let weekday_name = match weekday_num {
                0 => "Segunda-feira",
                1 => "Terça-feira",
                2 => "Quarta-feira",
                3 => "Quinta-feira",
                4 => "Sexta-feira",
                5 => "Sábado",
                6 => "Domingo",
                _ => "Desconhecido",
            };
            
            anomalies.push(TimeAnomaly {
                anomaly_type: TimeAnomalyType::UnusualWeekday,
                risk_level: 0.7, // Risco alto, mas não máximo
                description: format!("Login em dia da semana incomum 📅"),
                login_time,
                expected_value: None,
                detected_value: weekday_name.to_string(),
            });
            
            debug!("⚠️ Anomalia de dia da semana detectada para {}: {}", 
                user_id, weekday_name);
        }
        
        // 3. Verificar anomalia de fuso horário
        if let (Some(ref typical_tz), Some(ref login_tz)) = (pattern.typical_timezone, timezone.clone()) {
            if typical_tz != login_tz {
                anomalies.push(TimeAnomaly {
                    anomaly_type: TimeAnomalyType::TimezoneChange,
                    risk_level: 0.8, // Risco alto
                    description: format!("Login de fuso horário diferente do usual 🌐"),
                    login_time,
                    expected_value: Some(typical_tz.clone()),
                    detected_value: login_tz.clone(),
                });
                
                debug!("⚠️ Anomalia de fuso horário detectada para {}: {} vs típico {}", 
                    user_id, login_tz, typical_tz);
            }
        }
        
        // Registrar o login para atualizar o padrão, independente de anomalias
        let _ = self.register_login(pool, user_id, login_time, timezone)?;
        
        // Registrar no log o resultado da análise
        if anomalies.is_empty() {
            debug!("✅ Nenhuma anomalia temporal detectada para {}", user_id);
        } else {
            info!("⚠️ {} anomalias temporais detectadas para {}", anomalies.len(), user_id);
        }
        
        Ok(anomalies)
    }
    
    /// Obtém o resumo do padrão temporal de um usuário
    pub fn get_pattern_summary(&self, pool: &DbPool, user_id: &str) -> Result<Option<TimePatternSummary>, ApiError> {
        // Buscar padrão existente
        let pattern_opt = TimePatternRepository::find_by_user_id(pool, user_id)?;
        
        match pattern_opt {
            Some(pattern) => {
                let summary = TimePatternRepository::to_summary(&pattern);
                Ok(Some(summary))
            },
            None => Ok(None),
        }
    }
    
    /// Verifica se é possível que o mesmo usuário tenha logado em duas localizações
    /// dentro do intervalo de tempo dado, considerando a distância entre os pontos
    pub fn check_impossible_travel(
        &self,
        time_diff_hours: f64,
        distance_km: f64,
        max_speed_km_h: f64,
    ) -> Option<TimeAnomaly> {
        // Tempo mínimo necessário para percorrer a distância na velocidade máxima
        let min_time_needed = distance_km / max_speed_km_h;
        
        // Se o tempo real for menor que o tempo mínimo necessário, é um padrão impossível
        if time_diff_hours < min_time_needed {
            let now = Utc::now();
            
            Some(TimeAnomaly {
                anomaly_type: TimeAnomalyType::ImpossibleTravelTime,
                risk_level: 0.95, // Risco muito alto
                description: format!("Deslocamento fisicamente impossível detectado 🚨"),
                login_time: now,
                expected_value: Some(format!("Mínimo de {:.1}h para esta distância", min_time_needed)),
                detected_value: format!("{:.1}h", time_diff_hours),
            })
        } else {
            None
        }
    }
    
    /// Limpa padrões temporais antigos ou inativos
    pub fn clean_old_patterns(&self, pool: &DbPool, older_than_days: u32) -> Result<u32, ApiError> {
        let conn = pool.get()?;
        let cutoff_timestamp = (Utc::now() - Duration::days(older_than_days as i64)).timestamp();
        
        let deleted = conn.execute(
            "DELETE FROM user_time_patterns WHERE updated_at < ?1",
            &[&cutoff_timestamp],
        )?;
        
        info!("🧹 {} padrões temporais antigos removidos (mais de {} dias)", deleted, older_than_days);
        Ok(deleted as u32)
    }
} 