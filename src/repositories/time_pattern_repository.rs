use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::time_pattern::{UserTimePattern, TimePatternSummary};
use chrono::{DateTime, Utc, Timelike, Datelike, NaiveTime};
use std::collections::HashMap;
use rusqlite::params;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Repositório para operações com padrões temporais de login
pub struct TimePatternRepository;

impl TimePatternRepository {
    /// Salva ou atualiza um padrão de tempo para um usuário
    pub fn save(pool: &DbPool, pattern: &UserTimePattern) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Verificar se já existe um padrão para o usuário
        let exists = conn.query_row(
            "SELECT COUNT(*) FROM user_time_patterns WHERE user_id = ?1",
            params![pattern.user_id],
            |row| row.get::<_, i64>(0)
        ).map_err(|e| {
            error!("❌ Erro ao verificar padrão temporal existente: {}", e);
            ApiError::DatabaseError(e.to_string())
        })? > 0;

        if exists {
            // Serializar os HashMaps
            let hour_freq = serde_json::to_string(&pattern.hour_frequency)
                .map_err(|e| ApiError::SerializationError(e.to_string()))?;
            let weekday_freq = serde_json::to_string(&pattern.weekday_frequency)
                .map_err(|e| ApiError::SerializationError(e.to_string()))?;
            
            // Atualizar registro existente
            conn.execute(
                "UPDATE user_time_patterns SET 
                hour_frequency = ?1, 
                weekday_frequency = ?2, 
                last_typical_login = ?3, 
                total_logins = ?4, 
                average_login_time = ?5,
                typical_timezone = ?6,
                updated_at = ?7 
                WHERE user_id = ?8",
                params![
                    hour_freq,
                    weekday_freq,
                    pattern.last_typical_login.map(|dt| dt.timestamp()),
                    pattern.total_logins,
                    pattern.average_login_time.map(|t| t.format("%H:%M").to_string()),
                    pattern.typical_timezone,
                    Utc::now(),
                    pattern.user_id
                ],
            )?;
            
            debug!("✅ Padrão temporal atualizado para o usuário: {}", pattern.user_id);
        } else {
            // Serializar os HashMaps
            let hour_freq = serde_json::to_string(&pattern.hour_frequency)
                .map_err(|e| ApiError::SerializationError(e.to_string()))?;
            let weekday_freq = serde_json::to_string(&pattern.weekday_frequency)
                .map_err(|e| ApiError::SerializationError(e.to_string()))?;
            
            // Inserir novo registro
            conn.execute(
                "INSERT INTO user_time_patterns (
                id, user_id, hour_frequency, weekday_frequency, 
                last_typical_login, total_logins, average_login_time, 
                typical_timezone, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    pattern.id,
                    pattern.user_id,
                    hour_freq,
                    weekday_freq,
                    pattern.last_typical_login.map(|dt| dt.timestamp()),
                    pattern.total_logins,
                    pattern.average_login_time.map(|t| t.format("%H:%M").to_string()),
                    pattern.typical_timezone,
                    Utc::now().timestamp(),
                    Utc::now().timestamp()
                ],
            )?;
            
            info!("🆕 Novo padrão temporal criado para o usuário: {}", pattern.user_id);
        }
        
        Ok(())
    }
    
    /// Busca o padrão de tempo de um usuário específico
    pub fn find_by_user_id(pool: &DbPool, user_id: &str) -> Result<Option<UserTimePattern>, ApiError> {
        let conn = pool.get()?;
        
        let result = conn.query_row(
            "SELECT id, user_id, hour_frequency, weekday_frequency, 
            last_typical_login, total_logins, average_login_time, 
            typical_timezone, created_at, updated_at
            FROM user_time_patterns WHERE user_id = ?1",
            params![user_id],
            |row| {
                // Deserializar HashMaps de JSON
                let hour_freq_json: String = row.get(2)?;
                let weekday_freq_json: String = row.get(3)?;
                
                let hour_frequency: HashMap<u8, u32> = serde_json::from_str(&hour_freq_json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, 
                        rusqlite::types::Type::Text, Box::new(e)))?;
                
                let weekday_frequency: HashMap<u8, u32> = serde_json::from_str(&weekday_freq_json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, 
                        rusqlite::types::Type::Text, Box::new(e)))?;
                
                // Converter timestamps para DateTime
                let last_login: Option<i64> = row.get(4)?;
                let created_ts: i64 = row.get(8)?;
                let updated_ts: i64 = row.get(9)?;
                
                // Converter string de tempo médio para NaiveTime
                let avg_time_str: Option<String> = row.get(6)?;
                let avg_time = match avg_time_str {
                    Some(time_str) => {
                        let parts: Vec<&str> = time_str.split(':').collect();
                        if parts.len() == 2 {
                            let hour: u32 = parts[0].parse().unwrap_or(0);
                            let min: u32 = parts[1].parse().unwrap_or(0);
                            Some(NaiveTime::from_hms_opt(hour, min, 0).unwrap_or_else(|| NaiveTime::from_hms_opt(0, 0, 0).unwrap()))
                        } else {
                            None
                        }
                    },
                    None => None
                };

                Ok(UserTimePattern {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    hour_frequency,
                    weekday_frequency,
                    last_typical_login: last_login.map(|ts| DateTime::from_timestamp(ts, 0).unwrap_or(Utc::now())),
                    total_logins: row.get(5)?,
                    average_login_time: avg_time,
                    typical_timezone: row.get(7)?,
                    created_at: DateTime::from_timestamp(created_ts, 0).unwrap_or(Utc::now()),
                    updated_at: DateTime::from_timestamp(updated_ts, 0).unwrap_or(Utc::now()),
                })
            },
        );
        
        match result {
            Ok(pattern) => {
                debug!("📊 Padrão temporal encontrado para o usuário: {}", user_id);
                Ok(Some(pattern))
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                debug!("🔍 Nenhum padrão temporal encontrado para o usuário: {}", user_id);
                Ok(None)
            },
            Err(e) => {
                error!("❌ Erro ao buscar padrão temporal: {}", e);
                Err(ApiError::DatabaseError(e.to_string()))
            }
        }
    }
    
    /// Cria um novo padrão temporal para um usuário 
    pub fn create_new_pattern(user_id: &str) -> UserTimePattern {
        UserTimePattern {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            hour_frequency: HashMap::new(),
            weekday_frequency: HashMap::new(),
            last_typical_login: None,
            total_logins: 0,
            average_login_time: None,
            typical_timezone: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    /// Atualiza o padrão com um novo login
    pub fn update_with_login(
        pool: &DbPool, 
        user_id: &str, 
        login_time: DateTime<Utc>, 
        timezone: Option<String>
    ) -> Result<UserTimePattern, ApiError> {
        // Buscar padrão existente ou criar novo
        let mut pattern = Self::find_by_user_id(pool, user_id)?
            .unwrap_or_else(|| Self::create_new_pattern(user_id));
        
        // Incrementar o contador de logins
        pattern.total_logins += 1;
        
        // Atualizar frequência por hora
        let hour = login_time.hour() as u8;
        *pattern.hour_frequency.entry(hour).or_insert(0) += 1;
        
        // Atualizar frequência por dia da semana (0 = Segunda, 6 = Domingo)
        let weekday = match login_time.weekday() {
            chrono::Weekday::Mon => 0,
            chrono::Weekday::Tue => 1,
            chrono::Weekday::Wed => 2,
            chrono::Weekday::Thu => 3,
            chrono::Weekday::Fri => 4,
            chrono::Weekday::Sat => 5,
            chrono::Weekday::Sun => 6,
        };
        *pattern.weekday_frequency.entry(weekday).or_insert(0) += 1;
        
        // Definir último login típico
        pattern.last_typical_login = Some(login_time);
        
        // Atualizar fuso horário típico
        if let Some(tz) = timezone {
            pattern.typical_timezone = Some(tz);
        }
        
        // Calcular horário médio de login
        if pattern.total_logins > 0 && !pattern.hour_frequency.is_empty() {
            // Encontrar a hora mais comum
            let most_common_hour = pattern.hour_frequency.iter()
                .max_by_key(|(_, &count)| count)
                .map(|(&hour, _)| hour)
                .unwrap_or(9); // Padrão para 9h da manhã se não houver dados
            
            pattern.average_login_time = Some(NaiveTime::from_hms_opt(most_common_hour as u32, 0, 0)
                .unwrap_or_else(|| NaiveTime::from_hms_opt(0, 0, 0).unwrap()));
        }
        
        // Salvar o padrão atualizado
        Self::save(pool, &pattern)?;
        
        Ok(pattern)
    }
    
    /// Converte um padrão temporal em um resumo para resposta da API
    pub fn to_summary(pattern: &UserTimePattern) -> TimePatternSummary {
        // Encontrar as horas mais comuns
        let common_time = pattern.average_login_time
            .map(|t| t.format("%H:%M").to_string());
        
        // Encontrar os dias mais comuns
        let mut common_days = Vec::new();
        if !pattern.weekday_frequency.is_empty() {
            // Calcular a média de logins por dia
            let total_days = pattern.weekday_frequency.len() as u32;
            let avg_logins_per_day = if total_days > 0 {
                pattern.total_logins / total_days
            } else {
                0
            };
            
            // Dias com frequência acima da média
            for (&day, &count) in &pattern.weekday_frequency {
                if count >= avg_logins_per_day {
                    let day_name = match day {
                        0 => "Segunda-feira",
                        1 => "Terça-feira",
                        2 => "Quarta-feira",
                        3 => "Quinta-feira",
                        4 => "Sexta-feira",
                        5 => "Sábado",
                        6 => "Domingo",
                        _ => "Desconhecido",
                    };
                    common_days.push(day_name.to_string());
                }
            }
        }
        
        TimePatternSummary {
            common_login_time: common_time,
            common_days,
            typical_timezone: pattern.typical_timezone.clone(),
            total_logins: pattern.total_logins,
            last_typical_login: pattern.last_typical_login,
        }
    }
} 