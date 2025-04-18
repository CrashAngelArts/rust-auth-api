use chrono::{DateTime, Utc, Weekday, NaiveTime};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Modelo para armazenar os padrões de horário de login dos usuários
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTimePattern {
    /// ID único do padrão
    pub id: String,
    
    /// ID do usuário
    pub user_id: String,
    
    /// Mapa de frequência por hora do dia (0-23)
    pub hour_frequency: HashMap<u8, u32>,
    
    /// Mapa de frequência por dia da semana (0-6, onde 0 é segunda-feira)
    pub weekday_frequency: HashMap<u8, u32>,
    
    /// Último horário típico de login
    pub last_typical_login: Option<DateTime<Utc>>,
    
    /// Total de logins registrados
    pub total_logins: u32,
    
    /// Horário médio de login (formato HH:MM)
    pub average_login_time: Option<NaiveTime>,
    
    /// Fuso horário típico (formato +/-HH:MM)
    pub typical_timezone: Option<String>,
    
    /// Criado em
    pub created_at: DateTime<Utc>,
    
    /// Atualizado em
    pub updated_at: DateTime<Utc>,
}

/// DTO para anomalias de horário detectadas
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeAnomaly {
    /// Tipo de anomalia detectada
    pub anomaly_type: TimeAnomalyType,
    
    /// Nível de risco (0.0 - 1.0)
    pub risk_level: f64,
    
    /// Descrição da anomalia
    pub description: String,
    
    /// Horário do login anômalo
    pub login_time: DateTime<Utc>,
    
    /// Valor esperado (se aplicável)
    pub expected_value: Option<String>,
    
    /// Valor detectado
    pub detected_value: String,
}

/// Tipos de anomalias temporais
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimeAnomalyType {
    /// Login em horário incomum
    UnusualHour,
    
    /// Login em dia da semana incomum
    UnusualWeekday,
    
    /// Diferença de fuso horário
    TimezoneChange,
    
    /// Padrão de login diferente do usual
    PatternDeviation,
    
    /// Login em horário impossível (ex: dois logins em locais distantes em tempo muito curto)
    ImpossibleTravelTime,
}

/// Resumo de padrão temporal para resposta de API
#[derive(Debug, Serialize, Deserialize)]
pub struct TimePatternSummary {
    /// Horário mais comum de login (formato HH:MM)
    pub common_login_time: Option<String>,
    
    /// Dias da semana mais comuns para login
    pub common_days: Vec<String>,
    
    /// Fuso horário típico
    pub typical_timezone: Option<String>,
    
    /// Total de logins registrados
    pub total_logins: u32,
    
    /// Data do último login típico
    pub last_typical_login: Option<DateTime<Utc>>,
} 