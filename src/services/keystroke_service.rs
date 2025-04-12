use crate::errors::ApiError;
use crate::models::user::User;
use crate::models::keystroke_dynamics::{KeystrokeStatusResponse, KeystrokeVerificationResponse};
use crate::db::DbPool;
use chrono::Utc;
use tracing::info;

pub struct KeystrokeService;

impl KeystrokeService {
    /// Registra um novo padrão de digitação para o usuário
    pub fn register_pattern(
        pool: &DbPool,
        user_id: &str,
        typing_pattern: Vec<u32>,
        similarity_threshold: u8,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Verificar se já existe um padrão registrado
        let pattern_exists: bool = conn.query_row(
            "SELECT 1 FROM keystroke_dynamics WHERE user_id = ?1 LIMIT 1",
            [user_id],
            |_| Ok(true),
        ).unwrap_or(false);
        
        let pattern_json = serde_json::to_string(&typing_pattern)
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao serializar padrão de digitação: {}", e)))?;
        
        if pattern_exists {
            // Atualizar o padrão existente
            conn.execute(
                "UPDATE keystroke_dynamics SET typing_pattern = ?1, similarity_threshold = ?2, updated_at = ?3 WHERE user_id = ?4",
                (&pattern_json, similarity_threshold, Utc::now(), user_id),
            )?;
            
            info!("🔄 Padrão de digitação atualizado para o usuário ID: {}", user_id);
        } else {
            // Inserir novo padrão
            conn.execute(
                "INSERT INTO keystroke_dynamics (id, user_id, typing_pattern, similarity_threshold, enabled, created_at, updated_at) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                (
                    uuid::Uuid::new_v4().to_string(),
                    user_id,
                    &pattern_json,
                    similarity_threshold,
                    true, // Habilitado por padrão ao registrar
                    Utc::now(),
                    Utc::now(),
                ),
            )?;
            
            info!("✅ Padrão de digitação registrado para o usuário ID: {}", user_id);
        }
        
        Ok(())
    }
    
    /// Habilita ou desabilita a verificação de ritmo de digitação
    pub fn toggle_keystroke_verification(
        pool: &DbPool,
        user_id: &str,
        enabled: bool,
    ) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Verificar se existe um padrão registrado
        let pattern_exists: bool = conn.query_row(
            "SELECT 1 FROM keystroke_dynamics WHERE user_id = ?1 LIMIT 1",
            [user_id],
            |_| Ok(true),
        ).unwrap_or(false);
        
        if !pattern_exists {
            return Err(ApiError::BadRequestError("Nenhum padrão de digitação registrado para este usuário".to_string()));
        }
        
        // Atualizar o status
        conn.execute(
            "UPDATE keystroke_dynamics SET enabled = ?1, updated_at = ?2 WHERE user_id = ?3",
            (enabled, Utc::now(), user_id),
        )?;
        
        let status = if enabled { "habilitada" } else { "desabilitada" };
        info!("🔄 Verificação de ritmo de digitação {} para o usuário ID: {}", status, user_id);
        
        Ok(())
    }
    
    /// Obtém o status da verificação de ritmo de digitação
    pub fn get_keystroke_status(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<KeystrokeStatusResponse, ApiError> {
        let conn = pool.get()?;
        
        // Tentar obter as configurações
        let result = conn.query_row(
            "SELECT enabled, similarity_threshold FROM keystroke_dynamics WHERE user_id = ?1",
            [user_id],
            |row| {
                Ok(KeystrokeStatusResponse {
                    enabled: row.get(0)?,
                    similarity_threshold: row.get(1)?,
                    pattern_registered: true,
                })
            },
        );
        
        match result {
            Ok(status) => Ok(status),
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Nenhum padrão registrado
                Ok(KeystrokeStatusResponse {
                    enabled: false,
                    similarity_threshold: 80, // Valor padrão
                    pattern_registered: false,
                })
            },
            Err(e) => Err(ApiError::DatabaseError(e.to_string())),
        }
    }
    
    /// Verifica o padrão de digitação durante o login
    pub fn verify_keystroke_pattern(
        pool: &DbPool,
        user_id: &str,
        current_pattern: Vec<u32>,
    ) -> Result<KeystrokeVerificationResponse, ApiError> {
        let conn = pool.get()?;
        
        // Obter o padrão armazenado e configurações
        let result = conn.query_row(
            "SELECT typing_pattern, similarity_threshold, enabled FROM keystroke_dynamics WHERE user_id = ?1",
            [user_id],
            |row| {
                let pattern_json: String = row.get(0)?;
                let threshold: u8 = row.get(1)?;
                let enabled: bool = row.get(2)?;
                
                let stored_pattern: Vec<u32> = serde_json::from_str(&pattern_json)
                    .map_err(|e| rusqlite::Error::InvalidParameterName(format!("Erro ao deserializar padrão: {}", e)))?;
                
                Ok((stored_pattern, threshold, enabled))
            },
        );
        
        match result {
            Ok((stored_pattern, threshold, enabled)) => {
                if !enabled {
                    // Verificação desabilitada, sempre aceita
                    return Ok(KeystrokeVerificationResponse {
                        accepted: true,
                        similarity_percentage: 100.0,
                        threshold,
                        message: "Verificação de ritmo de digitação desabilitada".to_string(),
                    });
                }
                
                // Calcular a similaridade entre os padrões
                let similarity = Self::calculate_pattern_similarity(&stored_pattern, &current_pattern);
                let similarity_percentage = similarity * 100.0;
                let accepted = similarity_percentage >= threshold as f32;
                
                let message = if accepted {
                    format!("Padrão de digitação aceito com {}% de similaridade", similarity_percentage.round())
                } else {
                    format!("Padrão de digitação rejeitado. Similaridade: {}%, Limiar: {}%", 
                            similarity_percentage.round(), threshold)
                };
                
                info!("🔐 Verificação de ritmo de digitação para usuário ID {}: {}% (limiar: {}%)", 
                      user_id, similarity_percentage.round(), threshold);
                
                Ok(KeystrokeVerificationResponse {
                    accepted,
                    similarity_percentage,
                    threshold,
                    message,
                })
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                // Nenhum padrão registrado, aceita por padrão
                Ok(KeystrokeVerificationResponse {
                    accepted: true,
                    similarity_percentage: 100.0,
                    threshold: 80, // Valor padrão
                    message: "Nenhum padrão de digitação registrado".to_string(),
                })
            },
            Err(e) => Err(ApiError::DatabaseError(e.to_string())),
        }
    }
    
    /// Calcula a similaridade entre dois padrões de digitação
    /// Retorna um valor entre 0.0 e 1.0 (0% a 100%)
    fn calculate_pattern_similarity(stored_pattern: &[u32], current_pattern: &[u32]) -> f32 {
        // Se os tamanhos forem muito diferentes, a similaridade é baixa
        if (stored_pattern.len() as i32 - current_pattern.len() as i32).abs() > 2 {
            return 0.5; // 50% de similaridade base
        }
        
        // Normalizar os padrões para lidar com diferenças de velocidade geral
        let normalized_stored = Self::normalize_pattern(stored_pattern);
        let normalized_current = Self::normalize_pattern(current_pattern);
        
        // Usar o menor tamanho para comparação
        let min_len = normalized_stored.len().min(normalized_current.len());
        
        // Calcular a diferença média normalizada
        let mut total_diff = 0.0;
        for i in 0..min_len {
            let diff = (normalized_stored[i] - normalized_current[i]).abs();
            total_diff += diff;
        }
        
        let avg_diff = if min_len > 0 { total_diff / min_len as f32 } else { 1.0 };
        
        // Converter a diferença em similaridade (0.0 = totalmente diferente, 1.0 = idêntico)
        let similarity = 1.0 - (avg_diff.min(1.0));
        
        // Aplicar uma função sigmoide para aumentar a precisão
        // Isso torna a função mais sensível a pequenas diferenças no meio da escala
        let adjusted_similarity = 1.0 / (1.0 + (-10.0 * (similarity - 0.5)).exp());
        
        adjusted_similarity
    }
    
    /// Normaliza um padrão de digitação para valores entre 0.0 e 1.0
    fn normalize_pattern(pattern: &[u32]) -> Vec<f32> {
        if pattern.is_empty() {
            return Vec::new();
        }
        
        // Encontrar o valor máximo
        let max_value = *pattern.iter().max().unwrap_or(&1) as f32;
        
        // Normalizar cada valor
        pattern.iter()
            .map(|&value| value as f32 / max_value)
            .collect()
    }
}
