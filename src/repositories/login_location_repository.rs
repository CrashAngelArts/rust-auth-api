use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::login_location::{LocationListResponse, LocationSummary, LoginLocation};
use rusqlite::params;
use tracing::{debug, error, info};

/// Repositório para operações com a tabela de localizações de login dos usuários
pub struct LoginLocationRepository;

impl LoginLocationRepository {
    /// Salva uma nova localização de login
    pub fn save(pool: &DbPool, location: &LoginLocation) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        conn.execute(
            "INSERT INTO user_login_locations (
                id, user_id, ip_address, country_code, city, 
                latitude, longitude, accuracy_radius, created_at,
                risk_score, is_suspicious, suspicious_reason
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
            )",
            params![
                location.id,
                location.user_id,
                location.ip_address,
                location.country_code,
                location.city,
                location.latitude,
                location.longitude,
                location.accuracy_radius,
                location.created_at,
                location.risk_score,
                location.is_suspicious as i32,
                location.suspicious_reason,
            ],
        )?;

        if location.is_suspicious {
            info!(
                "⚠️ Login suspeito detectado para o usuário {} com IP {}! Motivo: {}",
                location.user_id,
                location.ip_address,
                location.suspicious_reason.as_deref().unwrap_or("desconhecido")
            );
        } else {
            debug!(
                "✅ Localização de login registrada para o usuário {} com IP {}",
                location.user_id, location.ip_address
            );
        }

        Ok(())
    }

    /// Atualiza uma localização de login existente
    pub fn update(pool: &DbPool, location: &LoginLocation) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        conn.execute(
            "UPDATE user_login_locations SET
                risk_score = ?1,
                is_suspicious = ?2,
                suspicious_reason = ?3
            WHERE id = ?4",
            params![
                location.risk_score,
                location.is_suspicious as i32,
                location.suspicious_reason,
                location.id,
            ],
        )?;

        debug!("✅ Localização de login atualizada: {}", location.id);
        Ok(())
    }

    /// Busca uma localização de login por ID
    pub fn find_by_id(pool: &DbPool, id: &str) -> Result<Option<LoginLocation>, ApiError> {
        let conn = pool.get()?;
        
        let result = conn.query_row(
            "SELECT 
                id, user_id, ip_address, country_code, city, 
                latitude, longitude, accuracy_radius, created_at,
                risk_score, is_suspicious, suspicious_reason
            FROM user_login_locations
            WHERE id = ?1",
            params![id],
            |row| {
                Ok(LoginLocation {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    ip_address: row.get(2)?,
                    country_code: row.get(3)?,
                    city: row.get(4)?,
                    latitude: row.get(5)?,
                    longitude: row.get(6)?,
                    accuracy_radius: row.get(7)?,
                    created_at: row.get(8)?,
                    risk_score: row.get(9)?,
                    is_suspicious: row.get::<_, i32>(10)? != 0,
                    suspicious_reason: row.get(11)?,
                })
            },
        );

        match result {
            Ok(location) => Ok(Some(location)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => {
                error!("❌ Erro ao buscar localização de login: {}", e);
                Err(ApiError::from(e))
            }
        }
    }

    /// Lista as localizações de login de um usuário
    pub fn find_by_user_id(
        pool: &DbPool,
        user_id: &str,
        limit: usize,
    ) -> Result<LocationListResponse, ApiError> {
        let conn = pool.get()?;
        
        let mut stmt = conn.prepare(
            "SELECT 
                id, user_id, ip_address, country_code, city, 
                latitude, longitude, accuracy_radius, created_at,
                risk_score, is_suspicious, suspicious_reason
            FROM user_login_locations
            WHERE user_id = ?1
            ORDER BY created_at DESC
            LIMIT ?2"
        )?;
        
        let locations_iter = stmt.query_map(params![user_id, limit as i64], |row| {
            Ok(LoginLocation {
                id: row.get(0)?,
                user_id: row.get(1)?,
                ip_address: row.get(2)?,
                country_code: row.get(3)?,
                city: row.get(4)?,
                latitude: row.get(5)?,
                longitude: row.get(6)?,
                accuracy_radius: row.get(7)?,
                created_at: row.get(8)?,
                risk_score: row.get(9)?,
                is_suspicious: row.get::<_, i32>(10)? != 0,
                suspicious_reason: row.get(11)?,
            })
        })?;
        
        let mut locations = Vec::new();
        for location in locations_iter {
            locations.push(location?);
        }
        
        let total_count = locations.len();
        let suspicious_count = locations.iter().filter(|l| l.is_suspicious).count();
        
        let location_summaries = locations.iter()
            .map(LocationSummary::from)
            .collect();
        
        Ok(LocationListResponse {
            locations: location_summaries,
            total_count,
            suspicious_count,
        })
    }

    /// Busca a última localização de login de um usuário
    pub fn find_latest(pool: &DbPool, user_id: &str) -> Result<Option<LoginLocation>, ApiError> {
        let conn = pool.get()?;
        
        let result = conn.query_row(
            "SELECT 
                id, user_id, ip_address, country_code, city, 
                latitude, longitude, accuracy_radius, created_at,
                risk_score, is_suspicious, suspicious_reason
            FROM user_login_locations
            WHERE user_id = ?1
            ORDER BY created_at DESC
            LIMIT 1",
            params![user_id],
            |row| {
                Ok(LoginLocation {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    ip_address: row.get(2)?,
                    country_code: row.get(3)?,
                    city: row.get(4)?,
                    latitude: row.get(5)?,
                    longitude: row.get(6)?,
                    accuracy_radius: row.get(7)?,
                    created_at: row.get(8)?,
                    risk_score: row.get(9)?,
                    is_suspicious: row.get::<_, i32>(10)? != 0,
                    suspicious_reason: row.get(11)?,
                })
            },
        );

        match result {
            Ok(location) => Ok(Some(location)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => {
                error!("❌ Erro ao buscar última localização de login: {}", e);
                Err(ApiError::from(e))
            }
        }
    }
    
    /// Limpa localizações de login antigas
    pub fn clean_old_locations(pool: &DbPool, days_to_keep: i64) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        
        let now = chrono::Utc::now();
        let cutoff_date = now - chrono::Duration::days(days_to_keep);
        
        let rows_deleted = conn.execute(
            "DELETE FROM user_login_locations WHERE created_at < ?1",
            params![cutoff_date],
        )?;
        
        info!("🧹 Limpeza de localizações de login: {} registros removidos", rows_deleted);
        Ok(rows_deleted)
    }
} 