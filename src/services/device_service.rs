use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::Session;
use crate::models::device::{DeviceInfo, DeviceListResponse};
use chrono::Utc;
use rusqlite::params;
use tracing::info;
use woothee::parser::Parser;

pub struct DeviceService;

impl DeviceService {
    // Lista todos os dispositivos de um usuário
    pub fn list_user_devices(pool: &DbPool, user_id: &str) -> Result<DeviceListResponse, ApiError> {
        let conn = pool.get()?;
        
        // Buscar todas as sessões ativas do usuário
        let mut stmt = conn.prepare(
            "SELECT id, user_id, device_name, device_type, ip_address, user_agent, 
                    location, last_active_at, is_current, expires_at, created_at
             FROM sessions 
             WHERE user_id = ?1 AND expires_at > ?2
             ORDER BY last_active_at DESC"
        )?;
        
        let now = Utc::now().to_rfc3339();
        let device_iter = stmt.query_map([user_id, &now], |row| {
            Ok(DeviceInfo {
                id: row.get(0)?,
                device_name: row.get(2)?,
                device_type: row.get(3)?,
                ip_address: row.get(4)?,
                location: row.get(6)?,
                last_active_at: row.get(7)?,
                is_current: row.get(8)?,
                created_at: row.get(10)?,
            })
        })?;
        
        let mut devices = Vec::new();
        let mut current_device = None;
        
        for device in device_iter {
            let device = device?;
            if device.is_current {
                current_device = Some(device.clone());
            }
            devices.push(device);
        }
        
        Ok(DeviceListResponse {
            devices,
            current_device,
        })
    }
    
    // Obtém detalhes de um dispositivo específico
    pub fn get_device_details(pool: &DbPool, device_id: &str, user_id: &str) -> Result<DeviceInfo, ApiError> {
        let conn = pool.get()?;
        
        let device = conn.query_row(
            "SELECT id, user_id, device_name, device_type, ip_address, user_agent, 
                    location, last_active_at, is_current, expires_at, created_at
             FROM sessions 
             WHERE id = ?1 AND user_id = ?2",
            [device_id, user_id],
            |row| {
                Ok(DeviceInfo {
                    id: row.get(0)?,
                    device_name: row.get(2)?,
                    device_type: row.get(3)?,
                    ip_address: row.get(4)?,
                    location: row.get(6)?,
                    last_active_at: row.get(7)?,
                    is_current: row.get(8)?,
                    created_at: row.get(10)?,
                })
            },
        )?;
        
        Ok(device)
    }
    
    // Atualiza informações de um dispositivo
    pub fn update_device(pool: &DbPool, device_id: &str, user_id: &str, device_name: &str) -> Result<DeviceInfo, ApiError> {
        let conn = pool.get()?;
        
        // Verificar se o dispositivo pertence ao usuário
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1 AND user_id = ?2",
            [device_id, user_id],
            |row| row.get(0),
        )?;
        
        if count == 0 {
            return Err(ApiError::NotFoundError("Dispositivo não encontrado".to_string()));
        }
        
        // Atualizar o nome do dispositivo
        conn.execute(
            "UPDATE sessions SET device_name = ?1 WHERE id = ?2",
            [device_name, device_id],
        )?;
        
        info!("📱 Nome do dispositivo atualizado para: {}", device_name);
        
        // Retornar os detalhes atualizados
        Self::get_device_details(pool, device_id, user_id)
    }
    
    // Revoga acesso de um dispositivo específico
    pub fn revoke_device(pool: &DbPool, device_id: &str, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Verificar se o dispositivo pertence ao usuário
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1 AND user_id = ?2",
            [device_id, user_id],
            |row| row.get(0),
        )?;
        
        if count == 0 {
            return Err(ApiError::NotFoundError("Dispositivo não encontrado".to_string()));
        }
        
        // Excluir a sessão
        conn.execute(
            "DELETE FROM sessions WHERE id = ?1",
            [device_id],
        )?;
        
        info!("🔒 Acesso revogado para o dispositivo ID: {}", device_id);
        
        Ok(())
    }
    
    // Atualiza o último acesso de um dispositivo
    pub fn update_last_active(pool: &DbPool, device_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        let now = Utc::now().to_rfc3339();
        
        conn.execute(
            "UPDATE sessions SET last_active_at = ?1 WHERE id = ?2",
            [&now, device_id],
        )?;
        
        Ok(())
    }
    
    // Marca um dispositivo como atual
    pub fn set_current_device(pool: &DbPool, device_id: &str, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Primeiro, desmarcar todos os dispositivos do usuário
        conn.execute(
            "UPDATE sessions SET is_current = 0 WHERE user_id = ?1",
            [user_id],
        )?;
        
        // Marcar o dispositivo específico como atual
        conn.execute(
            "UPDATE sessions SET is_current = 1 WHERE id = ?1",
            [device_id],
        )?;
        
        info!("📱 Dispositivo ID: {} definido como atual", device_id);
        
        Ok(())
    }
    
    // Detecta o tipo de dispositivo a partir do user agent
    pub fn detect_device_type(user_agent: &Option<String>) -> Option<String> {
        if let Some(ua_string) = user_agent {
            let parser = Parser::new();
            
            if let Some(result) = parser.parse(ua_string) {
                // Detectar o tipo de dispositivo
                let device_type = match result.category {
                    "smartphone" => "Celular 📱",
                    "mobilephone" => "Celular 📱",
                    "tablet" => "Tablet 📱",
                    _ => "Computador 💻"
                };
                
                // Detectar o navegador e sistema operacional
                let browser = result.name;
                let os = result.os;
                
                Some(format!("{} ({} em {})", device_type, browser, os))
            } else {
                Some("Dispositivo desconhecido ❓".to_string())
            }
        } else {
            Some("Dispositivo desconhecido ❓".to_string())
        }
    }
    
    // Gera um nome amigável para o dispositivo baseado no tipo e localização
    pub fn generate_device_name(device_type: &Option<String>, location: &Option<String>) -> String {
        let device = device_type.clone().unwrap_or_else(|| "Dispositivo".to_string());
        let location_str = location.clone().unwrap_or_else(|| "desconhecido".to_string());
        
        format!("{} em {}", device, location_str)
    }
    
    // Limpa sessões expiradas
    pub fn clean_expired_sessions(pool: &DbPool) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        let now = Utc::now().to_rfc3339();
        
        let deleted = conn.execute(
            "DELETE FROM sessions WHERE expires_at < ?1",
            [&now],
        )?;
        
        if deleted > 0 {
            info!("🧹 {} sessões expiradas foram removidas", deleted);
        }
        
        Ok(deleted)
    }
    
    // Cria uma nova sessão com informações de dispositivo
    pub fn create_session_with_device_info(
        pool: &DbPool,
        user_id: &str,
        ip_address: &Option<String>,
        user_agent: &Option<String>,
        duration_hours: i64,
    ) -> Result<Session, ApiError> {
        let conn = pool.get()?;
        
        // Criar a sessão
        let session = Session::new(user_id.to_string(), ip_address.clone(), user_agent.clone(), duration_hours);
        
        // Detectar tipo de dispositivo
        let device_type = Self::detect_device_type(user_agent);
        
        // Gerar localização aproximada (simulada para este exemplo)
        let location = if let Some(ip) = ip_address {
            if ip.starts_with("192.168.") {
                Some("Rede local".to_string())
            } else {
                Some("Localização desconhecida".to_string())
            }
        } else {
            None
        };
        
        // Gerar nome amigável para o dispositivo
        let device_name = Self::generate_device_name(&device_type, &location);
        
        // Inserir a sessão no banco de dados com informações de dispositivo
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at, 
                                  device_name, device_type, last_active_at, location, is_current)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                &session.id,
                &session.user_id,
                &session.token,
                &session.ip_address,
                &session.user_agent,
                &session.expires_at.to_rfc3339(),
                &session.created_at.to_rfc3339(),
                &device_name,
                &device_type,
                &now,
                &location,
                true, // Marcar como dispositivo atual
            ],
        )?;
        
        // Desmarcar outros dispositivos como atuais
        conn.execute(
            "UPDATE sessions SET is_current = 0 WHERE user_id = ?1 AND id != ?2",
            [&session.user_id, &session.id],
        )?;
        
        info!("📱 Nova sessão criada para o dispositivo: {}", device_name);
        
        Ok(session)
    }
}
