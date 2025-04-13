use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::auth::Session;
use crate::models::device::{DeviceInfo, DeviceListResponse};
use chrono::Utc;
use rusqlite::params;
use tracing::{info, warn, error};
use woothee::parser::Parser;
use serde_json;
use crate::config::Config;

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
        config: &Config,
    ) -> Result<Session, ApiError> {
        let conn = pool.get()?;
        
        // Criar a sessão com valores padrão se não fornecidos
        let ip = ip_address.clone().unwrap_or_else(|| "desconhecido".to_string());
        let ua = user_agent.clone().unwrap_or_else(|| "desconhecido".to_string());
        
        let now = Utc::now();
        let session = Session {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            ip_address: ip.clone(),
            user_agent: ua.clone(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(duration_hours),
            last_activity_at: now,
            is_active: true,
        };
        
        // Detectar tipo de dispositivo
        let device_type_info = Self::detect_device_type(user_agent);
        let current_device_type = device_type_info.clone().unwrap_or_default(); // Para comparação
        
        // Gerar localização aproximada (simulada para este exemplo)
        // TODO: Implementar geolocalização de IP real usando biblioteca externa (ex: maxminddb)
        //       e adicionar o campo `location` à migration da tabela `sessions`.
        let location: Option<String> = if let Some(ip_addr) = ip_address {
            if ip_addr.starts_with("192.168.") || ip_addr.starts_with("10.") || ip_addr == "::1" || ip_addr == "127.0.0.1" {
                Some("Rede Local 🏠".to_string())
            } else {
                // Simulação - substitua por chamada de geolocalização
                Some("Desconhecida 🌍".to_string())
            }
        } else {
            None
        };
        
        // Gerar nome amigável para o dispositivo
        let device_name = Self::generate_device_name(&device_type_info, &location);
        
        // --- ANÁLISE DE RISCO --- 
        const RISK_THRESHOLD_HIGH: i32 = 3;
        const RISK_THRESHOLD_MEDIUM: i32 = 2;

        let mut risk_score: i32 = 0;
        let mut risk_factors = Vec::new();

        // 1. Buscar histórico recente de sessões do usuário
        let recent_sessions = Self::get_recent_sessions(pool, user_id, 5)?; // Buscar as últimas 5 sessões

        let mut is_new_device_heuristic = true; // Assumir que é novo até encontrar um UA igual (heurística)

        if !recent_sessions.is_empty() {
            let last_session = &recent_sessions[0];

            // 2. Analisar mudança de IP
            if ip != last_session.ip_address {
                // TODO: Implementar verificação de geolocalização (mudança de país/cidade)
                risk_score += 1;
                risk_factors.push("Mudança de Endereço IP".to_string());
                info!("🛡️ [Risco Login] Mudança de IP detectada para {}: {} -> {}", user_id, last_session.ip_address, ip);
            }

            // 3. Analisar mudança de Dispositivo (User Agent - Comparação Simples por enquanto)
            if ua != last_session.user_agent {
                 // TODO: Comparação mais inteligente de UAs usando woothee
                 risk_score += 1;
                 risk_factors.push("Mudança de Dispositivo/Navegador".to_string());
                 info!("🛡️ [Risco Login] Mudança de User Agent detectada para {}: ... -> {}", user_id, ua);
            } else {
                is_new_device_heuristic = false; // Se UA for igual, provavelmente não é novo
            }
             
            // 4. Analisar Horário
            // TODO: Implementar análise baseada no histórico de horários do usuário
            let current_hour = now.hour();
            let is_weekend = now.weekday().number_from_monday() >= 6;
            let is_late_night = current_hour < 6; // Madrugada
            let is_outside_business_hours = current_hour < 8 || current_hour > 18;

            if is_late_night || (is_weekend && is_outside_business_hours) {
                risk_score += 1;
                risk_factors.push("Login em Horário Incomum".to_string());
                info!("🛡️ [Risco Login] Login em horário incomum detectado para {}: Hora {}, Fim de Semana: {}", user_id, current_hour, is_weekend);
            }

            // 5. Verificar se é um dispositivo completamente novo (baseado na heurística do UA)
            if is_new_device_heuristic {
                // Checar se *algum* registro no histórico recente tem o mesmo UA
                let ua_exists_in_history = recent_sessions.iter().any(|s| s.user_agent == ua);
                if !ua_exists_in_history {
                    risk_score += 1; // Pontuação extra para dispositivo 100% novo
                    risk_factors.push("Dispositivo Completamente Novo".to_string());
                    info!("🛡️ [Risco Login] Primeiro login detectado para o User Agent '{}' do usuário {}", ua, user_id);
                }
            }

        }

        // --- FIM ANÁLISE DE RISCO ---

        // --- Ação Baseada no Risco ---
        if risk_score >= RISK_THRESHOLD_HIGH {
            warn!("🚨 [Risco Login Elevado] Atividade suspeita detectada para usuário {}. Risco: {}, Fatores: {:?}", user_id, risk_score, risk_factors);
            // Retornar erro indicando atividade suspeita
            return Err(ApiError::SuspiciousLoginActivity("Atividade suspeita detectada. Verificação adicional necessária.".to_string()));
        }

        // Marcar se verificação extra é necessária (risco médio)
        let requires_extra_verification = risk_score >= RISK_THRESHOLD_MEDIUM;
        if requires_extra_verification {
             info!("⚠️ [Risco Login Médio] Verificação adicional pode ser necessária para usuário {}. Risco: {}, Fatores: {:?}", user_id, risk_score, risk_factors);
        }

        // TODO: Adicionar migration SQL para os campos: risk_score INTEGER, risk_factors TEXT, location TEXT

        // --- Limite de Sessões Ativas ---
        if let Some(max_sessions) = config.security.session_max_active {
            let active_sessions_count = Self::count_active_sessions(pool, user_id)?;
            if active_sessions_count >= max_sessions {
                // Revogar a sessão mais antiga
                if let Some(oldest_session_id) = Self::get_oldest_active_session_id(pool, user_id)? {
                    match Self::revoke_device(pool, &oldest_session_id, user_id) {
                        Ok(_) => info!("🔒 Sessão mais antiga ({}) revogada para usuário {} devido ao limite de {} sessões.", oldest_session_id, user_id, max_sessions),
                        Err(e) => error!("Erro ao revogar sessão antiga {}: {}", oldest_session_id, e),
                    }
                } 
            }
        }
        // --- FIM Limite de Sessões ---

        // Inserir a nova sessão no banco
        // Garantir que risk_factors seja serializado corretamente (ex: JSON string)
        let risk_factors_json = serde_json::to_string(&risk_factors).unwrap_or_else(|_| "[]".to_string());

        conn.execute(
            "INSERT INTO sessions (id, user_id, ip_address, user_agent, device_name, device_type, location, is_current, expires_at, created_at, last_activity_at, risk_score, risk_factors)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                &session.id,
                &session.user_id,
                &session.ip_address,
                &session.user_agent,
                &device_name,
                &device_type_info, // Usar a info detectada
                &location,
                true, // Marcar como dispositivo atual
                &session.expires_at,
                &session.created_at,
                &session.last_activity_at,
                &risk_score,
                &risk_factors_json // Salvar como JSON string
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
    
    // Obtém as sessões mais recentes de um usuário
    pub fn get_recent_sessions(pool: &DbPool, user_id: &str, limit: i64) -> Result<Vec<Session>, ApiError> {
        let conn = pool.get()?;
        
        let mut stmt = conn.prepare(
            "SELECT id, user_id, ip_address, user_agent, expires_at, created_at, last_activity_at, is_active, risk_score, risk_factors
             FROM sessions
             WHERE user_id = ?1
             ORDER BY created_at DESC
             LIMIT ?2"
        )?;
        
        let session_iter = stmt.query_map(params![user_id, limit], |row| {
            let risk_factors_json: Option<String> = row.get(9)?;
            let risk_factors = risk_factors_json
                .map(|json| serde_json::from_str(&json).unwrap_or_else(|_| Vec::new()))
                .unwrap_or_else(Vec::new);
                
            Ok(Session {
                id: row.get(0)?,
                user_id: row.get(1)?,
                ip_address: row.get(2)?,
                user_agent: row.get(3)?,
                expires_at: row.get(4)?,
                created_at: row.get(5)?,
                last_activity_at: row.get(6)?,
                is_active: row.get(7)?,
                risk_score: row.get(8)?,
                risk_factors: Some(risk_factors),
            })
        })?;
        
        let sessions = session_iter.collect::<Result<Vec<Session>, _>>()?;
        
        Ok(sessions)
    }

    // Conta as sessões ativas de um usuário
    fn count_active_sessions(pool: &DbPool, user_id: &str) -> Result<u32, ApiError> {
        let conn = pool.get()?;
        let now = Utc::now();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?1 AND expires_at > ?2",
            params![user_id, now],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    // Obtém o ID da sessão ativa mais antiga de um usuário
    fn get_oldest_active_session_id(pool: &DbPool, user_id: &str) -> Result<Option<String>, ApiError> {
        let conn = pool.get()?;
        let now = Utc::now();
        let result = conn.query_row(
            "SELECT id FROM sessions 
             WHERE user_id = ?1 AND expires_at > ?2 
             ORDER BY created_at ASC 
             LIMIT 1",
            params![user_id, now],
            |row| row.get(0),
        );

        match result {
            Ok(id) => Ok(Some(id)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None), // Nenhuma sessão ativa encontrada
            Err(e) => Err(ApiError::DatabaseError(e.to_string())),
        }
    }
}
