use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::recovery_code::{RecoveryCode, RecoveryCodeResponse};
use chrono::Utc;
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use rusqlite::params;
use tracing::{error, info, warn};
use uuid::Uuid;
use std::sync::Arc;

/// Serviço para gerenciar códigos de recuperação únicos
pub struct RecoveryCodeService;

impl RecoveryCodeService {
    /// Gera e armazena um novo código de recuperação para um usuário
    /// 
    /// # Parâmetros
    /// * `pool` - Pool de conexões com o banco de dados
    /// * `user_id` - ID do usuário para o qual gerar o código
    /// * `expiration_hours` - Opcional: número de horas até a expiração do código
    ///
    /// # Retorna
    /// * `RecoveryCodeResponse` - Resposta contendo o código gerado
    pub fn generate_code(
        pool: &DbPool,
        user_id: &str,
        expiration_hours: Option<i64>,
    ) -> Result<RecoveryCodeResponse, ApiError> {
        let conn = pool.get()?;

        // Gerar código aleatório (24 caracteres alfanuméricos)
        let code: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();
            
        // Criar novo objeto RecoveryCode
        let recovery_code = RecoveryCode::new(
            user_id.to_string(),
            code.clone(),
            expiration_hours,
        );
        
        // Invalidar códigos anteriores do usuário (opcional, dependendo do requisito)
        conn.execute(
            "UPDATE recovery_codes SET used = 1 WHERE user_id = ?1 AND used = 0",
            params![user_id],
        )?;
        
        // Inserir novo código no banco de dados
        conn.execute(
            "INSERT INTO recovery_codes (id, user_id, code, created_at, expires_at, used)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                recovery_code.id,
                recovery_code.user_id,
                recovery_code.code,
                recovery_code.created_at,
                recovery_code.expires_at,
                recovery_code.used as i32,
            ],
        )?;
        
        info!("✨ Novo código de recuperação gerado para o usuário: {}", user_id);
        
        // Criar resposta com mensagem adequada
        let message = match expiration_hours {
            Some(hours) => format!("Código de recuperação gerado com validade de {} horas 🕒", hours),
            None => "Código de recuperação permanente gerado com sucesso 🔐".to_string(),
        };
        
        Ok(RecoveryCodeResponse {
            message,
            code: code.clone(),
            expires_at: recovery_code.expires_at,
        })
    }
    
    /// Verifica e opcionalmente consome um código de recuperação
    /// 
    /// # Parâmetros
    /// * `pool` - Pool de conexões com o banco de dados
    /// * `code` - Código de recuperação a ser verificado
    /// * `consume` - Se true, marca o código como usado após a verificação
    ///
    /// # Retorna
    /// * `String` - ID do usuário associado ao código, se válido
    pub fn verify_code(
        pool: &DbPool,
        code: &str,
        consume: bool,
    ) -> Result<String, ApiError> {
        let conn = pool.get()?;
        
        // Buscar o código no banco de dados
        let result = conn.query_row(
            "SELECT id, user_id, code, created_at, expires_at, used 
             FROM recovery_codes 
             WHERE code = ?1 AND used = 0",
            params![code],
            |row| {
                Ok(RecoveryCode {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    code: row.get(2)?,
                    created_at: row.get(3)?,
                    expires_at: row.get(4)?,
                    used: row.get::<_, i32>(5)? != 0,
                })
            },
        );
        
        match result {
            Ok(recovery_code) => {
                // Verificar se o código está expirado
                if recovery_code.is_expired() {
                    warn!("❌ Código de recuperação expirado: {}", code);
                    return Err(ApiError::AuthenticationError("Código de recuperação expirado".to_string()));
                }
                
                // Se especificado, marcar o código como usado
                if consume {
                    conn.execute(
                        "UPDATE recovery_codes SET used = 1 WHERE id = ?1",
                        params![recovery_code.id],
                    )?;
                    info!("✅ Código de recuperação consumido: {}", code);
                }
                
                info!("✅ Código de recuperação verificado com sucesso para o usuário: {}", recovery_code.user_id);
                Ok(recovery_code.user_id)
            },
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                warn!("❌ Código de recuperação inválido ou já utilizado: {}", code);
                Err(ApiError::AuthenticationError("Código de recuperação inválido ou já utilizado".to_string()))
            },
            Err(e) => {
                error!("❌ Erro ao verificar código de recuperação: {}", e);
                Err(ApiError::from(e))
            }
        }
    }
    
    /// Lista todos os códigos de recuperação de um usuário
    /// 
    /// # Parâmetros
    /// * `pool` - Pool de conexões com o banco de dados
    /// * `user_id` - ID do usuário para listar os códigos
    ///
    /// # Retorna
    /// * `Vec<RecoveryCode>` - Lista de códigos de recuperação
    pub fn list_user_codes(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<RecoveryCode>, ApiError> {
        let conn = pool.get()?;
        
        let mut stmt = conn.prepare(
            "SELECT id, user_id, code, created_at, expires_at, used 
             FROM recovery_codes 
             WHERE user_id = ?1 
             ORDER BY created_at DESC"
        )?;
        
        let codes_iter = stmt.query_map(params![user_id], |row| {
            Ok(RecoveryCode {
                id: row.get(0)?,
                user_id: row.get(1)?,
                code: row.get(2)?,
                created_at: row.get(3)?,
                expires_at: row.get(4)?,
                used: row.get::<_, i32>(5)? != 0,
            })
        })?;
        
        let mut codes = Vec::new();
        for code in codes_iter {
            codes.push(code?);
        }
        
        Ok(codes)
    }
    
    /// Limpa códigos de recuperação expirados ou usados
    /// 
    /// # Parâmetros
    /// * `pool` - Pool de conexões com o banco de dados
    ///
    /// # Retorna
    /// * `usize` - Número de códigos removidos
    pub fn clean_expired_codes(
        pool: &DbPool,
    ) -> Result<usize, ApiError> {
        let conn = pool.get()?;
        
        // Remover códigos expirados
        let now = Utc::now();
        let rows_affected = conn.execute(
            "DELETE FROM recovery_codes WHERE 
             (expires_at IS NOT NULL AND expires_at < ?1) OR 
             (used = 1 AND created_at < ?2)",
            params![now, now - chrono::Duration::days(30)], // Remover códigos usados após 30 dias
        )?;
        
        info!("🧹 Limpeza de códigos de recuperação: {} códigos removidos", rows_affected);
        Ok(rows_affected)
    }
} 