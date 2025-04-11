use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::{info, warn, error};
use crate::errors::{ApiError, ErrorResponse};
use actix_web::http::StatusCode;

// Estrutura para armazenar informações de tentativas de verificação
#[derive(Debug, Clone)]
struct KeystrokeVerificationAttempt {
    timestamp: Instant,
    success: bool,
    similarity: f64,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

// Estrutura para armazenar o histórico de tentativas por usuário
#[derive(Debug)]
struct UserVerificationHistory {
    attempts: Vec<KeystrokeVerificationAttempt>,
    suspicious_activity_detected: bool,
    last_successful_verification: Option<Instant>,
    anomaly_score: f64,
}

// Serviço de segurança para keystroke dynamics
#[derive(Clone)]
pub struct KeystrokeSecurityService {
    // Armazena o histórico de verificações por usuário
    verification_history: Arc<Mutex<HashMap<String, UserVerificationHistory>>>,
    // Configurações de segurança
    max_failed_attempts: usize,
    suspicious_threshold: f64,
    anomaly_threshold: f64,
    history_window: Duration,
}

impl KeystrokeSecurityService {
    // Criar uma nova instância do serviço
    pub fn new(
        max_failed_attempts: usize,
        suspicious_threshold: f64,
        anomaly_threshold: f64,
        history_window_secs: u64,
    ) -> Self {
        Self {
            verification_history: Arc::new(Mutex::new(HashMap::new())),
            max_failed_attempts,
            suspicious_threshold,
            anomaly_threshold,
            history_window: Duration::from_secs(history_window_secs),
        }
    }

    // Configuração padrão
    pub fn default() -> Self {
        Self::new(
            5,                // 5 tentativas falhas consecutivas
            0.3,              // 30% de variação é suspeito
            0.5,              // 50% de variação é anomalia
            3600,             // Janela de histórico de 1 hora
        )
    }

    // Registrar uma tentativa de verificação e verificar se é suspeita
    pub async fn record_verification_attempt(
        &self,
        user_id: &str,
        success: bool,
        similarity: f64,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), ApiError> {
        let now = Instant::now();
        let attempt = KeystrokeVerificationAttempt {
            timestamp: now,
            success,
            similarity,
            ip_address,
            user_agent,
        };

        let mut history_map = self.verification_history.lock().await;
        
        // Obter ou criar histórico para o usuário
        let history = history_map.entry(user_id.to_string()).or_insert(UserVerificationHistory {
            attempts: Vec::new(),
            suspicious_activity_detected: false,
            last_successful_verification: None,
            anomaly_score: 0.0,
        });

        // Limpar tentativas antigas
        let window_start = now - self.history_window;
        history.attempts.retain(|attempt| attempt.timestamp >= window_start);

        // Adicionar nova tentativa
        history.attempts.push(attempt);

        // Atualizar última verificação bem-sucedida
        if success {
            history.last_successful_verification = Some(now);
        }

        // Verificar padrões suspeitos
        self.check_for_suspicious_patterns(user_id, history).await?;

        // Verificar tentativas falhas consecutivas
        self.check_consecutive_failures(user_id, history).await?;

        // Calcular pontuação de anomalia
        self.calculate_anomaly_score(history);

        Ok(())
    }

    // Verificar padrões suspeitos nas tentativas
    async fn check_for_suspicious_patterns(
        &self,
        user_id: &str,
        history: &mut UserVerificationHistory,
    ) -> Result<(), ApiError> {
        // Verificar variação de similaridade
        if history.attempts.len() >= 3 {
            let similarities: Vec<f64> = history.attempts.iter()
                .map(|a| a.similarity)
                .collect();
            
            // Calcular desvio padrão da similaridade
            let mean = similarities.iter().sum::<f64>() / similarities.len() as f64;
            let variance = similarities.iter()
                .map(|&s| (s - mean).powi(2))
                .sum::<f64>() / similarities.len() as f64;
            let std_dev = variance.sqrt();
            
            // Se o desvio padrão for muito alto, pode indicar tentativas de força bruta
            if std_dev > self.suspicious_threshold {
                warn!(
                    "Padrão suspeito detectado para o usuário {}: desvio padrão de similaridade = {}",
                    user_id, std_dev
                );
                
                history.suspicious_activity_detected = true;
                
                // Se for muito alto, bloquear imediatamente
                if std_dev > self.anomaly_threshold {
                    error!(
                        "Anomalia detectada para o usuário {}: desvio padrão de similaridade = {}",
                        user_id, std_dev
                    );
                    
                    return Err(ApiError::Forbidden(ErrorResponse {
                        status: StatusCode::FORBIDDEN.as_u16(),
                        message: "Atividade suspeita detectada. Verificação temporariamente desativada 🚨".to_string(),
                        error_code: "KEYSTROKE_ANOMALY_DETECTED".to_string(),
                        error_details: Some("Variação anormal nos padrões de digitação detectada. Por segurança, a verificação foi temporariamente bloqueada.".to_string()),
                        validation_details: None,
                    }));
                }
            }
        }
        
        Ok(())
    }

    // Verificar tentativas falhas consecutivas
    async fn check_consecutive_failures(
        &self,
        user_id: &str,
        history: &UserVerificationHistory,
    ) -> Result<(), ApiError> {
        // Contar falhas consecutivas recentes
        let consecutive_failures = history.attempts.iter()
            .rev() // Reverter para começar das mais recentes
            .take_while(|attempt| !attempt.success) // Parar na primeira tentativa bem-sucedida
            .count();
        
        if consecutive_failures >= self.max_failed_attempts {
            warn!(
                "Muitas tentativas falhas consecutivas para o usuário {}: {}",
                user_id, consecutive_failures
            );
            
            return Err(ApiError::TooManyRequests(ErrorResponse {
                status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                message: "Muitas tentativas falhas consecutivas. Tente novamente mais tarde 🔒".to_string(),
                error_code: "KEYSTROKE_CONSECUTIVE_FAILURES".to_string(),
                error_details: Some(format!(
                    "Limite de {} tentativas falhas consecutivas excedido. Aguarde antes de tentar novamente.",
                    self.max_failed_attempts
                )),
                validation_details: None,
            }));
        }
        
        Ok(())
    }

    // Calcular pontuação de anomalia
    fn calculate_anomaly_score(&self, history: &mut UserVerificationHistory) {
        if history.attempts.is_empty() {
            history.anomaly_score = 0.0;
            return;
        }
        
        // Fatores que contribuem para a pontuação de anomalia:
        // 1. Variação na similaridade
        // 2. Taxa de falhas
        // 3. Frequência de tentativas (muitas tentativas em pouco tempo)
        
        // Calcular variação na similaridade
        let similarities: Vec<f64> = history.attempts.iter()
            .map(|a| a.similarity)
            .collect();
        
        let mean = similarities.iter().sum::<f64>() / similarities.len() as f64;
        let variance = similarities.iter()
            .map(|&s| (s - mean).powi(2))
            .sum::<f64>() / similarities.len() as f64;
        let std_dev = variance.sqrt();
        
        // Calcular taxa de falhas
        let failure_rate = history.attempts.iter()
            .filter(|a| !a.success)
            .count() as f64 / history.attempts.len() as f64;
        
        // Calcular frequência de tentativas (tentativas por minuto)
        let now = Instant::now();
        let oldest_attempt = history.attempts.iter()
            .map(|a| a.timestamp)
            .min()
            .unwrap_or(now);
        
        let duration_mins = (now - oldest_attempt).as_secs_f64() / 60.0;
        let frequency = if duration_mins > 0.0 {
            history.attempts.len() as f64 / duration_mins
        } else {
            // Se todas as tentativas forem no mesmo instante, frequência alta
            history.attempts.len() as f64
        };
        
        // Normalizar frequência (considerar mais de 10 tentativas por minuto como alta frequência)
        let normalized_frequency = (frequency / 10.0).min(1.0);
        
        // Calcular pontuação de anomalia (0.0 - 1.0)
        // Pesos: variação (40%), taxa de falhas (30%), frequência (30%)
        history.anomaly_score = 
            (std_dev / self.anomaly_threshold) * 0.4 +
            failure_rate * 0.3 +
            normalized_frequency * 0.3;
        
        // Limitar entre 0.0 e 1.0
        history.anomaly_score = history.anomaly_score.min(1.0).max(0.0);
        
        // Registrar pontuação alta
        if history.anomaly_score > 0.7 {
            warn!(
                "Alta pontuação de anomalia para usuário: {:.2}",
                history.anomaly_score
            );
        }
    }

    // Verificar se o usuário está em uma lista de observação
    pub async fn is_user_suspicious(&self, user_id: &str) -> bool {
        let history_map = self.verification_history.lock().await;
        
        if let Some(history) = history_map.get(user_id) {
            return history.suspicious_activity_detected || history.anomaly_score > 0.7;
        }
        
        false
    }

    // Obter pontuação de anomalia do usuário
    pub async fn get_user_anomaly_score(&self, user_id: &str) -> f64 {
        let history_map = self.verification_history.lock().await;
        
        if let Some(history) = history_map.get(user_id) {
            return history.anomaly_score;
        }
        
        0.0
    }

    // Limpar histórico antigo periodicamente
    pub async fn clean_old_history(&self) {
        let now = Instant::now();
        let window_start = now - self.history_window;
        
        let mut history_map = self.verification_history.lock().await;
        
        // Para cada usuário, limpar tentativas antigas
        for history in history_map.values_mut() {
            history.attempts.retain(|attempt| attempt.timestamp >= window_start);
        }
        
        // Remover usuários sem tentativas
        history_map.retain(|_, history| !history.attempts.is_empty());
        
        info!("Limpeza de histórico de verificação concluída. Usuários restantes: {}", history_map.len());
    }
}
