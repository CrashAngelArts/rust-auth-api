use serde::{Deserialize, Serialize};
use validator::Validate;

/// Modelo para armazenar os dados de ritmo de digitação
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeystrokeDynamics {
    /// ID do usuário
    pub user_id: String,
    
    /// Padrão de digitação armazenado (intervalos entre teclas em milissegundos)
    #[serde(skip_serializing)]
    pub typing_pattern: Vec<u32>,
    
    /// Limiar de similaridade para aceitar o login (em porcentagem)
    pub similarity_threshold: u8,
    
    /// Se a verificação de ritmo de digitação está habilitada
    pub enabled: bool,
}

/// DTO para registrar um novo padrão de digitação
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct RegisterKeystrokePatternDto {
    /// Padrão de digitação (intervalos entre teclas em milissegundos)
    #[validate(length(min = 1, message = "O padrão de digitação não pode estar vazio"))]
    pub typing_pattern: Vec<u32>,
    
    /// Limiar de similaridade para aceitar o login (em porcentagem)
    #[validate(range(min = 50, max = 100, message = "O limiar de similaridade deve estar entre 50% e 100%"))]
    pub similarity_threshold: u8,
}

/// DTO para verificar um padrão de digitação durante o login
#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct VerifyKeystrokePatternDto {
    /// Padrão de digitação atual (intervalos entre teclas em milissegundos)
    #[validate(length(min = 1, message = "O padrão de digitação não pode estar vazio"))]
    pub typing_pattern: Vec<u32>,
}

/// Resposta para o status da verificação de ritmo de digitação
#[derive(Debug, Serialize, Deserialize)]
pub struct KeystrokeVerificationResponse {
    /// Se o padrão de digitação foi aceito
    pub accepted: bool,
    
    /// Porcentagem de similaridade calculada
    pub similarity_percentage: f32,
    
    /// Limiar configurado pelo usuário
    pub threshold: u8,
    
    /// Mensagem informativa
    pub message: String,
}

/// Resposta para o status da configuração de ritmo de digitação
#[derive(Debug, Serialize, Deserialize)]
pub struct KeystrokeStatusResponse {
    /// Se a verificação de ritmo de digitação está habilitada
    pub enabled: bool,
    
    /// Limiar de similaridade configurado
    pub similarity_threshold: u8,
    
    /// Se o usuário já registrou um padrão de digitação
    pub pattern_registered: bool,
}
