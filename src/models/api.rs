use serde::Serialize;

/// Estrutura padronizada para respostas da API
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<serde_json::Value>,
}

impl<T> ApiResponse<T> {
    /// Cria uma resposta de sucesso
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data,
            message: None,
            errors: None,
        }
    }

    /// Cria uma resposta de sucesso com mensagem
    pub fn success_with_message(data: T, message: &str) -> Self {
        Self {
            success: true,
            data,
            message: Some(message.to_string()),
            errors: None,
        }
    }

    /// Cria uma resposta de erro
    pub fn error(errors: serde_json::Value, message: &str) -> ApiResponse<serde_json::Value> {
        ApiResponse {
            success: false,
            data: serde_json::json!({}),
            message: Some(message.to_string()),
            errors: Some(errors),
        }
    }
} 