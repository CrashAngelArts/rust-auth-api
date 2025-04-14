use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecurityQuestion {
    pub id: String,
    pub text: String,         // Texto da pergunta 📝
    pub is_active: bool,      // Indica se a pergunta está ativa ✅
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SecurityQuestion {
    pub fn new(text: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            text,
            is_active: true,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserSecurityAnswer {
    pub id: String,
    pub user_id: String,                 // ID do usuário 👤
    pub question_id: String,             // ID da pergunta 📝
    pub answer_hash: String,             // Hash da resposta (para segurança) 🔒
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UserSecurityAnswer {
    pub fn new(user_id: String, question_id: String, answer_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            question_id,
            answer_hash,
            created_at: now,
            updated_at: now,
        }
    }
}

// DTOs para criação e atualização

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct CreateSecurityQuestionDto {
    #[validate(length(min = 5, max = 200, message = "A pergunta deve ter entre 5 e 200 caracteres"))]
    pub text: String,           // Texto da pergunta 📝
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UpdateSecurityQuestionDto {
    #[validate(length(min = 5, max = 200, message = "A pergunta deve ter entre 5 e 200 caracteres"))]
    pub text: Option<String>,    // Texto da pergunta 📝
    pub is_active: Option<bool>, // Status da pergunta ✅
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct CreateUserSecurityAnswerDto {
    pub question_id: String,    // ID da pergunta selecionada 📝
    
    #[validate(length(min = 2, max = 100, message = "A resposta deve ter entre 2 e 100 caracteres"))]
    pub answer: String,         // Resposta em texto plano 🔑
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityQuestionResponse {
    pub id: String,
    pub text: String,           // Texto da pergunta 📝
    pub is_active: bool,        // Status da pergunta ✅
    pub created_at: DateTime<Utc>,
}

impl From<SecurityQuestion> for SecurityQuestionResponse {
    fn from(question: SecurityQuestion) -> Self {
        Self {
            id: question.id,
            text: question.text,
            is_active: question.is_active,
            created_at: question.created_at,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserQuestionResponse {
    pub id: String,
    pub question_id: String,     // ID da pergunta 📝
    pub question_text: String,   // Texto da pergunta para exibição 📝
    pub created_at: DateTime<Utc>,
} 