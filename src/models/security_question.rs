use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Representa uma pergunta de segurança pré-definida pelo sistema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityQuestion {
    pub id: Uuid,
    pub text: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Representa a resposta de um usuário a uma pergunta de segurança
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSecurityAnswer {
    pub id: Uuid,
    pub user_id: Uuid,
    pub question_id: Uuid,
    /// Resposta armazenada com hash por segurança
    pub answer_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SecurityQuestion {
    pub fn new(text: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            text,
            active: true,
            created_at: now,
            updated_at: now,
        }
    }
}

impl UserSecurityAnswer {
    pub fn new(user_id: Uuid, question_id: Uuid, answer_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            question_id,
            answer_hash,
            created_at: now,
            updated_at: now,
        }
    }
} 