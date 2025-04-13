use chrono::Utc;
use rusqlite::{params, Row};
use uuid::Uuid;

use crate::models::security_question::{SecurityQuestion, UserSecurityAnswer};
use crate::db::DbPool;
use crate::errors::ApiError;

#[derive(Clone)]
pub struct SqliteSecurityQuestionRepository {
    pool: DbPool,
}

impl SqliteSecurityQuestionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // ----- Métodos para SecurityQuestion -----

    pub fn create_security_question(&self, text: String) -> Result<SecurityQuestion, ApiError> {
        let conn = self.pool.get()?;
        
        let question = SecurityQuestion {
            id: Uuid::new_v4(),
            text,
            active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        conn.execute(
            "INSERT INTO security_questions (id, text, active, created_at, updated_at) 
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &question.id.to_string(),
                &question.text,
                &question.active,
                &question.created_at,
                &question.updated_at
            ],
        )?;
        
        Ok(question)
    }

    pub fn get_security_question_by_id(&self, id: &Uuid) -> Result<SecurityQuestion, ApiError> {
        let conn = self.pool.get()?;
        
        let question = conn.query_row(
            "SELECT id, text, active, created_at, updated_at 
             FROM security_questions 
             WHERE id = ?1",
            [id.to_string()],
            |row| {
                let id_str: String = row.get(0)?;
                Ok(SecurityQuestion {
                    id: Uuid::parse_str(&id_str).unwrap_or_default(),
                    text: row.get(1)?,
                    active: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        )?;
        
        Ok(question)
    }

    pub fn list_security_questions(&self, only_active: bool) -> Result<Vec<SecurityQuestion>, ApiError> {
        let conn = self.pool.get()?;
        
        let mut stmt = if only_active {
            conn.prepare(
                "SELECT id, text, active, created_at, updated_at 
                 FROM security_questions 
                 WHERE active = 1 
                 ORDER BY created_at"
            )?
        } else {
            conn.prepare(
                "SELECT id, text, active, created_at, updated_at 
                 FROM security_questions 
                 ORDER BY created_at"
            )?
        };
        
        let question_iter = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            Ok(SecurityQuestion {
                id: Uuid::parse_str(&id_str).unwrap_or_default(),
                text: row.get(1)?,
                active: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        
        let mut questions = Vec::new();
        for question in question_iter {
            questions.push(question?);
        }
        
        Ok(questions)
    }

    pub fn update_security_question(&self, question: &mut SecurityQuestion) -> Result<(), ApiError> {
        let conn = self.pool.get()?;
        
        question.updated_at = Utc::now();
        
        conn.execute(
            "UPDATE security_questions 
             SET text = ?1, active = ?2, updated_at = ?3 
             WHERE id = ?4",
            params![
                &question.text,
                &question.active,
                &question.updated_at,
                &question.id.to_string()
            ],
        )?;
        
        Ok(())
    }

    pub fn delete_security_question(&self, id: &Uuid) -> Result<(), ApiError> {
        let conn = self.pool.get()?;
        
        // Verificar se existem respostas para esta pergunta
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM user_security_answers WHERE question_id = ?1",
            [id.to_string()],
            |row| row.get(0),
        )?;
        
        if count > 0 {
            return Err(ApiError::ConflictError(
                "Esta pergunta de segurança tem respostas associadas e não pode ser excluída 🚫".to_string()
            ));
        }
        
        conn.execute(
            "DELETE FROM security_questions WHERE id = ?1",
            [id.to_string()],
        )?;
        
        Ok(())
    }

    // ----- Métodos para UserSecurityAnswer -----

    pub fn create_user_answer(&self, user_id: &Uuid, question_id: &Uuid, answer_hash: String) -> Result<(), ApiError> {
        let conn = self.pool.get()?;
        let now = Utc::now();
        let id = Uuid::new_v4();
        
        conn.execute(
            "INSERT INTO user_security_answers (id, user_id, question_id, answer_hash, created_at, updated_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &id.to_string(),
                &user_id.to_string(),
                &question_id.to_string(),
                &answer_hash,
                &now,
                &now
            ],
        )?;
        
        Ok(())
    }

    pub fn get_user_answer(&self, user_id: &Uuid, question_id: &Uuid) -> Result<UserSecurityAnswer, ApiError> {
        let conn = self.pool.get()?;
        
        let answer = conn.query_row(
            "SELECT id, user_id, question_id, answer_hash, created_at, updated_at 
             FROM user_security_answers 
             WHERE user_id = ?1 AND question_id = ?2",
            params![
                &user_id.to_string(),
                &question_id.to_string()
            ],
            |row| {
                let id_str: String = row.get(0)?;
                let user_id_str: String = row.get(1)?;
                let question_id_str: String = row.get(2)?;
                
                Ok(UserSecurityAnswer {
                    id: Uuid::parse_str(&id_str).unwrap_or_default(),
                    user_id: Uuid::parse_str(&user_id_str).unwrap_or_default(),
                    question_id: Uuid::parse_str(&question_id_str).unwrap_or_default(),
                    answer_hash: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        )?;
        
        Ok(answer)
    }

    pub fn get_user_answers(&self, user_id: &Uuid) -> Result<Vec<UserSecurityAnswer>, ApiError> {
        let conn = self.pool.get()?;
        
        let mut stmt = conn.prepare(
            "SELECT id, user_id, question_id, answer_hash, created_at, updated_at 
             FROM user_security_answers 
             WHERE user_id = ?1"
        )?;
        
        let answer_iter = stmt.query_map([user_id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let user_id_str: String = row.get(1)?;
            let question_id_str: String = row.get(2)?;
            
            Ok(UserSecurityAnswer {
                id: Uuid::parse_str(&id_str).unwrap_or_default(),
                user_id: Uuid::parse_str(&user_id_str).unwrap_or_default(),
                question_id: Uuid::parse_str(&question_id_str).unwrap_or_default(),
                answer_hash: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            })
        })?;
        
        let mut answers = Vec::new();
        for answer in answer_iter {
            answers.push(answer?);
        }
        
        Ok(answers)
    }

    pub fn update_user_answer(&self, answer: &mut UserSecurityAnswer) -> Result<(), ApiError> {
        let conn = self.pool.get()?;
        
        answer.updated_at = Utc::now();
        
        conn.execute(
            "UPDATE user_security_answers 
             SET answer_hash = ?1, updated_at = ?2 
             WHERE id = ?3",
            params![
                &answer.answer_hash,
                &answer.updated_at,
                &answer.id.to_string()
            ],
        )?;
        
        Ok(())
    }

    pub fn delete_user_answer(&self, user_id: &Uuid, question_id: &Uuid) -> Result<(), ApiError> {
        let conn = self.pool.get()?;
        
        conn.execute(
            "DELETE FROM user_security_answers 
             WHERE user_id = ?1 AND question_id = ?2",
            params![
                &user_id.to_string(),
                &question_id.to_string()
            ],
        )?;
        
        Ok(())
    }

    pub fn delete_all_user_answers(&self, user_id: &Uuid) -> Result<(), ApiError> {
        let conn = self.pool.get()?;
        
        conn.execute(
            "DELETE FROM user_security_answers WHERE user_id = ?1",
            [user_id.to_string()],
        )?;
        
        Ok(())
    }

    // ----- Métodos auxiliares -----

    fn map_row_to_security_question(&self, row: &Row) -> Result<SecurityQuestion, rusqlite::Error> {
        let id_str: String = row.get(0)?;
        Ok(SecurityQuestion {
            id: Uuid::parse_str(&id_str).unwrap(),
            text: row.get(1)?,
            active: row.get(2)?,
            created_at: row.get(3)?,
            updated_at: row.get(4)?,
        })
    }

    fn map_row_to_user_answer(&self, row: &Row) -> Result<UserSecurityAnswer, rusqlite::Error> {
        let id_str: String = row.get(0)?;
        let user_id_str: String = row.get(1)?;
        let question_id_str: String = row.get(2)?;
        
        Ok(UserSecurityAnswer {
            id: Uuid::parse_str(&id_str).unwrap(),
            user_id: Uuid::parse_str(&user_id_str).unwrap(),
            question_id: Uuid::parse_str(&question_id_str).unwrap(),
            answer_hash: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    }
} 