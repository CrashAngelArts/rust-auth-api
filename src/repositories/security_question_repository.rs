use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, Row};
use uuid::Uuid;

use crate::errors::app_error::AppError;
use crate::models::security_question::{SecurityQuestion, UserSecurityAnswer};

pub struct SqliteSecurityQuestionRepository {
    conn: Connection,
}

impl SqliteSecurityQuestionRepository {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    // ----- Métodos para SecurityQuestion -----

    pub fn create_security_question(&self, text: String) -> Result<SecurityQuestion> {
        let security_question = SecurityQuestion::new(text);
        
        self.conn.execute(
            "INSERT INTO security_questions (id, text, active, created_at, updated_at) 
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                security_question.id.to_string(),
                security_question.text,
                security_question.active,
                security_question.created_at,
                security_question.updated_at,
            ],
        )?;

        Ok(security_question)
    }

    pub fn get_security_question_by_id(&self, id: &Uuid) -> Result<SecurityQuestion> {
        let mut stmt = self.conn.prepare(
            "SELECT id, text, active, created_at, updated_at 
             FROM security_questions 
             WHERE id = ?1",
        )?;

        let security_question = stmt.query_row(params![id.to_string()], |row| {
            self.map_row_to_security_question(row)
        })?;

        Ok(security_question)
    }

    pub fn list_security_questions(&self, only_active: bool) -> Result<Vec<SecurityQuestion>> {
        let sql = if only_active {
            "SELECT id, text, active, created_at, updated_at 
             FROM security_questions 
             WHERE active = TRUE 
             ORDER BY text"
        } else {
            "SELECT id, text, active, created_at, updated_at 
             FROM security_questions 
             ORDER BY text"
        };

        let mut stmt = self.conn.prepare(sql)?;
        let security_question_iter = stmt.query_map([], |row| {
            self.map_row_to_security_question(row)
        })?;

        let mut security_questions = Vec::new();
        for security_question in security_question_iter {
            security_questions.push(security_question?);
        }

        Ok(security_questions)
    }

    pub fn update_security_question(&self, security_question: &mut SecurityQuestion) -> Result<()> {
        security_question.updated_at = Utc::now();

        self.conn.execute(
            "UPDATE security_questions 
             SET text = ?2, active = ?3, updated_at = ?4 
             WHERE id = ?1",
            params![
                security_question.id.to_string(),
                security_question.text,
                security_question.active,
                security_question.updated_at,
            ],
        )?;

        Ok(())
    }

    pub fn delete_security_question(&self, id: &Uuid) -> Result<()> {
        // Primeiro verifica se a pergunta está sendo usada
        let mut stmt = self.conn.prepare(
            "SELECT COUNT(*) FROM user_security_answers WHERE question_id = ?1"
        )?;
        
        let count: i64 = stmt.query_row(params![id.to_string()], |row| row.get(0))?;
        
        if count > 0 {
            return Err(AppError::ConstraintViolation(
                "Não é possível excluir uma pergunta de segurança que está em uso 🔒".to_string()
            ).into());
        }

        self.conn.execute(
            "DELETE FROM security_questions WHERE id = ?1",
            params![id.to_string()],
        )?;

        Ok(())
    }

    // ----- Métodos para UserSecurityAnswer -----

    pub fn create_user_answer(
        &self, 
        user_id: &Uuid, 
        question_id: &Uuid, 
        answer_hash: String
    ) -> Result<UserSecurityAnswer> {
        let user_answer = UserSecurityAnswer::new(*user_id, *question_id, answer_hash);
        
        self.conn.execute(
            "INSERT INTO user_security_answers (id, user_id, question_id, answer_hash, created_at, updated_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                user_answer.id.to_string(),
                user_answer.user_id.to_string(),
                user_answer.question_id.to_string(),
                user_answer.answer_hash,
                user_answer.created_at,
                user_answer.updated_at,
            ],
        )?;

        Ok(user_answer)
    }

    pub fn get_user_answers(&self, user_id: &Uuid) -> Result<Vec<UserSecurityAnswer>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, question_id, answer_hash, created_at, updated_at 
             FROM user_security_answers 
             WHERE user_id = ?1
             ORDER BY created_at"
        )?;

        let answer_iter = stmt.query_map(params![user_id.to_string()], |row| {
            self.map_row_to_user_answer(row)
        })?;

        let mut answers = Vec::new();
        for answer in answer_iter {
            answers.push(answer?);
        }

        Ok(answers)
    }

    pub fn get_user_answer(
        &self, 
        user_id: &Uuid, 
        question_id: &Uuid
    ) -> Result<UserSecurityAnswer> {
        let mut stmt = self.conn.prepare(
            "SELECT id, user_id, question_id, answer_hash, created_at, updated_at 
             FROM user_security_answers 
             WHERE user_id = ?1 AND question_id = ?2"
        )?;

        let answer = stmt.query_row(
            params![user_id.to_string(), question_id.to_string()], 
            |row| self.map_row_to_user_answer(row)
        )?;

        Ok(answer)
    }

    pub fn update_user_answer(
        &self, 
        user_answer: &mut UserSecurityAnswer
    ) -> Result<()> {
        user_answer.updated_at = Utc::now();

        self.conn.execute(
            "UPDATE user_security_answers 
             SET answer_hash = ?3, updated_at = ?4 
             WHERE user_id = ?1 AND question_id = ?2",
            params![
                user_answer.user_id.to_string(),
                user_answer.question_id.to_string(),
                user_answer.answer_hash,
                user_answer.updated_at,
            ],
        )?;

        Ok(())
    }

    pub fn delete_user_answer(
        &self, 
        user_id: &Uuid, 
        question_id: &Uuid
    ) -> Result<()> {
        self.conn.execute(
            "DELETE FROM user_security_answers 
             WHERE user_id = ?1 AND question_id = ?2",
            params![user_id.to_string(), question_id.to_string()],
        )?;

        Ok(())
    }

    pub fn delete_all_user_answers(&self, user_id: &Uuid) -> Result<()> {
        self.conn.execute(
            "DELETE FROM user_security_answers WHERE user_id = ?1",
            params![user_id.to_string()],
        )?;

        Ok(())
    }

    // ----- Métodos auxiliares -----

    fn map_row_to_security_question(&self, row: &Row) -> Result<SecurityQuestion, rusqlite::Error> {
        Ok(SecurityQuestion {
            id: Uuid::parse_str(row.get(0)?).unwrap(),
            text: row.get(1)?,
            active: row.get(2)?,
            created_at: row.get(3)?,
            updated_at: row.get(4)?,
        })
    }

    fn map_row_to_user_answer(&self, row: &Row) -> Result<UserSecurityAnswer, rusqlite::Error> {
        Ok(UserSecurityAnswer {
            id: Uuid::parse_str(row.get(0)?).unwrap(),
            user_id: Uuid::parse_str(row.get(1)?).unwrap(),
            question_id: Uuid::parse_str(row.get(2)?).unwrap(),
            answer_hash: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    }
} 