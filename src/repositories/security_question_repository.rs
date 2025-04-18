use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::security_question::{SecurityQuestion, UserSecurityAnswer};
use chrono::Utc;
use rusqlite::{params, OptionalExtension};
use tracing::{info};

pub struct SqliteSecurityQuestionRepository;

impl SqliteSecurityQuestionRepository {
    // === Métodos para Perguntas de Segurança ===

    // Criar nova pergunta de segurança
    pub fn create_question(pool: &DbPool, text: String) -> Result<SecurityQuestion, ApiError> {
        let conn = pool.get()?;
        
        // Verificar se já existe uma pergunta com o mesmo texto
        let exists: bool = conn.query_row(
            "SELECT 1 FROM security_questions WHERE text = ?1",
            [&text],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);

        if exists {
            return Err(ApiError::ConflictError("Uma pergunta de segurança com este texto já existe".to_string()));
        }

        // Criar nova pergunta
        let question = SecurityQuestion::new(text);
        
        conn.execute(
            "INSERT INTO security_questions (id, text, is_active, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                question.id,
                question.text,
                question.is_active,
                question.created_at,
                question.updated_at
            ],
        )?;

        info!("✅ Pergunta de segurança criada: {}", question.id);
        Ok(question)
    }

    // Obter pergunta pelo ID
    pub fn get_question_by_id(pool: &DbPool, id: &str) -> Result<SecurityQuestion, ApiError> {
        let conn = pool.get()?;
        
        let question = conn.query_row(
            "SELECT id, text, is_active, created_at, updated_at FROM security_questions WHERE id = ?1",
            [id],
            |row| {
                Ok(SecurityQuestion {
                    id: row.get(0)?,
                    text: row.get(1)?,
                    is_active: row.get(2)?,
                    created_at: row.get(3)?,
                    updated_at: row.get(4)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                ApiError::NotFoundError(format!("Pergunta de segurança não encontrada: {}", id))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })?;

        Ok(question)
    }

    // Listar todas as perguntas
    pub fn list_questions(
        pool: &DbPool, 
        page: u64, 
        page_size: u64, 
        only_active: bool
    ) -> Result<(Vec<SecurityQuestion>, u64), ApiError> {
        let conn = pool.get()?;
        
        // Construir consulta com base no filtro de status
        let query_count = if only_active {
            "SELECT COUNT(*) FROM security_questions WHERE is_active = 1"
        } else {
            "SELECT COUNT(*) FROM security_questions"
        };
        
        // Obter o total de perguntas
        let total: u64 = conn.query_row(query_count, [], |row| row.get(0))?;
        
        // Calcular o offset
        let offset = (page.saturating_sub(1)) * page_size;
        
        // Construir consulta para obter as perguntas
        let query = if only_active {
            "SELECT id, text, is_active, created_at, updated_at FROM security_questions 
             WHERE is_active = 1 
             ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        } else {
            "SELECT id, text, is_active, created_at, updated_at FROM security_questions 
             ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        };
        
        let mut stmt = conn.prepare(query)?;
        
        let rows = stmt.query_map([page_size, offset], |row| {
            Ok(SecurityQuestion {
                id: row.get(0)?,
                text: row.get(1)?,
                is_active: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        
        let mut questions = Vec::new();
        for row in rows {
            questions.push(row?);
        }
        
        Ok((questions, total))
    }

    // Atualizar pergunta
    pub fn update_question(
        pool: &DbPool, 
        id: &str, 
        text: Option<String>, 
        is_active: Option<bool>
    ) -> Result<SecurityQuestion, ApiError> {
        let conn = pool.get()?;
        
        // Verificar se a pergunta existe
        let question_exists: bool = conn.query_row(
            "SELECT 1 FROM security_questions WHERE id = ?1",
            [id],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        if !question_exists {
            return Err(ApiError::NotFoundError(format!("Pergunta de segurança não encontrada: {}", id)));
        }
        
        // Se o texto for atualizado, verificar duplicatas
        if let Some(ref new_text) = text {
            let text_exists: bool = conn.query_row(
                "SELECT 1 FROM security_questions WHERE text = ?1 AND id != ?2",
                params![new_text, id],
                |_| Ok(true),
            ).optional()?.unwrap_or(false);
            
            if text_exists {
                return Err(ApiError::ConflictError("Uma pergunta de segurança com este texto já existe".to_string()));
            }
        }
        
        // Construir a query de atualização dinamicamente
        let mut update_parts = Vec::new();
        let mut params = Vec::new();
        
        if text.is_some() {
            update_parts.push("text = ?");
            params.push(text.unwrap());
        }
        
        if is_active.is_some() {
            update_parts.push("is_active = ?");
            params.push(is_active.unwrap().to_string());
        }
        
        update_parts.push("updated_at = ?");
        let now = Utc::now();
        params.push(now.to_string());
        
        let update_clause = update_parts.join(", ");
        let query = format!("UPDATE security_questions SET {} WHERE id = ?", update_clause);
        
        params.push(id.to_string());
        
        conn.execute(&query, rusqlite::params_from_iter(params.iter()))?;
        
        // Obter a pergunta atualizada
        Self::get_question_by_id(pool, id)
    }

    // Excluir pergunta
    pub fn delete_question(pool: &DbPool, id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        // Verificar se a pergunta está em uso por algum usuário
        let in_use: bool = conn.query_row(
            "SELECT 1 FROM user_security_answers WHERE question_id = ?1 LIMIT 1",
            [id],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        if in_use {
            return Err(ApiError::ConflictError("Esta pergunta está em uso e não pode ser excluída".to_string()));
        }
        
        // Excluir a pergunta
        let rows_affected = conn.execute(
            "DELETE FROM security_questions WHERE id = ?1",
            [id],
        )?;
        
        if rows_affected == 0 {
            return Err(ApiError::NotFoundError(format!("Pergunta de segurança não encontrada: {}", id)));
        }
        
        info!("🗑️ Pergunta de segurança excluída: {}", id);
        Ok(())
    }

    // === Métodos para Respostas de Segurança do Usuário ===
    
    // Adicionar resposta de segurança para um usuário
    pub fn add_user_answer(
        pool: &DbPool, 
        user_id: &str, 
        question_id: &str, 
        answer_hash: &str
    ) -> Result<UserSecurityAnswer, ApiError> {
        let conn = pool.get()?;
        
        // Verificar se a pergunta existe
        let question_exists: bool = conn.query_row(
            "SELECT 1 FROM security_questions WHERE id = ?1",
            [question_id],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        if !question_exists {
            return Err(ApiError::NotFoundError(format!("Pergunta de segurança não encontrada: {}", question_id)));
        }
        
        // Verificar se o usuário já respondeu esta pergunta
        let already_answered: bool = conn.query_row(
            "SELECT 1 FROM user_security_answers WHERE user_id = ?1 AND question_id = ?2",
            params![user_id, question_id],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        if already_answered {
            return Err(ApiError::ConflictError("O usuário já respondeu esta pergunta de segurança".to_string()));
        }
        
        // Criar nova resposta
        let answer = UserSecurityAnswer::new(
            user_id.to_string(),
            question_id.to_string(),
            answer_hash.to_string(),
        );
        
        conn.execute(
            "INSERT INTO user_security_answers (id, user_id, question_id, answer_hash, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                answer.id,
                answer.user_id,
                answer.question_id,
                answer.answer_hash,
                answer.created_at,
                answer.updated_at
            ],
        )?;
        
        info!("✅ Resposta de segurança adicionada para o usuário: {}", user_id);
        Ok(answer)
    }
    
    // Obter resposta do usuário pelo ID
    pub fn get_user_answer_by_id(pool: &DbPool, id: &str) -> Result<UserSecurityAnswer, ApiError> {
        let conn = pool.get()?;
        
        let answer = conn.query_row(
            "SELECT id, user_id, question_id, answer_hash, created_at, updated_at 
             FROM user_security_answers WHERE id = ?1",
            [id],
            |row| {
                Ok(UserSecurityAnswer {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    question_id: row.get(2)?,
                    answer_hash: row.get(3)?,
                    created_at: row.get(4)?,
                    updated_at: row.get(5)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                ApiError::NotFoundError(format!("Resposta de segurança não encontrada: {}", id))
            }
            _ => ApiError::DatabaseError(e.to_string()),
        })?;
        
        Ok(answer)
    }
    
    // Listar respostas de um usuário
    pub fn list_user_answers(pool: &DbPool, user_id: &str) -> Result<Vec<(UserSecurityAnswer, String)>, ApiError> {
        let conn = pool.get()?;
        
        let mut stmt = conn.prepare(
            "SELECT a.id, a.user_id, a.question_id, a.answer_hash, a.created_at, a.updated_at, q.text
             FROM user_security_answers a
             JOIN security_questions q ON a.question_id = q.id
             WHERE a.user_id = ?1
             ORDER BY a.created_at ASC"
        )?;
        
        let rows = stmt.query_map([user_id], |row| {
            let answer = UserSecurityAnswer {
                id: row.get(0)?,
                user_id: row.get(1)?,
                question_id: row.get(2)?,
                answer_hash: row.get(3)?,
                created_at: row.get(4)?,
                updated_at: row.get(5)?,
            };
            
            let question_text: String = row.get(6)?;
            
            Ok((answer, question_text))
        })?;
        
        let mut answers = Vec::new();
        for row in rows {
            answers.push(row?);
        }
        
        Ok(answers)
    }
    
    // Verificar resposta de segurança
    pub fn verify_answer(
        pool: &DbPool, 
        user_id: &str, 
        question_id: &str, 
        answer_hash: &str
    ) -> Result<bool, ApiError> {
        let conn = pool.get()?;
        
        let is_correct = conn.query_row(
            "SELECT 1 FROM user_security_answers 
             WHERE user_id = ?1 AND question_id = ?2 AND answer_hash = ?3",
            params![user_id, question_id, answer_hash],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        Ok(is_correct)
    }
    
    // Atualizar resposta de segurança
    pub fn update_user_answer(
        pool: &DbPool, 
        id: &str, 
        answer_hash: &str
    ) -> Result<UserSecurityAnswer, ApiError> {
        let conn = pool.get()?;
        
        let now = Utc::now();
        
        let rows_affected = conn.execute(
            "UPDATE user_security_answers 
             SET answer_hash = ?1, updated_at = ?2
             WHERE id = ?3",
            params![answer_hash, now, id],
        )?;
        
        if rows_affected == 0 {
            return Err(ApiError::NotFoundError(format!("Resposta de segurança não encontrada: {}", id)));
        }
        
        Self::get_user_answer_by_id(pool, id)
    }
    
    // Remover resposta de segurança
    pub fn delete_user_answer(pool: &DbPool, id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        let rows_affected = conn.execute(
            "DELETE FROM user_security_answers WHERE id = ?1",
            [id],
        )?;
        
        if rows_affected == 0 {
            return Err(ApiError::NotFoundError(format!("Resposta de segurança não encontrada: {}", id)));
        }
        
        info!("🗑️ Resposta de segurança excluída: {}", id);
        Ok(())
    }
    
    // Remover todas as respostas de um usuário
    pub fn delete_user_answers(pool: &DbPool, user_id: &str) -> Result<(), ApiError> {
        let conn = pool.get()?;
        
        conn.execute(
            "DELETE FROM user_security_answers WHERE user_id = ?1",
            [user_id],
        )?;
        
        info!("🗑️ Todas as respostas de segurança excluídas para o usuário: {}", user_id);
        Ok(())
    }
} 