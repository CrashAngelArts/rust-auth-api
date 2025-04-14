use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::security_question::{
    CreateSecurityQuestionDto, CreateUserSecurityAnswerDto,
    SecurityQuestionResponse, UpdateSecurityQuestionDto,
    UserQuestionResponse
};
use crate::repositories::security_question_repository::SqliteSecurityQuestionRepository;
use bcrypt::{hash, verify};
use rusqlite::OptionalExtension;
use tracing::info;

pub struct SecurityQuestionService;

impl SecurityQuestionService {
    // === Métodos para Perguntas de Segurança ===

    // Criar nova pergunta de segurança
    pub fn create_question(
        pool: &DbPool,
        dto: CreateSecurityQuestionDto,
    ) -> Result<SecurityQuestionResponse, ApiError> {
        let question = SqliteSecurityQuestionRepository::create_question(pool, dto.text)?;
        Ok(SecurityQuestionResponse::from(question))
    }

    // Obter pergunta pelo ID
    pub fn get_question_by_id(
        pool: &DbPool,
        id: &str,
    ) -> Result<SecurityQuestionResponse, ApiError> {
        let question = SqliteSecurityQuestionRepository::get_question_by_id(pool, id)?;
        Ok(SecurityQuestionResponse::from(question))
    }

    // Listar perguntas
    pub fn list_questions(
        pool: &DbPool,
        page: u64,
        page_size: u64,
        only_active: bool,
    ) -> Result<(Vec<SecurityQuestionResponse>, u64), ApiError> {
        let (questions, total) = SqliteSecurityQuestionRepository::list_questions(
            pool, page, page_size, only_active,
        )?;
        
        let question_responses = questions
            .into_iter()
            .map(SecurityQuestionResponse::from)
            .collect();
            
        Ok((question_responses, total))
    }

    // Atualizar pergunta
    pub fn update_question(
        pool: &DbPool,
        id: &str,
        dto: UpdateSecurityQuestionDto,
    ) -> Result<SecurityQuestionResponse, ApiError> {
        let question = SqliteSecurityQuestionRepository::update_question(
            pool, id, dto.text, dto.is_active,
        )?;
        
        Ok(SecurityQuestionResponse::from(question))
    }

    // Excluir pergunta
    pub fn delete_question(
        pool: &DbPool,
        id: &str,
    ) -> Result<(), ApiError> {
        SqliteSecurityQuestionRepository::delete_question(pool, id)
    }

    // === Métodos para Respostas de Segurança do Usuário ===

    // Adicionar resposta de segurança para um usuário
    pub fn add_user_answer(
        pool: &DbPool,
        user_id: &str,
        dto: CreateUserSecurityAnswerDto,
        salt_rounds: u32,
    ) -> Result<UserQuestionResponse, ApiError> {
        // Verificar se a pergunta existe e está ativa
        let question = SqliteSecurityQuestionRepository::get_question_by_id(pool, &dto.question_id)?;
        
        if !question.is_active {
            return Err(ApiError::BadRequestError(
                "Esta pergunta de segurança não está ativa".to_string(),
            ));
        }
        
        // Criar hash da resposta para armazenamento seguro
        let answer_hash = hash(&dto.answer, salt_rounds)?;
        
        // Adicionar resposta
        let answer = SqliteSecurityQuestionRepository::add_user_answer(
            pool, user_id, &dto.question_id, &answer_hash,
        )?;
        
        Ok(UserQuestionResponse {
            id: answer.id,
            question_id: answer.question_id,
            question_text: question.text,
            created_at: answer.created_at,
        })
    }

    // Listar respostas de um usuário
    pub fn list_user_answers(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<UserQuestionResponse>, ApiError> {
        let answers_with_text = SqliteSecurityQuestionRepository::list_user_answers(pool, user_id)?;
        
        let responses = answers_with_text
            .into_iter()
            .map(|(answer, question_text)| UserQuestionResponse {
                id: answer.id,
                question_id: answer.question_id,
                question_text,
                created_at: answer.created_at,
            })
            .collect();
            
        Ok(responses)
    }

    // Verificar resposta de segurança
    pub fn verify_user_answer(
        pool: &DbPool,
        user_id: &str,
        question_id: &str,
        answer: &str,
    ) -> Result<bool, ApiError> {
        // Obter todas as respostas do usuário para verificar o hash
        let conn = pool.get()?;
        
        let answer_hash: Option<String> = conn.query_row(
            "SELECT answer_hash FROM user_security_answers 
             WHERE user_id = ?1 AND question_id = ?2",
            [user_id, question_id],
            |row| row.get(0),
        ).optional()?;
        
        match answer_hash {
            Some(hash_str) => {
                // Verificar usando bcrypt
                let result = verify(answer, &hash_str)?;
                Ok(result)
            }
            None => Ok(false), // Usuário não respondeu esta pergunta
        }
    }

    // Atualizar resposta de segurança
    pub fn update_user_answer(
        pool: &DbPool,
        user_id: &str,
        answer_id: &str,
        new_answer: &str,
        salt_rounds: u32,
    ) -> Result<UserQuestionResponse, ApiError> {
        // Verificar se a resposta pertence ao usuário
        let conn = pool.get()?;
        
        let belongs_to_user: bool = conn.query_row(
            "SELECT 1 FROM user_security_answers 
             WHERE id = ?1 AND user_id = ?2",
            [answer_id, user_id],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        if !belongs_to_user {
            return Err(ApiError::ForbiddenError(
                "Esta resposta de segurança não pertence ao usuário".to_string(),
            ));
        }
        
        // Criar hash da nova resposta
        let answer_hash = hash(new_answer, salt_rounds)?;
        
        // Atualizar resposta
        let answer = SqliteSecurityQuestionRepository::update_user_answer(
            pool, answer_id, &answer_hash,
        )?;
        
        // Obter texto da pergunta
        let question = SqliteSecurityQuestionRepository::get_question_by_id(
            pool, &answer.question_id,
        )?;
        
        Ok(UserQuestionResponse {
            id: answer.id,
            question_id: answer.question_id,
            question_text: question.text,
            created_at: answer.created_at,
        })
    }

    // Remover resposta de segurança
    pub fn delete_user_answer(
        pool: &DbPool,
        user_id: &str,
        answer_id: &str,
    ) -> Result<(), ApiError> {
        // Verificar se a resposta pertence ao usuário
        let conn = pool.get()?;
        
        let belongs_to_user: bool = conn.query_row(
            "SELECT 1 FROM user_security_answers 
             WHERE id = ?1 AND user_id = ?2",
            [answer_id, user_id],
            |_| Ok(true),
        ).optional()?.unwrap_or(false);
        
        if !belongs_to_user {
            return Err(ApiError::ForbiddenError(
                "Esta resposta de segurança não pertence ao usuário".to_string(),
            ));
        }
        
        SqliteSecurityQuestionRepository::delete_user_answer(pool, answer_id)
    }

    // Remover todas as respostas de um usuário
    pub fn delete_all_user_answers(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(), ApiError> {
        SqliteSecurityQuestionRepository::delete_user_answers(pool, user_id)
    }
    
    // Verifica se o usuário tem um número mínimo de perguntas de segurança respondidas
    pub fn user_has_min_security_questions(
        pool: &DbPool,
        user_id: &str,
        min_count: usize,
    ) -> Result<bool, ApiError> {
        let answers = Self::list_user_answers(pool, user_id)?;
        Ok(answers.len() >= min_count)
    }
    
    // Método auxiliar para verificação durante recuperação de conta
    pub fn verify_multiple_answers(
        pool: &DbPool,
        user_id: &str,
        answers: &[(String, String)], // Vec de (question_id, resposta)
        min_correct: usize, // Número mínimo de respostas corretas necessárias
    ) -> Result<bool, ApiError> {
        if answers.is_empty() {
            return Ok(false);
        }
        
        let mut correct_count = 0;
        
        for (question_id, answer) in answers {
            let is_correct = Self::verify_user_answer(pool, user_id, question_id, answer)?;
            
            if is_correct {
                correct_count += 1;
                
                // Já atingiu o mínimo necessário
                if correct_count >= min_correct {
                    return Ok(true);
                }
            }
        }
        
        // Não atingiu o número mínimo de respostas corretas
        Ok(false)
    }
} 