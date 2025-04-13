use crate::errors::ApiError;
use log::{debug, error, info};
use uuid::Uuid;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::models::security_question::{SecurityQuestion, UserSecurityAnswer};

// Stub temporário até que o repositório real seja implementado
#[derive(Clone)]
pub struct SqliteSecurityQuestionRepository;

impl SqliteSecurityQuestionRepository {
    pub fn new() -> Self {
        Self {}
    }
    
    pub fn create_security_question(&self, text: String) -> Result<SecurityQuestion, ApiError> {
        Ok(SecurityQuestion {
            id: Uuid::new_v4(),
            text,
            active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        })
    }
    
    pub fn get_security_question_by_id(&self, _id: &Uuid) -> Result<SecurityQuestion, ApiError> {
        Err(ApiError::NotFound("Pergunta de segurança não encontrada 🔍".to_string()))
    }
    
    pub fn list_security_questions(&self, _only_active: bool) -> Result<Vec<SecurityQuestion>, ApiError> {
        Ok(Vec::new())
    }
    
    pub fn update_security_question(&self, question: &mut SecurityQuestion) -> Result<(), ApiError> {
        question.updated_at = chrono::Utc::now();
        Ok(())
    }
    
    pub fn delete_security_question(&self, _id: &Uuid) -> Result<(), ApiError> {
        Ok(())
    }
    
    pub fn get_user_answer(&self, _user_id: &Uuid, _question_id: &Uuid) -> Result<UserSecurityAnswer, ApiError> {
        Err(ApiError::NotFound("Resposta de segurança não encontrada 🔍".to_string()))
    }
    
    pub fn get_user_answers(&self, _user_id: &Uuid) -> Result<Vec<UserSecurityAnswer>, ApiError> {
        Ok(Vec::new())
    }
    
    pub fn create_user_answer(&self, _user_id: &Uuid, _question_id: &Uuid, _answer_hash: String) -> Result<(), ApiError> {
        Ok(())
    }
    
    pub fn update_user_answer(&self, _answer: &mut UserSecurityAnswer) -> Result<(), ApiError> {
        Ok(())
    }
    
    pub fn delete_user_answer(&self, _user_id: &Uuid, _question_id: &Uuid) -> Result<(), ApiError> {
        Ok(())
    }
    
    pub fn delete_all_user_answers(&self, _user_id: &Uuid) -> Result<(), ApiError> {
        Ok(())
    }
}

/// Serviço para gerenciar perguntas de segurança e respostas dos usuários
#[derive(Clone)]
pub struct SecurityQuestionService {
    repo: SqliteSecurityQuestionRepository,
}

impl SecurityQuestionService {
    pub fn new(repo: SqliteSecurityQuestionRepository) -> Self {
        Self { repo }
    }

    // ----- Métodos para perguntas de segurança -----

    /// Cria uma nova pergunta de segurança no sistema
    pub fn create_security_question(&self, text: String) -> Result<SecurityQuestion, ApiError> {
        info!("Criando nova pergunta de segurança: {}", text);
        
        let security_question = self.repo.create_security_question(text)?;
        
        info!("Pergunta de segurança criada com ID: {} ✅", security_question.id);
        Ok(security_question)
    }

    /// Obtém uma pergunta de segurança pelo ID
    pub fn get_security_question_by_id(&self, id: &Uuid) -> Result<SecurityQuestion, ApiError> {
        debug!("Buscando pergunta de segurança com ID: {}", id);
        
        match self.repo.get_security_question_by_id(id) {
            Ok(question) => {
                debug!("Pergunta de segurança encontrada ✅");
                Ok(question)
            },
            Err(err) => {
                error!("Erro ao buscar pergunta de segurança: {}", err);
                Err(ApiError::NotFound(format!("Pergunta de segurança não encontrada 🔍")))
            }
        }
    }

    /// Lista todas as perguntas de segurança
    pub fn list_security_questions(&self, only_active: bool) -> Result<Vec<SecurityQuestion>, ApiError> {
        debug!("Listando perguntas de segurança (apenas ativas: {})", only_active);
        
        let questions = self.repo.list_security_questions(only_active)?;
        
        debug!("Encontradas {} perguntas de segurança 📋", questions.len());
        Ok(questions)
    }

    /// Atualiza uma pergunta de segurança existente
    pub fn update_security_question(&self, id: &Uuid, text: String, active: bool) -> Result<SecurityQuestion, ApiError> {
        info!("Atualizando pergunta de segurança com ID: {}", id);
        
        let mut question = self.get_security_question_by_id(id)?;
        question.text = text;
        question.active = active;
        
        self.repo.update_security_question(&mut question)?;
        
        info!("Pergunta de segurança atualizada ✅");
        Ok(question)
    }

    /// Desativa uma pergunta de segurança (mais seguro que excluir)
    pub fn deactivate_security_question(&self, id: &Uuid) -> Result<SecurityQuestion, ApiError> {
        info!("Desativando pergunta de segurança com ID: {}", id);
        
        let mut question = self.get_security_question_by_id(id)?;
        question.active = false;
        
        self.repo.update_security_question(&mut question)?;
        
        info!("Pergunta de segurança desativada ✅");
        Ok(question)
    }

    /// Exclui uma pergunta de segurança (apenas se não estiver em uso)
    pub fn delete_security_question(&self, id: &Uuid) -> Result<(), ApiError> {
        info!("Tentando excluir pergunta de segurança com ID: {}", id);
        
        match self.repo.delete_security_question(id) {
            Ok(_) => {
                info!("Pergunta de segurança excluída com sucesso ✅");
                Ok(())
            },
            Err(err) => {
                error!("Falha ao excluir pergunta de segurança: {}", err);
                Err(err)
            }
        }
    }

    // ----- Métodos para respostas de usuários -----

    /// Adiciona ou atualiza a resposta de um usuário a uma pergunta de segurança
    pub fn set_user_security_answer(
        &self, 
        user_id: &Uuid, 
        question_id: &Uuid, 
        answer: &str
    ) -> Result<(), ApiError> {
        info!("Configurando resposta de segurança para usuário: {}", user_id);
        
        // Verifica se a pergunta existe e está ativa
        let question = self.get_security_question_by_id(question_id)?;
        if !question.active {
            return Err(ApiError::BadRequest(
                "Esta pergunta de segurança não está mais disponível 🚫".to_string()
            ));
        }
        
        // Cria o hash da resposta
        let answer_hash = self.hash_answer(answer)?;
        
        // Verifica se o usuário já tem uma resposta para esta pergunta
        match self.repo.get_user_answer(user_id, question_id) {
            Ok(mut existing_answer) => {
                // Atualiza a resposta existente
                existing_answer.answer_hash = answer_hash;
                self.repo.update_user_answer(&mut existing_answer)?;
                info!("Resposta de segurança atualizada ✅");
            },
            Err(_) => {
                // Cria uma nova resposta
                self.repo.create_user_answer(user_id, question_id, answer_hash)?;
                info!("Nova resposta de segurança criada ✅");
            }
        }
        
        Ok(())
    }

    /// Obtém todas as respostas de segurança de um usuário
    pub fn get_user_security_answers(&self, user_id: &Uuid) -> Result<Vec<UserSecurityAnswer>, ApiError> {
        debug!("Buscando respostas de segurança do usuário: {}", user_id);
        
        let answers = self.repo.get_user_answers(user_id)?;
        
        debug!("Encontradas {} respostas de segurança 📋", answers.len());
        Ok(answers)
    }

    /// Verifica se a resposta do usuário está correta
    pub fn verify_security_answer(
        &self, 
        user_id: &Uuid, 
        question_id: &Uuid, 
        answer: &str
    ) -> Result<bool, ApiError> {
        debug!("Verificando resposta de segurança para usuário: {}", user_id);
        
        match self.repo.get_user_answer(user_id, question_id) {
            Ok(user_answer) => {
                let is_valid = self.verify_answer(answer, &user_answer.answer_hash)?;
                
                if is_valid {
                    debug!("Resposta de segurança verificada com sucesso ✅");
                } else {
                    debug!("Resposta de segurança incorreta ❌");
                }
                
                Ok(is_valid)
            },
            Err(_) => {
                error!("Resposta de segurança não encontrada para este usuário/pergunta");
                Err(ApiError::NotFound(
                    "Resposta de segurança não encontrada 🔍".to_string()
                ))
            }
        }
    }

    /// Remove uma resposta de segurança específica
    pub fn delete_user_security_answer(
        &self, 
        user_id: &Uuid, 
        question_id: &Uuid
    ) -> Result<(), ApiError> {
        info!("Removendo resposta de segurança para usuário: {}", user_id);
        
        self.repo.delete_user_answer(user_id, question_id)?;
        
        info!("Resposta de segurança removida ✅");
        Ok(())
    }

    /// Remove todas as respostas de segurança de um usuário
    pub fn delete_all_user_security_answers(&self, user_id: &Uuid) -> Result<(), ApiError> {
        info!("Removendo todas as respostas de segurança do usuário: {}", user_id);
        
        self.repo.delete_all_user_answers(user_id)?;
        
        info!("Todas as respostas de segurança do usuário foram removidas ✅");
        Ok(())
    }

    // ----- Métodos auxiliares -----

    /// Cria um hash seguro para a resposta do usuário
    fn hash_answer(&self, answer: &str) -> Result<String, ApiError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(answer.as_bytes(), &salt)
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao gerar hash: {}", e)))?
            .to_string();
        
        Ok(password_hash)
    }

    /// Verifica se a resposta do usuário corresponde ao hash armazenado
    fn verify_answer(&self, answer: &str, hash: &str) -> Result<bool, ApiError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao analisar hash: {}", e)))?;
            
        let argon2 = Argon2::default();
        
        Ok(argon2.verify_password(answer.as_bytes(), &parsed_hash).is_ok())
    }
} 