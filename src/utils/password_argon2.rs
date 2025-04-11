use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
use tracing::{error, info};

/// Gera um hash seguro de senha usando Argon2id (mais seguro que bcrypt)
pub fn hash_password(password: &str) -> Result<String, String> {
    // Gera um salt aleatório
    let salt = SaltString::generate(&mut OsRng);
    
    // Configura o Argon2id com parâmetros recomendados
    let argon2 = Argon2::default();
    
    // Gera o hash da senha
    match argon2.hash_password(password.as_bytes(), &salt) {
        Ok(hash) => {
            info!("🔑 Senha hashada com Argon2id com sucesso");
            Ok(hash.to_string())
        },
        Err(e) => {
            error!("❌ Erro ao gerar hash de senha com Argon2id: {}", e);
            Err(format!("Erro ao gerar hash de senha: {}", e))
        }
    }
}

/// Verifica se uma senha corresponde ao hash armazenado
pub fn verify_password(password: &str, hash: &str) -> Result<bool, String> {
    // Faz o parse do hash armazenado
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(e) => {
            error!("❌ Erro ao fazer parse do hash de senha: {}", e);
            return Err(format!("Hash de senha inválido: {}", e));
        }
    };
    
    // Verifica a senha
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => {
            info!("✅ Verificação de senha com Argon2id bem-sucedida");
            Ok(true)
        },
        Err(_) => {
            info!("❌ Verificação de senha com Argon2id falhou - senha incorreta");
            Ok(false)
        }
    }
}

/// Verifica se um hash foi gerado com Argon2
pub fn is_argon2_hash(hash: &str) -> bool {
    hash.starts_with("$argon2")
}
