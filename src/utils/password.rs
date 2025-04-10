// // Função não utilizada
// use rand::{distributions::Alphanumeric, Rng};
// pub fn generate_random_password(length: usize) -> String {
//     rand::thread_rng()
//         .sample_iter(&Alphanumeric)
//         .take(length)
//         .map(char::from)
//         .collect()
// }
// Verifica a força da senha
// Verifica a força da senha e retorna os requisitos não atendidos
pub fn check_password_strength(password: &str) -> Result<(), Vec<String>> {
    let mut unmet_requirements = Vec::new();

    // Requisitos Mínimos (Exemplo)
    let min_length = 8;
    let requires_uppercase = true;
    let requires_lowercase = true;
    let requires_digit = true;
    let requires_special = true;

    if password.len() < min_length {
        unmet_requirements.push(format!("Senha deve ter pelo menos {} caracteres", min_length));
    }
    if requires_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        unmet_requirements.push("Senha deve conter pelo menos uma letra maiúscula".to_string());
    }
    if requires_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        unmet_requirements.push("Senha deve conter pelo menos uma letra minúscula".to_string());
    }
    if requires_digit && !password.chars().any(|c| c.is_digit(10)) {
        unmet_requirements.push("Senha deve conter pelo menos um número".to_string());
    }
    if requires_special && !password.chars().any(|c| !c.is_alphanumeric()) {
        unmet_requirements.push("Senha deve conter pelo menos um caractere especial (ex: !@#$%)".to_string());
    }

    if unmet_requirements.is_empty() {
        Ok(()) // Todos os requisitos foram atendidos
    } else {
        Err(unmet_requirements) // Retorna a lista de requisitos não atendidos
    }
}
// // Enum e impl não utilizados após refatoração de check_password_strength
// #[derive(Debug, PartialEq)]
// pub enum PasswordStrength {
//     Weak,
//     Medium,
//     Strong,
//     VeryStrong,
// }
//
// impl PasswordStrength {
//     // Converte para string
//     pub fn as_str(&self) -> &'static str {
//         match self {
//             PasswordStrength::Weak => "fraca",
//             PasswordStrength::Medium => "média",
//             PasswordStrength::Strong => "forte",
//             PasswordStrength::VeryStrong => "muito forte",
//         }
//     }
//
//     // Este método não é mais necessário, pois check_password_strength retorna Result
//     // pub fn meets_requirements(&self) -> bool {
//     //     match self {
//     //         PasswordStrength::Weak => false,
//     //         _ => true,
//     //     }
//     // }
// }
