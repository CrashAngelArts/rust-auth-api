// Imports não utilizados após remoção da trait ValidateExt
// use crate::errors::ApiError;
// use validator::Validate;

// A trait ValidateExt não é mais necessária, pois usamos From<ValidationErrors> diretamente
// pub trait ValidateExt: Validate {
//     fn validate_dto(&self) -> Result<(), ApiError> {
//         // Usa a implementação From<ValidationErrors> para ApiError diretamente
//         self.validate().map_err(ApiError::from)
//     }
// }
//
// // Implementa a extensão para todos os tipos que implementam Validate
// impl<T: Validate> ValidateExt for T {}
