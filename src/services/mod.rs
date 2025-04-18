pub mod auth_service;
pub mod email_service;
pub mod user_service;
pub mod two_factor_service;
pub mod token_service;
pub mod keystroke_service;
pub mod keystroke_security_service;
pub mod email_verification_service;
pub mod device_service;
pub mod recovery_email_service;
pub mod oauth_service;
pub mod rbac_service;
pub mod webhook_service;
pub mod webauthn_service;
pub mod recovery_code_service;
pub mod location_risk_service;
pub mod time_pattern_service;
pub mod session_policy_service;
pub mod audit_log_service;


// Re-exportar structs/enums para facilitar imports externos
// Estes exports são utilizados principalmente no main.rs e em outros módulos
// Mantido para consistência e possível uso futuro
pub use rbac_service::RbacService;
pub mod security_question_service; 
pub use security_question_service::SecurityQuestionService; 
pub use audit_log_service::AuditLogService;
