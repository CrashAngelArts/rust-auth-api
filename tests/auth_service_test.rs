use rusqlite::Connection;
use std::sync::Arc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rust_auth_api::{
    db::migrations,
    models::auth::{LoginDto, RegisterDto},
    services::auth_service::AuthService,
};

// Configura um banco de dados em memória para testes
fn setup_test_db() -> Pool<SqliteConnectionManager> {
    let manager = SqliteConnectionManager::memory();
    let pool = Pool::new(manager).expect("❌ Falha ao criar pool de conexão");
    
    // Executa as migrações
    migrations::run_migrations(&pool).expect("❌ Falha ao executar migrações");
    
    pool
}

#[test]
fn test_register_user() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Cria um DTO de registro
    let register_dto = RegisterDto {
        email: "teste@example.com".to_string(),
        username: "usuario_teste".to_string(),
        password: "Senha@123".to_string(),
        confirm_password: "Senha@123".to_string(),
        first_name: Some("Usuário".to_string()),
        last_name: Some("Teste".to_string()),
    };
    
    // Registra o usuário
    let user = AuthService::register(&pool, register_dto, 4).expect("❌ Falha ao registrar usuário");
    
    // Verifica se o usuário foi criado corretamente
    assert_eq!(user.first_name.unwrap(), "Usuário");
    assert_eq!(user.last_name.unwrap(), "Teste");
    assert_eq!(user.email, "teste@example.com");
    assert!(user.is_active);
    assert!(!user.is_admin);
}

#[test]
fn test_login_user() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Registra um usuário
    let register_dto = RegisterDto {
        email: "teste@example.com".to_string(),
        username: "usuario_teste".to_string(),
        password: "Senha@123".to_string(),
        confirm_password: "Senha@123".to_string(),
        first_name: Some("Usuário".to_string()),
        last_name: Some("Teste".to_string()),
    };
    
    AuthService::register(&pool, register_dto, 4).expect("❌ Falha ao registrar usuário");
    
    // Cria um DTO de login
    let login_dto = LoginDto {
        username_or_email: "teste@example.com".to_string(),
        password: "Senha@123".to_string(),
    };
    
    // Faz login
    let auth_response = AuthService::login(
        &pool,
        login_dto,
        "test_secret",
        "1h",
        Some("127.0.0.1".to_string()),
        Some("Test Browser".to_string()),
    )
    .expect("❌ Falha ao fazer login");
    
    // Verifica se o token foi gerado
    assert!(!auth_response.access_token.is_empty());
    assert_eq!(auth_response.token_type, "Bearer");
}

#[test]
fn test_login_invalid_credentials() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Registra um usuário
    let register_dto = RegisterDto {
        email: "teste@example.com".to_string(),
        username: "usuario_teste".to_string(),
        password: "Senha@123".to_string(),
        confirm_password: "Senha@123".to_string(),
        first_name: Some("Usuário".to_string()),
        last_name: Some("Teste".to_string()),
    };
    
    AuthService::register(&pool, register_dto, 4).expect("❌ Falha ao registrar usuário");
    
    // Cria um DTO de login com senha incorreta
    let login_dto = LoginDto {
        username_or_email: "teste@example.com".to_string(),
        password: "senha_incorreta".to_string(),
    };
    
    // Tenta fazer login
    let result = AuthService::login(
        &pool,
        login_dto,
        "test_secret",
        "1h",
        Some("127.0.0.1".to_string()),
        Some("Test Browser".to_string()),
    );
    
    // Verifica se o login falhou
    assert!(result.is_err());
}

#[test]
fn test_validate_token() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Registra um usuário
    let register_dto = RegisterDto {
        email: "teste@example.com".to_string(),
        username: "usuario_teste".to_string(),
        password: "Senha@123".to_string(),
        confirm_password: "Senha@123".to_string(),
        first_name: Some("Usuário".to_string()),
        last_name: Some("Teste".to_string()),
    };
    
    let user = AuthService::register(&pool, register_dto, 4).expect("❌ Falha ao registrar usuário");
    
    // Cria um DTO de login
    let login_dto = LoginDto {
        username_or_email: "teste@example.com".to_string(),
        password: "Senha@123".to_string(),
    };
    
    // Faz login
    let auth_response = AuthService::login(
        &pool,
        login_dto,
        "test_secret",
        "1h",
        Some("127.0.0.1".to_string()),
        Some("Test Browser".to_string()),
    )
    .expect("❌ Falha ao fazer login");
    
    // Valida o token
    let claims = AuthService::validate_token(&auth_response.access_token, "test_secret")
        .expect("❌ Falha ao validar token");
    
    // Verifica se as claims estão corretas
    assert_eq!(claims.sub, user.id);
    assert_eq!(claims.email, user.email);
    assert!(!claims.is_admin);
}
