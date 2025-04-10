use rusqlite::Connection;
use std::sync::Arc;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rust_auth_api::{
    db::migrations,
    models::{
        auth::RegisterDto,
        user::{ChangePasswordDto, UpdateUserDto},
    },
    services::{auth_service::AuthService, user_service::UserService},
};

// Configura um banco de dados em memória para testes
fn setup_test_db() -> Pool<SqliteConnectionManager> {
    let manager = SqliteConnectionManager::memory();
    let pool = Pool::new(manager).expect("❌ Falha ao criar pool de conexão");
    
    // Executa as migrações
    migrations::run_migrations(&pool).expect("❌ Falha ao executar migrações");
    
    pool
}

// Cria um usuário para testes
fn create_test_user(pool: &Pool<SqliteConnectionManager>) -> String {
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
    let user = AuthService::register(pool, register_dto, 4).expect("❌ Falha ao registrar usuário");
    
    user.id
}

#[test]
fn test_get_user_by_id() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Cria um usuário
    let user_id = create_test_user(&pool);
    
    // Obtém o usuário pelo ID
    let user = UserService::get_user_by_id(&pool, &user_id).expect("❌ Falha ao obter usuário");
    
    // Verifica se o usuário foi obtido corretamente
    assert_eq!(user.id, user_id);
    assert_eq!(user.username, "usuario_teste");
    assert_eq!(user.email, "teste@example.com");
}

#[test]
fn test_get_user_by_email() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Cria um usuário
    create_test_user(&pool);
    
    // Obtém o usuário pelo email
    let user = UserService::get_user_by_email(&pool, "teste@example.com").expect("❌ Falha ao obter usuário");
    
    // Verifica se o usuário foi obtido corretamente
    assert_eq!(user.username, "usuario_teste");
    assert_eq!(user.email, "teste@example.com");
}

#[test]
fn test_update_user() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Cria um usuário
    let user_id = create_test_user(&pool);
    
    // Cria um DTO de atualização
    let update_dto = UpdateUserDto {
        username: Some("usuario_atualizado".to_string()),
        first_name: Some("Usuário".to_string()),
        last_name: Some("Atualizado".to_string()),
        email: Some("teste@example.com".to_string()),
        is_active: Some(true),
    };
    
    // Atualiza o usuário
    let updated_user = UserService::update_user(&pool, &user_id, update_dto).expect("❌ Falha ao atualizar usuário");
    
    // Verifica se o usuário foi atualizado corretamente
    assert_eq!(updated_user.id, user_id);
    assert_eq!(updated_user.username, "usuario_atualizado");
    assert_eq!(updated_user.first_name.unwrap(), "Usuário");
    assert_eq!(updated_user.last_name.unwrap(), "Atualizado");
    assert_eq!(updated_user.email, "teste@example.com");
}

#[test]
fn test_change_password() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Cria um usuário
    let user_id = create_test_user(&pool);
    
    // Cria um DTO de alteração de senha
    let change_dto = ChangePasswordDto {
        current_password: "Senha@123".to_string(),
        new_password: "NovaSenha@123".to_string(),
        confirm_password: "NovaSenha@123".to_string(),
    };
    
    // Altera a senha
    UserService::change_password(&pool, &user_id, change_dto, 4).expect("❌ Falha ao alterar senha");
    
    // Verifica se a senha foi alterada tentando fazer login
    let login_dto = rust_auth_api::models::auth::LoginDto {
        username_or_email: "teste@example.com".to_string(),
        password: "NovaSenha@123".to_string(),
    };
    
    let auth_response = AuthService::login(
        &pool,
        login_dto,
        "test_secret",
        "1h",
        Some("127.0.0.1".to_string()),
        Some("Test Browser".to_string()),
    );
    
    assert!(auth_response.is_ok());
}

#[test]
fn test_list_users() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Cria alguns usuários
    create_test_user(&pool);
    
    // Registra outro usuário
    let register_dto = RegisterDto {
        email: "outro@example.com".to_string(),
        username: "outro_usuario".to_string(),
        password: "Senha@123".to_string(),
        confirm_password: "Senha@123".to_string(),
        first_name: Some("Outro".to_string()),
        last_name: Some("Usuário".to_string()),
    };
    
    AuthService::register(&pool, register_dto, 4).expect("❌ Falha ao registrar usuário");
    
    // Lista os usuários
    let (users, total) = UserService::list_users(&pool, 1, 10).expect("❌ Falha ao listar usuários");
    
    // Verifica se os usuários foram listados corretamente
    assert_eq!(total, 2);
    assert_eq!(users.len(), 2);
    assert!(users.iter().any(|u| u.email == "teste@example.com"));
    assert!(users.iter().any(|u| u.email == "outro@example.com"));
}

#[test]
fn test_delete_user() {
    // Configura o banco de dados
    let pool = setup_test_db();
    
    // Cria um usuário
    let user_id = create_test_user(&pool);
    
    // Remove o usuário
    UserService::delete_user(&pool, &user_id).expect("❌ Falha ao remover usuário");
    
    // Tenta obter o usuário
    let result = UserService::get_user_by_id(&pool, &user_id);
    
    // Verifica se o usuário foi removido
    assert!(result.is_err());
}
