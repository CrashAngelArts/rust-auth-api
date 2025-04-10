use actix_web::{test, web, App, dev::{Service, ServiceResponse}, http::Request, Error};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use serde_json::json;

use rust_auth_api::{
    config::AppConfig,
    models::auth::{RegisterDto},
    routes,
    services::auth_service::AuthService,
    services::user_service::UserService,
};

async fn setup_test_app(
) -> impl Service<Request, Response = ServiceResponse, Error = Error> {
    // Setup test database
    let conn = Connection::open_in_memory().unwrap();
    let manager = SqliteConnectionManager::memory();
    let pool = Pool::new(manager).unwrap();

    // Initialize services
    let config = AppConfig::new();
    let auth_service = AuthService::new(&pool, &config);
    let user_service = UserService::new(&pool);

    // Create and return test application
    test::init_service(
        App::new()
            .app_data(web::Data::new(pool))
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(auth_service))
            .app_data(web::Data::new(user_service))
            .configure(routes::auth::config)
            .configure(routes::user::config)
    ).await
}

#[actix_rt::test]
async fn test_register_user() {
    let app = setup_test_app().await;

    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success());

    // Then try to login
    let login_req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(&json!({
            "username_or_email": "test@example.com",
            "password": "Test123!"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert!(login_resp.status().is_success());

    let body = test::read_body(login_resp).await;
    let response: serde_json::Value = serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert!(response["success"].as_bool().unwrap());
    assert!(response["data"]["access_token"].is_string());
    assert_eq!(response["data"]["token_type"].as_str().unwrap(), "Bearer");
}

#[actix_rt::test]
async fn test_login_user() {
    let app = setup_test_app().await;

    // First register a test user
    let register_data = RegisterDto {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: "Test123!".to_string(),
    };

    let register_req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(&register_data)
        .to_request();

    let register_resp = test::call_service(&app, register_req).await;
    assert!(register_resp.status().is_success()
