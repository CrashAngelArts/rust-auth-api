use dotenv::dotenv;
use serde::Deserialize;
use std::env;
use tracing::{info, error};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub email: EmailConfig,
    pub security: SecurityConfig,
    pub cors: CorsConfig,
    pub oauth: OAuthConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub expiration: String, // Duração do access token (ex: "1h", "15m")
    pub refresh_expiration_days: i64, // Duração do refresh token em dias
}

#[derive(Debug, Deserialize, Clone)]
pub struct EmailConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub from_name: String,
    pub base_url: String, // URL base para links em emails (ex: desbloqueio)
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub password_salt_rounds: u32,
    pub use_argon2: Option<bool>,
    pub rate_limit_capacity: u32,
    pub rate_limit_refill_rate: f64,
    pub max_login_attempts: u32,
    pub lockout_duration_seconds: u64,
    pub unlock_token_duration_minutes: u64,
    
    pub keystroke_threshold: Option<u8>,
    pub keystroke_rate_limit_requests: Option<u32>,
    pub keystroke_rate_limit_duration: Option<u64>,
    pub keystroke_block_duration: Option<u64>,
    
    pub email_verification_enabled: bool,
    pub csrf_secret: String,
    pub session_max_active: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

// Configurações OAuth
#[derive(Debug, Deserialize, Clone)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub redirect_url: String,
    
    // Google OAuth
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub google_enabled: bool,
    
    // Facebook OAuth
    pub facebook_client_id: Option<String>,
    pub facebook_client_secret: Option<String>,
    pub facebook_enabled: bool,
    
    // Microsoft OAuth
    pub microsoft_client_id: Option<String>,
    pub microsoft_client_secret: Option<String>,
    pub microsoft_enabled: bool,
    
    // GitHub OAuth
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub github_enabled: bool,
    
    // Apple OAuth
    pub apple_client_id: Option<String>,
    pub apple_client_secret: Option<String>,
    pub apple_team_id: Option<String>,
    pub apple_key_id: Option<String>,
    pub apple_private_key_path: Option<String>,
    pub apple_enabled: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, env::VarError> {
        // Tenta carregar .env e loga o resultado
        match dotenv() {
            Ok(path) => info!("✅ Arquivo .env carregado de: {:?}", path),
            Err(e) => info!("⚠️ Não foi possível carregar o arquivo .env: {}. Usando variáveis de ambiente existentes.", e),
        };

        // Log para verificar as variáveis obrigatórias ANTES de tentar usá-las
        info!("🔍 Verificando variáveis de ambiente obrigatórias...");
        info!("  JWT_SECRET presente: {}", env::var("JWT_SECRET").is_ok());
        info!("  EMAIL_USERNAME presente: {}", env::var("EMAIL_USERNAME").is_ok());
        info!("  EMAIL_PASSWORD presente: {}", env::var("EMAIL_PASSWORD").is_ok());
        info!("  EMAIL_FROM presente: {}", env::var("EMAIL_FROM").is_ok());
        info!("  CSRF_SECRET presente: {}", env::var("CSRF_SECRET").is_ok());
        info!("🔍 Verificação concluída.");

        let server = ServerConfig {
            host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
        };

        let database = DatabaseConfig {
            url: env::var("DATABASE_URL").unwrap_or_else(|_| "./data/auth.db".to_string()),
        };

        let jwt = JwtConfig {
            secret: env::var("JWT_SECRET")?,
            expiration: env::var("JWT_EXPIRATION").unwrap_or_else(|_| "1h".to_string()),
            refresh_expiration_days: env::var("JWT_REFRESH_EXPIRATION_DAYS")
                .unwrap_or_else(|_| "7".to_string())
                .parse()
                .unwrap_or(7),
        };

        let email = EmailConfig {
            smtp_server: env::var("SMTP_SERVER").unwrap_or_else(|_| "smtp.example.com".to_string()),
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .unwrap_or(587),
            username: env::var("EMAIL_USERNAME")?,
            password: env::var("EMAIL_PASSWORD")?,
            from: env::var("EMAIL_FROM")?,
            from_name: env::var("EMAIL_FROM_NAME").unwrap_or_else(|_| "API de Autenticação".to_string()),
            base_url: env::var("EMAIL_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()),
            enabled: env::var("EMAIL_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        };

        let security = SecurityConfig {
            password_salt_rounds: env::var("PASSWORD_SALT_ROUNDS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            use_argon2: env::var("USE_ARGON2").ok().and_then(|v| v.parse().ok()),
            rate_limit_capacity: env::var("RATE_LIMIT_CAPACITY")
                .unwrap_or_else(|_| "100".to_string())
                .parse::<u32>()
                .map_err(|e| {
                    error!("Falha ao parsear RATE_LIMIT_CAPACITY: {}. Usando padrão 100.", e);
                    env::VarError::NotPresent
                })
                .unwrap_or(100),
            rate_limit_refill_rate: env::var("RATE_LIMIT_REFILL_RATE")
                .unwrap_or_else(|_| "10.0".to_string())
                .parse::<f64>()
                .map_err(|e| {
                    error!("Falha ao parsear RATE_LIMIT_REFILL_RATE: {}. Usando padrão 10.0.", e);
                    env::VarError::NotPresent
                })
                .unwrap_or(10.0),
            max_login_attempts: env::var("MAX_LOGIN_ATTEMPTS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            lockout_duration_seconds: env::var("LOCKOUT_DURATION_SECONDS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600),
            unlock_token_duration_minutes: env::var("UNLOCK_TOKEN_DURATION_MINUTES")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .unwrap_or(30),
            
            keystroke_threshold: env::var("SECURITY_KEYSTROKE_THRESHOLD")
                .ok()
                .and_then(|v| v.parse().ok()),
            keystroke_rate_limit_requests: env::var("SECURITY_RATE_LIMIT_REQUESTS")
                .ok()
                .and_then(|v| v.parse().ok()),
            keystroke_rate_limit_duration: env::var("SECURITY_RATE_LIMIT_DURATION")
                .ok()
                .and_then(|v| v.parse().ok()),
            keystroke_block_duration: env::var("SECURITY_BLOCK_DURATION")
                .ok()
                .and_then(|v| v.parse().ok()),
                
            email_verification_enabled: env::var("EMAIL_VERIFICATION_ENABLED")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
            csrf_secret: env::var("CSRF_SECRET")?,
            session_max_active: env::var("SESSION_MAX_ACTIVE")
                .ok()
                .and_then(|v| v.parse().ok()),
        };

        let cors = CorsConfig {
            allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        };
        
        // Configurações OAuth
        let oauth = OAuthConfig {
            enabled: env::var("OAUTH_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            redirect_url: env::var("OAUTH_REDIRECT_URL")
                .unwrap_or_else(|_| "http://localhost:8080/api/auth/oauth/callback".to_string()),
                
            // Google OAuth
            google_client_id: env::var("GOOGLE_CLIENT_ID").ok(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET").ok(),
            google_enabled: env::var("GOOGLE_OAUTH_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
                
            // Facebook OAuth
            facebook_client_id: env::var("FACEBOOK_CLIENT_ID").ok(),
            facebook_client_secret: env::var("FACEBOOK_CLIENT_SECRET").ok(),
            facebook_enabled: env::var("FACEBOOK_OAUTH_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
                
            // Microsoft OAuth
            microsoft_client_id: env::var("MICROSOFT_CLIENT_ID").ok(),
            microsoft_client_secret: env::var("MICROSOFT_CLIENT_SECRET").ok(),
            microsoft_enabled: env::var("MICROSOFT_OAUTH_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
                
            // GitHub OAuth
            github_client_id: env::var("GITHUB_CLIENT_ID").ok(),
            github_client_secret: env::var("GITHUB_CLIENT_SECRET").ok(),
            github_enabled: env::var("GITHUB_OAUTH_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
                
            // Apple OAuth
            apple_client_id: env::var("APPLE_CLIENT_ID").ok(),
            apple_client_secret: env::var("APPLE_CLIENT_SECRET").ok(),
            apple_team_id: env::var("APPLE_TEAM_ID").ok(),
            apple_key_id: env::var("APPLE_KEY_ID").ok(),
            apple_private_key_path: env::var("APPLE_PRIVATE_KEY_PATH").ok(),
            apple_enabled: env::var("APPLE_OAUTH_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        };

        Ok(Config {
            server,
            database,
            jwt,
            email,
            security,
            cors,
            oauth,
        })
    }
}

pub fn load_config() -> Result<Config, env::VarError> {
    Config::from_env()
}
