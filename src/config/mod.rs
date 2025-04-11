use dotenv::dotenv;
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub jwt: JwtConfig,
    pub email: EmailConfig,
    pub security: SecurityConfig,
    pub cors: CorsConfig,
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
    pub rate_limit_requests: u32,
    pub rate_limit_duration: u32,
    // Novas configurações para bloqueio de login
    pub max_login_attempts: u32,
    pub lockout_duration_seconds: u64, // Usar u64 para durações potencialmente longas
    pub unlock_token_duration_minutes: u64, // Duração do token de desbloqueio
    
    // Configurações para keystroke dynamics
    pub keystroke_threshold: Option<u8>,             // Limiar de similaridade para verificação de keystroke
    pub keystroke_rate_limit_requests: Option<usize>, // Número máximo de tentativas de verificação
    pub keystroke_rate_limit_duration: Option<u64>,  // Duração da janela de rate limiting em segundos
    pub keystroke_block_duration: Option<u64>,       // Duração do bloqueio após exceder o limite
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    pub allowed_origins: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, env::VarError> {
        dotenv().ok();

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
            expiration: env::var("JWT_EXPIRATION").unwrap_or_else(|_| "1h".to_string()), // Reduzir expiração padrão do access token
            refresh_expiration_days: env::var("JWT_REFRESH_EXPIRATION_DAYS")
                .unwrap_or_else(|_| "7".to_string()) // Padrão: 7 dias
                .parse()
                .unwrap_or(7),
        };

        let email = EmailConfig {
            smtp_server: env::var("SMTP_SERVER").unwrap_or_else(|_| "smtp.example.com".to_string()), // Usar um placeholder genérico
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .unwrap_or(587),
            username: env::var("EMAIL_USERNAME")?,
            password: env::var("EMAIL_PASSWORD")?,
            from: env::var("EMAIL_FROM")?,
            from_name: env::var("EMAIL_FROM_NAME").unwrap_or_else(|_| "API de Autenticação".to_string()),
            base_url: env::var("EMAIL_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string()), // URL base para links
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
            rate_limit_requests: env::var("RATE_LIMIT_REQUESTS")
                .unwrap_or_else(|_| "100".to_string())
                .parse()
                .unwrap_or(100),
            rate_limit_duration: env::var("RATE_LIMIT_DURATION")
                .unwrap_or_else(|_| "60".to_string())
                .parse()
                .unwrap_or(60),
            // Carregar novas configurações de bloqueio
            max_login_attempts: env::var("MAX_LOGIN_ATTEMPTS")
                .unwrap_or_else(|_| "5".to_string()) // Padrão: 5 tentativas
                .parse()
                .unwrap_or(5),
            lockout_duration_seconds: env::var("LOCKOUT_DURATION_SECONDS")
                .unwrap_or_else(|_| "3600".to_string()) // Padrão: 3600 segundos (1 hora)
                .parse()
                .unwrap_or(3600),
            unlock_token_duration_minutes: env::var("UNLOCK_TOKEN_DURATION_MINUTES")
                .unwrap_or_else(|_| "30".to_string()) // Padrão: 30 minutos
                .parse()
                .unwrap_or(30),
            
            // Carregar configurações para keystroke dynamics
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
        };

        let cors = CorsConfig {
            allowed_origins: env::var("CORS_ALLOWED_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000,http://localhost:8080".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        };

        Ok(Config {
            server,
            database,
            jwt,
            email,
            security,
            cors,
        })
    }
}

pub fn load_config() -> Result<Config, env::VarError> {
    Config::from_env()
}
