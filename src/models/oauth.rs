use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tipos de provedores OAuth suportados
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OAuthProvider {
    Google,
    Facebook,
    Microsoft,
    GitHub,
    Apple,
}

impl std::fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProvider::Google => write!(f, "Google"),
            OAuthProvider::Facebook => write!(f, "Facebook"),
            OAuthProvider::Microsoft => write!(f, "Microsoft"),
            OAuthProvider::GitHub => write!(f, "GitHub"),
            OAuthProvider::Apple => write!(f, "Apple"),
        }
    }
}

impl From<&str> for OAuthProvider {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "google" => OAuthProvider::Google,
            "facebook" => OAuthProvider::Facebook,
            "microsoft" => OAuthProvider::Microsoft,
            "github" => OAuthProvider::GitHub,
            "apple" => OAuthProvider::Apple,
            _ => panic!("Provedor OAuth não suportado: {}", s),
        }
    }
}

/// DTO para iniciar o processo de login OAuth
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthLoginRequest {
    pub provider: OAuthProvider,
    pub redirect_uri: Option<String>,
}

/// DTO para callback OAuth
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthCallbackRequest {
    pub code: String,
    pub state: Option<String>,
    pub provider: Option<String>,
}

/// Resposta com URL de autorização
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthUrlResponse {
    pub authorization_url: String,
    pub state: String,
}

/// Informações do perfil do usuário OAuth
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OAuthUserProfile {
    pub provider: OAuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub picture: Option<String>,
    pub locale: Option<String>,
}

/// Modelo para armazenar conexões OAuth no banco de dados
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthConnection {
    pub id: String,
    pub user_id: String,
    pub provider: OAuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_expires_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl OAuthConnection {
    pub fn new(user_id: &str, profile: &OAuthUserProfile) -> Self {
        let now = chrono::Utc::now().timestamp();
        
        Self {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            provider: profile.provider.clone(),
            provider_user_id: profile.provider_user_id.clone(),
            email: profile.email.clone(),
            name: profile.name.clone(),
            access_token: None,
            refresh_token: None,
            token_expires_at: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Resposta para listagem de conexões OAuth
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthConnectionResponse {
    pub id: String,
    pub provider: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub connected_at: i64,
}

impl From<&OAuthConnection> for OAuthConnectionResponse {
    fn from(conn: &OAuthConnection) -> Self {
        Self {
            id: conn.id.clone(),
            provider: conn.provider.to_string(),
            email: conn.email.clone(),
            name: conn.name.clone(),
            connected_at: conn.created_at,
        }
    }
}

/// Mensagem de erro para OAuth
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthErrorResponse {
    pub error: String,
    pub error_description: Option<String>,
}
