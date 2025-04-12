use crate::config::Config;
use crate::db::DbPool;
use crate::errors::ApiError;
use crate::models::oauth::{OAuthConnection, OAuthProvider, OAuthUserProfile};
use crate::models::user::{CreateUserDto, User};
use crate::services::user_service::UserService;

use oauth2::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
    basic::BasicClient, AuthUrl,
    reqwest::async_http_client
};
use reqwest::Client as HttpClient;
use rusqlite::params;
use std::sync::Arc;
use uuid::Uuid;

pub struct OAuthService {
    config: Arc<Config>,
    db_pool: DbPool,
    http_client: HttpClient,
}

impl OAuthService {
    pub fn new(config: Arc<Config>, db_pool: DbPool) -> Self {
        Self {
            config,
            db_pool,
            http_client: HttpClient::new(),
        }
    }

    /// Cria URL de autorização para o provedor OAuth especificado
    pub async fn get_authorization_url(&self, provider: OAuthProvider, _state: &str) -> Result<String, ApiError> {
        let client = self.create_oauth_client(provider)?;
        
        // Gera um desafio PKCE para maior segurança
        let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        
        // Armazena o verificador PKCE para uso posterior (em produção, isso seria armazenado em uma sessão)
        // Aqui estamos apenas gerando a URL de autorização
        
        // Gera um token CSRF para proteção contra ataques CSRF
        let (auth_url, _csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();
        
        Ok(auth_url.to_string())
    }

    /// Processa o callback OAuth e retorna o perfil do usuário
    pub async fn process_callback(
        &self,
        provider: OAuthProvider,
        code: &str,
        _state: &str,
    ) -> Result<OAuthUserProfile, ApiError> {
        let client = self.create_oauth_client(provider.clone())?;
        
        // Em uma implementação real, você recuperaria o verificador PKCE da sessão
        // Para este exemplo, estamos ignorando a verificação PKCE
        
        // Troca o código de autorização por um token de acesso
        let token_result = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao trocar código por token: {}", e)))?;
        
        // Obtém o perfil do usuário usando o token de acesso
        let user_profile = self.get_user_profile(provider, token_result.access_token().secret()).await?;
        
        Ok(user_profile)
    }

    /// Obtém o perfil do usuário do provedor OAuth
    async fn get_user_profile(
        &self,
        provider: OAuthProvider,
        access_token: &str,
    ) -> Result<OAuthUserProfile, ApiError> {
        match provider {
            OAuthProvider::Google => self.get_google_profile(access_token).await,
            OAuthProvider::Facebook => self.get_facebook_profile(access_token).await,
            OAuthProvider::Microsoft => self.get_microsoft_profile(access_token).await,
            OAuthProvider::GitHub => self.get_github_profile(access_token).await,
            OAuthProvider::Apple => self.get_apple_profile(access_token).await,
        }
    }

    /// Obtém o perfil do usuário do Google
    async fn get_google_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> {
        let response = self.http_client
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao obter perfil do Google: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(ApiError::InternalServerError(format!(
                "Erro ao obter perfil do Google: {}",
                response.status()
            )));
        }
        
        let data = response.json::<serde_json::Value>().await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao analisar resposta do Google: {}", e)))?;
        
        Ok(OAuthUserProfile {
            provider: OAuthProvider::Google,
            provider_user_id: data["sub"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["given_name"].as_str().map(|s| s.to_string()),
            last_name: data["family_name"].as_str().map(|s| s.to_string()),
            display_name: data["name"].as_str().map(|s| s.to_string()),
            picture: data["picture"].as_str().map(|s| s.to_string()),
            locale: data["locale"].as_str().map(|s| s.to_string()),
        })
    }

    /// Obtém o perfil do usuário do Facebook
    async fn get_facebook_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> {
        let response = self.http_client
            .get("https://graph.facebook.com/v18.0/me")
            .query(&[
                ("fields", "id,email,name,first_name,last_name,picture"),
                ("access_token", access_token),
            ])
            .send()
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao obter perfil do Facebook: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(ApiError::InternalServerError(format!(
                "Erro ao obter perfil do Facebook: {}",
                response.status()
            )));
        }
        
        let data = response.json::<serde_json::Value>().await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao analisar resposta do Facebook: {}", e)))?;
        
        Ok(OAuthUserProfile {
            provider: OAuthProvider::Facebook,
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(|s| s.to_string()),
            name: data["name"].as_str().map(|s| s.to_string()),
            first_name: data["first_name"].as_str().map(|s| s.to_string()),
            last_name: data["last_name"].as_str().map(|s| s.to_string()),
            display_name: data["name"].as_str().map(|s| s.to_string()),
            picture: data["picture"]["data"]["url"].as_str().map(|s| s.to_string()),
            locale: None,
        })
    }

    /// Obtém o perfil do usuário do Microsoft
    async fn get_microsoft_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> {
        let response = self.http_client
            .get("https://graph.microsoft.com/v1.0/me")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao obter perfil do Microsoft: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(ApiError::InternalServerError(format!(
                "Erro ao obter perfil do Microsoft: {}",
                response.status()
            )));
        }
        
        let data = response.json::<serde_json::Value>().await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao analisar resposta do Microsoft: {}", e)))?;
        
        Ok(OAuthUserProfile {
            provider: OAuthProvider::Microsoft,
            provider_user_id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["mail"].as_str().or(data["userPrincipalName"].as_str()).map(|s| s.to_string()),
            name: data["displayName"].as_str().map(|s| s.to_string()),
            first_name: data["givenName"].as_str().map(|s| s.to_string()),
            last_name: data["surname"].as_str().map(|s| s.to_string()),
            display_name: data["displayName"].as_str().map(|s| s.to_string()),
            picture: None, // Microsoft Graph requer uma chamada separada para obter a foto
            locale: data["preferredLanguage"].as_str().map(|s| s.to_string()),
        })
    }

    /// Obtém o perfil do usuário do GitHub
    async fn get_github_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> {
        // Obter informações básicas do usuário
        let user_response = self.http_client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("User-Agent", "Rust-Auth-API")
            .send()
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao obter perfil do GitHub: {}", e)))?;
        
        if !user_response.status().is_success() {
            return Err(ApiError::InternalServerError(format!(
                "Erro ao obter perfil do GitHub: {}",
                user_response.status()
            )));
        }
        
        let user_data = user_response.json::<serde_json::Value>().await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao analisar resposta do GitHub: {}", e)))?;
        
        // Obter email do usuário (pode ser privado, então é uma chamada separada)
        let email_response = self.http_client
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("User-Agent", "Rust-Auth-API")
            .send()
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Erro ao obter emails do GitHub: {}", e)))?;
        
        let mut primary_email = None;
        
        if email_response.status().is_success() {
            let emails = email_response.json::<Vec<serde_json::Value>>().await
                .map_err(|e| ApiError::InternalServerError(format!("Erro ao analisar emails do GitHub: {}", e)))?;
            
            // Encontrar o email primário
            for email in emails {
                if email["primary"].as_bool().unwrap_or(false) {
                    primary_email = email["email"].as_str().map(|s| s.to_string());
                    break;
                }
            }
        }
        
        // Se não encontrou um email primário, tenta usar o email público
        let email = primary_email.or_else(|| user_data["email"].as_str().map(|s| s.to_string()));
        
        let name = user_data["name"].as_str().map(|s| s.to_string());
        let login = user_data["login"].as_str().map(|s| s.to_string());
        
        Ok(OAuthUserProfile {
            provider: OAuthProvider::GitHub,
            provider_user_id: {
                // Primeiro tentamos obter como string
                if let Some(id_str) = user_data["id"].as_str() {
                    id_str.to_string()
                } else if let Some(id_num) = user_data["id"].as_u64() {
                    // Se não for string, tentamos como número
                    id_num.to_string()
                } else {
                    // Caso contrário, retornamos string vazia
                    String::new()
                }
            },
            email,
            name: name.clone(),
            first_name: None, // GitHub não fornece nome separado
            last_name: None,
            display_name: name.or(login),
            picture: user_data["avatar_url"].as_str().map(|s| s.to_string()),
            locale: None,
        })
    }

    /// Obtém o perfil do usuário da Apple
    pub async fn get_apple_profile(&self, _access_token: &str) -> Result<OAuthUserProfile, ApiError> {
        // Apple não fornece um endpoint de perfil padrão
        // As informações do usuário são enviadas apenas uma vez durante o login inicial
        // Normalmente, você armazenaria essas informações quando recebidas
        // Para este exemplo, estamos retornando um perfil mínimo com o ID
        
        // Em uma implementação real, você decodificaria o ID token para obter informações do usuário
        // O ID token é um JWT que contém claims sobre o usuário
        
        Err(ApiError::InternalServerError("Implementação do Apple Sign In requer tratamento especial do ID token".to_string()))
    }

    /// Cria ou atualiza um usuário com base no perfil OAuth
    pub async fn process_oauth_login(&self, profile: OAuthUserProfile) -> Result<User, ApiError> {
        // Verificar se já existe uma conexão OAuth para este provedor/usuário
        let connection = self.find_oauth_connection(&profile.provider, &profile.provider_user_id)?;
        
        if let Some(connection) = connection {
            // Conexão existente, retornar o usuário associado
            let user = UserService::get_user_by_id(&self.db_pool, &connection.user_id)?;
            return Ok(user);
        }
        
        // Verificar se existe um usuário com o mesmo email
        if let Some(email) = &profile.email {
            if let Ok(user) = UserService::get_user_by_email(&self.db_pool, email) {
                // Usuário existente, criar conexão OAuth
                self.create_oauth_connection(&user.id, &profile)?;
                return Ok(user);
            }
        }
        
        // Obter configuração de salt rounds
        let salt_rounds = self.config.security.password_salt_rounds;
        
        // Criar um novo usuário
        let username = profile.email.clone()
            .or_else(|| Some(format!("{}_{}", profile.provider.to_string().to_lowercase(), profile.provider_user_id)))
            .unwrap();
        
        let _display_name = profile.display_name.clone()
            .or_else(|| profile.name.clone())
            .unwrap_or_else(|| username.clone());
        
        // Gerar uma senha aleatória para o usuário (eles podem alterá-la mais tarde)
        let password = Uuid::new_v4().to_string();
        
        let create_user_dto = CreateUserDto {
            email: profile.email.clone().unwrap_or_else(|| format!("{}@example.com", Uuid::new_v4())),
            username,
            password,
            first_name: Some(profile.first_name.clone().unwrap_or_else(|| "".to_string())),
            last_name: Some(profile.last_name.clone().unwrap_or_else(|| "".to_string())),
            recovery_email: None,
        };
        
        let user = UserService::create_user(&self.db_pool, create_user_dto, salt_rounds)?;
        
        // Criar conexão OAuth
        self.create_oauth_connection(&user.id, &profile)?;
        
        Ok(user)
    }

    /// Encontra uma conexão OAuth existente
    fn find_oauth_connection(&self, provider: &OAuthProvider, provider_user_id: &str) -> Result<Option<OAuthConnection>, ApiError> {
        let conn = self.db_pool.get()
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        let query = "SELECT * FROM oauth_connections WHERE provider = ?1 AND provider_user_id = ?2";
        
        let mut stmt = conn.prepare(query)
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        let connection = stmt.query_row(
            params![provider.to_string(), provider_user_id],
            |row| {
                Ok(OAuthConnection {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    provider: OAuthProvider::from(row.get::<_, String>(2)?.as_str()),
                    provider_user_id: row.get(3)?,
                    email: row.get(4)?,
                    name: row.get(5)?,
                    access_token: row.get(6)?,
                    refresh_token: row.get(7)?,
                    token_expires_at: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            },
        );
        
        match connection {
            Ok(connection) => Ok(Some(connection)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ApiError::DatabaseError(e.to_string())),
        }
    }

    /// Cria uma nova conexão OAuth
    fn create_oauth_connection(&self, user_id: &str, profile: &OAuthUserProfile) -> Result<OAuthConnection, ApiError> {
        let conn = self.db_pool.get()
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        let oauth_connection = OAuthConnection::new(user_id, profile);
        
        let query = "INSERT INTO oauth_connections 
            (id, user_id, provider, provider_user_id, email, name, access_token, refresh_token, token_expires_at, created_at, updated_at) 
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
        
        conn.execute(
            query,
            params![
                oauth_connection.id,
                oauth_connection.user_id,
                oauth_connection.provider.to_string(),
                oauth_connection.provider_user_id,
                oauth_connection.email,
                oauth_connection.name,
                oauth_connection.access_token,
                oauth_connection.refresh_token,
                oauth_connection.token_expires_at,
                oauth_connection.created_at,
                oauth_connection.updated_at,
            ],
        )
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        Ok(oauth_connection)
    }

    /// Lista todas as conexões OAuth de um usuário
    pub fn list_user_oauth_connections(&self, user_id: &str) -> Result<Vec<OAuthConnection>, ApiError> {
        let conn = self.db_pool.get()
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        let query = "SELECT * FROM oauth_connections WHERE user_id = ?1";
        
        let mut stmt = conn.prepare(query)
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        let connections = stmt.query_map(
            params![user_id],
            |row| {
                Ok(OAuthConnection {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    provider: OAuthProvider::from(row.get::<_, String>(2)?.as_str()),
                    provider_user_id: row.get(3)?,
                    email: row.get(4)?,
                    name: row.get(5)?,
                    access_token: row.get(6)?,
                    refresh_token: row.get(7)?,
                    token_expires_at: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            },
        )
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        let mut result = Vec::new();
        for connection in connections {
            result.push(connection.map_err(|e| ApiError::DatabaseError(e.to_string()))?);
        }
        
        Ok(result)
    }

    /// Remove uma conexão OAuth
    pub fn remove_oauth_connection(&self, user_id: &str, connection_id: &str) -> Result<(), ApiError> {
        let conn = self.db_pool.get()
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        let query = "DELETE FROM oauth_connections WHERE id = ?1 AND user_id = ?2";
        
        conn.execute(query, params![connection_id, user_id])
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?;
        
        Ok(())
    }

    /// Cria um cliente OAuth para o provedor especificado
    fn create_oauth_client(&self, provider: OAuthProvider) -> Result<BasicClient, ApiError> {
        match provider {
            OAuthProvider::Google => {
                let google_client_id = self.config.oauth.google_client_id.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Google Client ID não configurado".to_string()))?;
                
                let google_client_secret = self.config.oauth.google_client_secret.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Google Client Secret não configurado".to_string()))?;
                
                let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de autorização inválida: {}", e)))?;
                
                let token_url = TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de token inválida: {}", e)))?;
                
                let redirect_url = RedirectUrl::new(self.config.oauth.redirect_url.clone())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de redirecionamento inválida: {}", e)))?;
                
                Ok(BasicClient::new(
                    ClientId::new(google_client_id),
                    Some(ClientSecret::new(google_client_secret)),
                    auth_url,
                    Some(token_url),
                ).set_redirect_uri(redirect_url))
            },
            OAuthProvider::Facebook => {
                let facebook_client_id = self.config.oauth.facebook_client_id.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Facebook Client ID não configurado".to_string()))?;
                
                let facebook_client_secret = self.config.oauth.facebook_client_secret.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Facebook Client Secret não configurado".to_string()))?;
                
                let auth_url = AuthUrl::new("https://www.facebook.com/v18.0/dialog/oauth".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de autorização inválida: {}", e)))?;
                
                let token_url = TokenUrl::new("https://graph.facebook.com/v18.0/oauth/access_token".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de token inválida: {}", e)))?;
                
                let redirect_url = RedirectUrl::new(self.config.oauth.redirect_url.clone())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de redirecionamento inválida: {}", e)))?;
                
                Ok(BasicClient::new(
                    ClientId::new(facebook_client_id),
                    Some(ClientSecret::new(facebook_client_secret)),
                    auth_url,
                    Some(token_url),
                ).set_redirect_uri(redirect_url))
            },
            OAuthProvider::Microsoft => {
                let microsoft_client_id = self.config.oauth.microsoft_client_id.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Microsoft Client ID não configurado".to_string()))?;
                
                let microsoft_client_secret = self.config.oauth.microsoft_client_secret.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Microsoft Client Secret não configurado".to_string()))?;
                
                let auth_url = AuthUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de autorização inválida: {}", e)))?;
                
                let token_url = TokenUrl::new("https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de token inválida: {}", e)))?;
                
                let redirect_url = RedirectUrl::new(self.config.oauth.redirect_url.clone())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de redirecionamento inválida: {}", e)))?;
                
                Ok(BasicClient::new(
                    ClientId::new(microsoft_client_id),
                    Some(ClientSecret::new(microsoft_client_secret)),
                    auth_url,
                    Some(token_url),
                ).set_redirect_uri(redirect_url))
            },
            OAuthProvider::GitHub => {
                let github_client_id = self.config.oauth.github_client_id.clone()
                    .ok_or_else(|| ApiError::BadRequestError("GitHub Client ID não configurado".to_string()))?;
                
                let github_client_secret = self.config.oauth.github_client_secret.clone()
                    .ok_or_else(|| ApiError::BadRequestError("GitHub Client Secret não configurado".to_string()))?;
                
                let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de autorização inválida: {}", e)))?;
                
                let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de token inválida: {}", e)))?;
                
                let redirect_url = RedirectUrl::new(self.config.oauth.redirect_url.clone())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de redirecionamento inválida: {}", e)))?;
                
                Ok(BasicClient::new(
                    ClientId::new(github_client_id),
                    Some(ClientSecret::new(github_client_secret)),
                    auth_url,
                    Some(token_url),
                ).set_redirect_uri(redirect_url))
            },
            OAuthProvider::Apple => {
                let apple_client_id = self.config.oauth.apple_client_id.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Apple Client ID não configurado".to_string()))?;
                
                let apple_client_secret = self.config.oauth.apple_client_secret.clone()
                    .ok_or_else(|| ApiError::BadRequestError("Apple Client Secret não configurado".to_string()))?;
                
                let auth_url = AuthUrl::new("https://appleid.apple.com/auth/authorize".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de autorização inválida: {}", e)))?;
                
                let token_url = TokenUrl::new("https://appleid.apple.com/auth/token".to_string())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de token inválida: {}", e)))?;
                
                let redirect_url = RedirectUrl::new(self.config.oauth.redirect_url.clone())
                    .map_err(|e| ApiError::BadRequestError(format!("URL de redirecionamento inválida: {}", e)))?;
                
                Ok(BasicClient::new(
                    ClientId::new(apple_client_id),
                    Some(ClientSecret::new(apple_client_secret)),
                    auth_url,
                    Some(token_url),
                ).set_redirect_uri(redirect_url))
            },
        }
    }
}
