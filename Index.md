# Rust Auth API - Project Index 🚀

## Project Structure Overview

Este documento fornece um índice abrangente do projeto da API de Autenticação em Rust, incluindo todos os arquivos, pastas, métodos, funções e uma breve descrição de cada componente.

## Directory Structure

```
rust-auth-api/
├── .cargo/
├── .env
├── .env.example
├── .git/
├── .gitignore
├── Cargo.lock
├── Cargo.toml
├── README.md
├── data/
├── melhorias.md
├── migrations/
├── src/
│   ├── config/
│   │   └── mod.rs
│   ├── controllers/
│   │   ├── auth_controller.rs
│   │   ├── health_controller.rs
│   │   ├── mod.rs
│   │   ├── user_controller.rs
│   │   ├── two_factor_controller.rs
│   │   ├── token_controller.rs
│   │   └── keystroke_controller.rs
│   ├── db/
│   │   └── [database files]
│   ├── errors/
│   │   └── [error handling files]
│   ├── lib.rs
│   ├── main.rs
│   ├── middleware/
│   │   ├── auth.rs
│   │   ├── cors.rs
│   │   ├── error.rs
│   │   ├── logger.rs
│   │   ├── mod.rs
│   │   └── rate_limiter.rs
│   ├── models/
│   │   ├── auth.rs
│   │   ├── mod.rs
│   │   ├── response.rs
│   │   ├── user.rs
│   │   ├── two_factor.rs
│   │   ├── token.rs
│   │   └── keystroke_dynamics.rs
│   ├── routes/
│   │   └── mod.rs
│   ├── services/
│   │   ├── auth_service.rs
│   │   ├── email_service.rs
│   │   ├── mod.rs
│   │   ├── user_service.rs
│   │   ├── two_factor_service.rs
│   │   ├── token_service.rs
│   │   └── keystroke_service.rs
│   └── utils/
│       └── [utility files]
├── target/
├── test_api.py
└── tests/
```

## Core Files

### main.rs
The entry point of the application that initializes and starts the web server.

**Main Functions:**
- `main()`: Initializes the application, loads configuration, sets up database connection, and starts the web server.

### lib.rs
Exports all the modules for use in other parts of the application.

## Modules

### Config Module (`src/config/`)

#### mod.rs
Manages application configuration loaded from environment variables.

**Structs:**
- `Config`: Main configuration container
- `ServerConfig`: Server-specific settings (host, port)
- `DatabaseConfig`: Database connection settings
- `JwtConfig`: JWT authentication settings
- `EmailConfig`: Email service configuration
- `SecurityConfig`: Security settings like password hashing and rate limiting
- `CorsConfig`: CORS policy configuration

**Functions:**
- `Config::from_env()`: Loads configuration from environment variables
- `load_config()`: Helper function to load the configuration

### Controllers Module (`src/controllers/`) 🎮

#### auth_controller.rs
Lida com requisições HTTP relacionadas à autenticação.

**Functions:**
- `register()`: Registra um novo usuário
- `login()`: Autentica um usuário e retorna tokens
- `refresh_token()`: Atualiza token de acesso usando um token de atualização
- `forgot_password()`: Inicia processo de recuperação de senha
- `reset_password()`: Redefine a senha de um usuário
- `unlock_account()`: Desbloqueia uma conta bloqueada
- `me()`: Retorna as informações do usuário autenticado atual

#### two_factor_controller.rs
Lida com requisições HTTP relacionadas à autenticação de dois fatores.

**Functions:**
- `setup_2fa()`: Inicia configuração 2FA e gera QR code
- `enable_2fa()`: Ativa 2FA após verificar código TOTP
- `disable_2fa()`: Desativa 2FA após verificação
- `regenerate_backup_codes()`: Regenera códigos de backup
- `get_2fa_status()`: Obtém status atual do 2FA

#### token_controller.rs
Lida com requisições HTTP relacionadas à rotação de tokens.

**Functions:**
- `rotate_token()`: Rotaciona um token JWT
- `revoke_token()`: Revoga um token específico
- `revoke_all_tokens()`: Revoga todos os tokens de um usuário
- `clean_expired_tokens()`: Limpa tokens expirados da lista negra

#### keystroke_controller.rs
Lida com requisições HTTP relacionadas à análise de ritmo de digitação.

**Functions:**
- `register_keystroke_pattern()`: Registra padrão de digitação
- `verify_keystroke_pattern()`: Verifica padrão durante login
- `toggle_keystroke_verification()`: Habilita/desabilita verificação
- `get_keystroke_status()`: Obtém status da verificação

#### user_controller.rs
Handles user-related HTTP requests.

**Functions:**
- `list_users()`: Lists all users (admin only)
- `get_user()`: Gets a specific user by ID
- `update_user()`: Updates a user's information
- `delete_user()`: Deletes a user (admin only)
- `change_password()`: Changes a user's password

#### health_controller.rs
Handles health check endpoints.

**Functions:**
- `health_check()`: Returns the API health status
- `version()`: Returns the API version information

### Models Module (`src/models/`) 📋

#### user.rs
Define estruturas de dados relacionadas ao usuário.

**Structs:**
- `User`: Entidade principal do usuário com todos os dados
- `CreateUserDto`: Objeto de transferência de dados para criação de usuário
- `UpdateUserDto`: Objeto de transferência de dados para atualizações de usuário
- `ChangePasswordDto`: Objeto de transferência de dados para alterações de senha
- `UserResponse`: Dados do usuário seguros para respostas da API (exclui dados sensíveis)

#### two_factor.rs
Define estruturas de dados para autenticação de dois fatores.

**Structs:**
- `TwoFactorSetupResponse`: Resposta de configuração 2FA com QR code
- `TwoFactorEnabledResponse`: Resposta de ativação 2FA com códigos de backup
- `Enable2FADto`: Objeto para ativar 2FA
- `Verify2FADto`: Objeto para verificar código TOTP
- `Disable2FADto`: Objeto para desativar 2FA

#### token.rs
Define estruturas de dados para rotação de tokens JWT.

**Structs:**
- `TokenClaims`: Claims do token JWT com suporte a família de tokens
- `BlacklistedToken`: Token na lista negra
- `RefreshTokenDto`: Objeto para atualização de token

#### keystroke_dynamics.rs
Define estruturas de dados para análise de ritmo de digitação.

**Structs:**
- `KeystrokeDynamics`: Modelo para armazenar padrões de digitação
- `RegisterKeystrokePatternDto`: Objeto para registrar padrões
- `VerifyKeystrokePatternDto`: Objeto para verificar padrões
- `KeystrokeVerificationResponse`: Resposta de verificação com similaridade
- `KeystrokeStatusResponse`: Status da verificação de ritmo de digitação

**Methods:**
- `User::new()`: Creates a new user
- `User::full_name()`: Returns the user's full name
- `User::is_locked()`: Checks if the user account is locked

#### auth.rs
Defines authentication-related data structures.

**Structs:**
- `LoginDto`: Data transfer object for login
- `RegisterDto`: Data transfer object for registration
- `RefreshTokenDto`: Data transfer object for token refresh
- `ForgotPasswordDto`: Data transfer object for password recovery
- `ResetPasswordDto`: Data transfer object for password reset
- `UnlockAccountDto`: Data transfer object for account unlocking
- `TokenClaims`: JWT token claims
- `AuthResponse`: Authentication response with tokens
- `Session`: User session information
- `RefreshToken`: Refresh token data
- `PasswordResetToken`: Password reset token data
- `AuthLog`: Authentication event log

#### response.rs
Defines API response structures.

**Structs:**
- `ApiResponse<T>`: Generic API response wrapper

### Services Module (`src/services/`)

#### auth_service.rs
Implements authentication business logic.

**Functions:**
- `register()`: Registers a new user
- `login()`: Authenticates a user
- `forgot_password()`: Initiates password recovery
- `reset_password()`: Resets a user's password
- `refresh_token()`: Refreshes an access token
- `unlock_account()`: Unlocks a locked account
- `validate_token()`: Validates a JWT token
- `generate_jwt()`: Generates a JWT token
- `create_session()`: Creates a new user session
- `log_auth_event()`: Logs authentication events
- `parse_expiration()`: Parses token expiration time
- `save_refresh_token()`: Saves a refresh token
- `find_and_validate_refresh_token()`: Finds and validates a refresh token
- `revoke_refresh_token()`: Revokes a specific refresh token
- `hash_token()`: Hashes a token for secure storage
- `revoke_all_user_refresh_tokens()`: Revokes all refresh tokens for a user

#### email_service.rs
Handles email sending functionality.

**Struct:**
- `EmailService`: Service for sending emails

**Methods:**
- `new()`: Creates a new email service
- `send_welcome_email()`: Sends welcome email to new users
- `send_password_reset_email()`: Sends password reset instructions
- `send_account_locked_email()`: Sends account locked notification
- `send_email()`: Generic method to send emails

#### user_service.rs
Implements user management business logic.

**Functions:**
- `create_user()`: Creates a new user
- `get_user_by_id()`: Retrieves a user by ID
- `get_user_by_email()`: Retrieves a user by email
- `get_user_by_username()`: Retrieves a user by username
- `get_user_by_email_or_username()`: Retrieves a user by email or username
- `update_user()`: Updates a user's information
- `delete_user()`: Deletes a user
- `change_password()`: Changes a user's password
- `hash_password()`: Hashes a password
- `verify_password()`: Verifies a password against its hash
- `list_users()`: Lists all users

#### keystroke_service.rs
Implementa a lógica de negócios para análise de ritmo de digitação.

**Funções:**
- `register_pattern()`: Registra um novo padrão de digitação
- `verify_keystroke_pattern()`: Verifica um padrão durante o login
- `toggle_keystroke_verification()`: Habilita/desabilita verificação
- `get_keystroke_status()`: Obtém o status atual da verificação

#### keystroke_security_service.rs
Implementa monitoramento de segurança e detecção de anomalias para keystroke dynamics.

**Struct:**
- `KeystrokeSecurityService`: Serviço para monitorar tentativas de verificação de keystroke

**Métodos:**
- `record_verification_attempt()`: Registra e analisa tentativas de verificação
- `check_for_suspicious_patterns()`: Detecta anomalias em padrões de digitação
- `check_consecutive_failures()`: Monitora ataques de força bruta
- `calculate_anomaly_score()`: Calcula pontuações de anomalia para padrões de digitação
- `is_user_suspicious()`: Verifica se um usuário está sob suspeita

### Middleware Module (`src/middleware/`)

#### auth.rs
Implements authentication middleware.

**Structs:**
- `JwtAuth`: Middleware for JWT authentication
- `AdminAuth`: Middleware for admin authorization

**Methods:**
- `JwtAuth::new()`: Creates a new JWT authentication middleware
- `AdminAuth::new()`: Creates a new admin authorization middleware

#### cors.rs
Configures CORS (Cross-Origin Resource Sharing) policies.

**Functions:**
- `configure_cors()`: Configures CORS settings based on application config

#### error.rs
Handles error transformation for consistent API responses.

**Struct:**
- `ErrorHandler`: Middleware for consistent error handling

#### logger.rs
Logs HTTP requests and responses.

**Struct:**
- `RequestLogger`: Middleware for request logging

#### rate_limiter.rs
Implements rate limiting to prevent abuse.

**Struct:**
- `RateLimiter`: Middleware for rate limiting requests

**Methods:**
- `RateLimiter::new()`: Creates a new rate limiter with specified limits

#### keystroke_rate_limiter.rs
Implements specialized rate limiting for keystroke dynamics verification.

**Struct:**
- `KeystrokeRateLimiter`: Middleware for rate limiting keystroke verification attempts

**Methods:**
- `KeystrokeRateLimiter::new()`: Creates a new keystroke rate limiter with specified limits
- `clean_keystroke_rate_limit_entries()`: Cleans expired rate limit entries

### Routes Module (`src/routes/`)

#### mod.rs
Configures API routes and middleware.

**Functions:**
- `configure_routes()`: Sets up all API routes with their respective middleware

## API Endpoints

### Authentication Endpoints 🔑
- `POST /api/auth/register`: Registrar um novo usuário
- `POST /api/auth/login`: Autenticar um usuário
- `POST /api/auth/forgot-password`: Solicitar redefinição de senha
- `POST /api/auth/reset-password`: Redefinir senha com token
- `POST /api/auth/unlock`: Desbloquear uma conta bloqueada
- `POST /api/auth/refresh`: Atualizar token de acesso
- `GET /api/auth/me`: Obter informações do usuário atual (requer autenticação)
- `POST /api/auth/token/rotate`: Rotacionar token JWT
- `POST /api/auth/token/revoke`: Revogar token JWT
- `POST /api/auth/revoke-all/{id}`: Revogar todos os tokens (logout de todos os dispositivos)

### User Endpoints 👤
- `GET /api/users`: Listar todos os usuários (somente admin)
- `GET /api/users/{id}`: Obter usuário por ID
- `PUT /api/users/{id}`: Atualizar usuário
- `DELETE /api/users/{id}`: Excluir usuário (somente admin)
- `POST /api/users/{id}/change-password`: Alterar senha do usuário

### Two-Factor Authentication Endpoints 📱
- `GET /api/users/{id}/2fa/setup`: Iniciar configuração 2FA
- `POST /api/users/{id}/2fa/enable`: Ativar 2FA
- `POST /api/users/{id}/2fa/disable`: Desativar 2FA
- `POST /api/users/{id}/2fa/backup-codes`: Regenerar códigos de backup
- `GET /api/users/{id}/2fa/status`: Verificar status do 2FA

### Keystroke Dynamics Endpoints 🎹
- `POST /api/users/{id}/keystroke/register`: Registrar padrão de digitação
- `POST /api/users/{id}/keystroke/verify`: Verificar padrão de digitação (com proteção contra ataques de força bruta)
- `PUT /api/users/{id}/keystroke/toggle`: Habilitar/desabilitar verificação
- `GET /api/users/{id}/keystroke/status`: Verificar status da verificação

### Health Check Endpoints ✅
- `GET /api/health`: Verificar saúde da API
- `GET /api/health/version`: Obter versão da API

### Admin Endpoints 👑
- `POST /api/admin/clean-tokens`: Limpar tokens expirados da lista negra

## Security Features 🔒

1. **JWT Authentication**: Autenticação segura baseada em tokens
2. **Password Hashing**: Armazenamento seguro de senhas com bcrypt e Argon2
3. **Rate Limiting**: Proteção contra ataques de força bruta
4. **Account Locking**: Bloqueio automático de conta após tentativas de login malsucedidas
5. **CORS Protection**: Política de compartilhamento de recursos entre origens configurável
6. **Refresh Tokens**: Mecanismo seguro de atualização de tokens
7. **Admin Authorization**: Controle de acesso baseado em funções
8. **Email Verification**: Verificação opcional de email para ações de segurança
9. **Two-Factor Authentication (2FA)**: Autenticação de dois fatores com TOTP e códigos de backup
10. **Token Rotation**: Rotação de tokens JWT com invalidação baseada em família
11. **Token Blacklist**: Lista negra de tokens para revogação imediata
12. **Keystroke Dynamics**: Análise de ritmo de digitação para verificação biométrica comportamental
13. **Rate Limiting para Keystroke**: Limitação de taxa específica para tentativas de verificação de keystroke
14. **Detecção de Anomalias**: Identificação de padrões anômalos em tentativas de verificação
15. **Proteção contra Força Bruta**: Mecanismos avançados para prevenir ataques de força bruta
16. **Monitoramento de Segurança**: Monitoramento contínuo de atividades suspeitas
