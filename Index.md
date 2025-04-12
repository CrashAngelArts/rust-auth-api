# Rust Auth API - Project Index 

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
│   │   ├── device_controller.rs
│   │   ├── email_verification_controller.rs
│   │   ├── health_controller.rs
│   │   ├── keystroke_controller.rs
│   │   ├── mod.rs
│   │   ├── oauth_controller.rs
│   │   ├── recovery_email_controller.rs
│   │   ├── token_controller.rs
│   │   ├── two_factor_controller.rs
│   │   └── user_controller.rs
│   ├── db/
│   │   └── [database files]
│   ├── errors/
│   │   └── [error handling files]
│   ├── lib.rs
│   ├── main.rs
│   ├── middleware/
│   │   ├── auth.rs
│   │   ├── cors.rs
│   │   ├── email_verification.rs
│   │   ├── error.rs
│   │   ├── keystroke_rate_limiter.rs
│   │   ├── logger.rs
│   │   ├── mod.rs
│   │   ├── rate_limiter.rs
│   │   └── security.rs
│   ├── models/
│   │   ├── auth.rs
│   │   ├── device.rs
│   │   ├── email_verification.rs
│   │   ├── keystroke_dynamics.rs
│   │   ├── mod.rs
│   │   ├── oauth.rs
│   │   ├── recovery_email.rs
│   │   ├── response.rs
│   │   ├── token.rs
│   │   ├── two_factor.rs
│   │   └── user.rs
│   ├── routes/
│   │   └── mod.rs
│   ├── services/
│   │   ├── auth_service.rs
│   │   ├── device_service.rs
│   │   ├── email_service.rs
│   │   ├── email_verification_service.rs
│   │   ├── keystroke_security_service.rs
│   │   ├── keystroke_service.rs
│   │   ├── mod.rs
│   │   ├── oauth_service.rs
│   │   ├── recovery_email_service.rs
│   │   ├── token_service.rs
│   │   ├── two_factor_service.rs
│   │   └── user_service.rs
│   └── utils/
│       └── [utility files]
├── target/
├── test_api.py
└── tests/
```

## Core Files

### main.rs
O ponto de entrada da aplicação que inicializa e inicia o servidor web.

**Funções Principais:**
- `main()`: Inicializa a aplicação, carrega configuração, configura conexão com banco de dados, inicializa serviços (como email) e o cache de validação de token (Moka), e inicia o servidor web.

### lib.rs
Exporta todos os módulos para uso em outras partes da aplicação.

## Modules

### Config Module (`src/config/`)

#### mod.rs
Gerencia a configuração da aplicação carregada de variáveis de ambiente.

**Structs:**
- `Config`: Contêiner principal de configuração
- `ServerConfig`: Configurações específicas do servidor (host, porta)
- `DatabaseConfig`: Configurações de conexão com banco de dados
- `JwtConfig`: Configurações de autenticação JWT
- `EmailConfig`: Configuração do serviço de email
- `SecurityConfig`: Configurações de segurança como hash de senha e rate limiting
- `CorsConfig`: Configuração da política CORS
- `OAuthConfig`: Configurações para autenticação OAuth com provedores sociais

**Functions:**
- `Config::from_env()`: Carrega configuração de variáveis de ambiente
- `load_config()`: Função auxiliar para carregar a configuração

### Controllers Module (`src/controllers/`) 

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

#### device_controller.rs
Lida com requisições HTTP relacionadas ao gerenciamento de dispositivos conectados 

**Functions:**
- `list_devices()`: Lista todos os dispositivos conectados à conta do usuário
- `get_device()`: Obtém detalhes de um dispositivo específico
- `update_device()`: Atualiza informações de um dispositivo (como nome personalizado)
- `revoke_device()`: Revoga acesso de um dispositivo
- `clean_expired_sessions()`: Limpa sessões expiradas (admin)

#### email_verification_controller.rs
Lida com requisições HTTP relacionadas à verificação por email após login.

**Functions:**
- `verify_email_code()`: Verifica um código enviado por email após login 
- `resend_verification_code()`: Reenvia o código de verificação por email 
- `clean_expired_codes()`: Limpa códigos de verificação expirados 

#### recovery_email_controller.rs
Gerencia os emails de recuperação secundários para contas de usuário.

**Functions:**
- `list_recovery_emails()`: Lista todos os emails de recuperação do usuário
- `add_recovery_email()`: Adiciona um novo email de recuperação
- `verify_recovery_email()`: Verifica um email de recuperação recém-adicionado
- `remove_recovery_email()`: Remove um email de recuperação
- `resend_verification_email()`: Reenvia email de verificação para um email de recuperação

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
Lida com requisições HTTP relacionadas aos usuários.

**Functions:**
- `list_users()`: Lista todos os usuários (somente admin)
- `get_user()`: Obtém um usuário específico por ID
- `update_user()`: Atualiza as informações de um usuário
- `delete_user()`: Exclui um usuário (somente admin)
- `change_password()`: Altera a senha de um usuário

#### health_controller.rs
Lida com endpoints de verificação de saúde.

**Functions:**
- `health_check()`: Retorna o status de saúde da API
- `version()`: Retorna as informações de versão da API

#### oauth_controller.rs
Lida com requisições HTTP relacionadas à autenticação OAuth com provedores sociais 

**Functions:**
- `oauth_login()`: Inicia o fluxo de login OAuth redirecionando para o provedor
- `oauth_callback()`: Processa o retorno do provedor OAuth e autentica o usuário
- `list_oauth_connections()`: Lista todas as conexões OAuth de um usuário
- `remove_oauth_connection()`: Remove uma conexão OAuth específica
- `clean_expired_tokens()`: Limpa tokens expirados da lista negra

### Models Module (`src/models/`) 

#### device.rs
Define estruturas de dados para o gerenciamento de dispositivos conectados.

**Structs:**
- `Device`: Dados de um dispositivo conectado
- `DeviceResponse`: Resposta da API com informações do dispositivo
- `UpdateDeviceDto`: DTO para atualizar informações do dispositivo
- `DeviceList`: Lista de dispositivos conectados

#### email_verification.rs
Define estruturas de dados para verificação por email após login.

**Structs:**
- `EmailVerificationCode`: Modelo para armazenar códigos de verificação por email
- `VerifyEmailCodeDto`: DTO para verificar um código
- `EmailVerificationResponse`: Resposta para o status de verificação

**Methods:**
- `EmailVerificationCode::new()`: Cria um novo código de verificação
- `EmailVerificationCode::is_expired()`: Verifica se o código expirou
- `EmailVerificationCode::generate_code()`: Gera um código aleatório de 6 dígitos

#### recovery_email.rs
Define estruturas de dados para emails de recuperação secundários.

**Structs:**
- `RecoveryEmail`: Modelo para email de recuperação
- `RecoveryEmailResponse`: Resposta da API com informações do email de recuperação
- `AddRecoveryEmailDto`: DTO para adicionar um novo email de recuperação
- `VerifyRecoveryEmailDto`: DTO para verificar um email de recuperação

**Methods:**
- `RecoveryEmail::new()`: Cria um novo email de recuperação
- `RecoveryEmail::is_verified()`: Verifica se o email foi verificado
- `RecoveryEmail::generate_verification_code()`: Gera código de verificação

#### user.rs
Define estruturas de dados relacionadas ao usuário.

**Structs:**
- `User`: Entidade principal do usuário com todos os dados
- `CreateUserDto`: DTO para criação de usuário
- `UpdateUserDto`: DTO para atualização de usuário
- `ChangePasswordDto`: DTO para alteração de senha
- `UserResponse`: Dados do usuário seguros para respostas da API (exclui dados sensíveis)

**Methods:**
- `User::new()`: Cria um novo usuário
- `User::full_name()`: Retorna o nome completo do usuário
- `User::is_locked()`: Verifica se a conta do usuário está bloqueada

#### two_factor.rs
Define estruturas de dados para autenticação de dois fatores.

**Structs:**
- `TwoFactorSetupResponse`: Resposta de configuração 2FA com QR code
- `TwoFactorEnabledResponse`: Resposta de ativação 2FA com códigos de backup
- `Enable2FADto`: DTO para ativar 2FA
- `Verify2FADto`: DTO para verificar código TOTP
- `Disable2FADto`: DTO para desativar 2FA

#### token.rs
Define estruturas de dados para rotação de tokens JWT.

**Structs:**
- `TokenClaims`: Claims do token JWT com suporte a família de tokens
- `BlacklistedToken`: Token na lista negra
- `RefreshTokenDto`: DTO para atualização de token

#### keystroke_dynamics.rs
Define estruturas de dados para análise de ritmo de digitação.

**Structs:**
- `KeystrokeDynamics`: Modelo para armazenar padrões de digitação
- `RegisterKeystrokePatternDto`: DTO para registrar padrões
- `VerifyKeystrokePatternDto`: DTO para verificar padrões
- `KeystrokeVerificationResponse`: Resposta de verificação com similaridade
- `KeystrokeStatusResponse`: Status da verificação de ritmo de digitação

#### auth.rs
Define estruturas de dados relacionadas à autenticação.

**Structs:**
- `LoginDto`: DTO para login
- `RegisterDto`: DTO para registro
- `RefreshTokenDto`: DTO para atualização de token
- `ForgotPasswordDto`: DTO para recuperação de senha
- `ResetPasswordDto`: DTO para redefinição de senha
- `UnlockAccountDto`: DTO para desbloqueio de conta
- `TokenClaims`: Claims do token JWT
- `AuthResponse`: Resposta de autenticação com tokens
- `Session`: Informações de sessão do usuário
- `RefreshToken`: Dados do token de atualização
- `PasswordResetToken`: Dados do token de redefinição de senha
- `AuthLog`: Log de eventos de autenticação

#### response.rs
Define estruturas de resposta da API.

**Structs:**
- `ApiResponse<T>`: Wrapper genérico de resposta da API

#### oauth.rs
Define estruturas de dados para autenticação OAuth.

**Structs:**
- `OAuthProvider`: Enum dos provedores suportados (Google, Facebook, Microsoft, GitHub, Apple)
- `OAuthConnection`: Modelo para armazenar conexões OAuth do usuário
- `OAuthUserProfile`: Perfil de usuário obtido do provedor OAuth
- `OAuthLoginRequest`: Requisição para iniciar login OAuth
- `OAuthCallbackRequest`: Dados recebidos no callback OAuth

### Services Module (`src/services/`) 

#### device_service.rs
Implementa a lógica de negócios para gerenciamento de dispositivos conectados.

**Functions:**
- `list_devices()`: Lista todos os dispositivos do usuário
- `get_device()`: Obtém detalhes de um dispositivo específico
- `update_device()`: Atualiza informações de um dispositivo
- `revoke_device()`: Revoga acesso de um dispositivo
- `register_device()`: Registra um novo dispositivo durante login
- `clean_expired_sessions()`: Limpa sessões expiradas
- `parse_user_agent()`: Extrai informações de um user-agent
- `get_location_from_ip()`: Tenta obter localização a partir de um IP

#### email_verification_service.rs
Implementa a lógica de negócios para verificação por email após login.

**Functions:**
- `generate_and_send_code()`: Gera um novo código e envia por email 
- `verify_code()`: Verifica um código enviado pelo usuário
- `has_pending_code()`: Verifica se o usuário tem um código pendente
- `clean_expired_codes()`: Limpa códigos expirados
- `send_verification_email()`: Envia email com código de verificação

#### recovery_email_service.rs
Implementa a lógica de negócios para gerenciamento de emails de recuperação secundários.

**Functions:**
- `list_recovery_emails()`: Lista todos os emails de recuperação do usuário
- `add_recovery_email()`: Adiciona um novo email de recuperação
- `verify_email()`: Verifica um novo email de recuperação
- `remove_recovery_email()`: Remove um email de recuperação
- `resend_verification_email()`: Reenvia email de verificação
- `get_verified_recovery_emails()`: Obtém todos os emails de recuperação verificados

#### auth_service.rs
Implementa a lógica de negócios para autenticação.

**Functions:**
- `register()`: Registra um novo usuário
- `login()`: Autentica um usuário
- `forgot_password()`: Inicia recuperação de senha
- `reset_password()`: Redefine a senha de um usuário
- `refresh_token()`: Atualiza um token de acesso
- `unlock_account()`: Desbloqueia uma conta bloqueada
- `validate_token()`: Valida um token JWT, verificando primeiro o cache (Moka) antes de decodificar e, opcionalmente, verificando a blacklist.
- `generate_jwt()`: Gera um token JWT
- `create_session()`: Cria uma nova sessão de usuário
- `log_auth_event()`: Registra eventos de autenticação
- `parse_expiration()`: Analisa o tempo de expiração do token
- `save_refresh_token()`: Salva um token de atualização
- `find_and_validate_refresh_token()`: Encontra e valida um token de atualização
- `revoke_refresh_token()`: Revoga um token de atualização específico
- `hash_token()`: Gera hash de um token para armazenamento seguro
- `revoke_all_user_refresh_tokens()`: Revoga todos os tokens de atualização de um usuário

#### email_service.rs
Implementa envio de emails.

**Struct:**
- `EmailService`: Serviço para envio de emails

**Methods:**
- `new()`: Cria um novo serviço de email
- `send_welcome_email()`: Envia email de boas-vindas para novos usuários
- `send_password_reset_email()`: Envia instruções de redefinição de senha
- `send_account_locked_email()`: Envia notificação de conta bloqueada
- `send_verification_email()`: Envia email de verificação após login
- `send_recovery_email_verification()`: Envia email de verificação para um email secundário
- `send_email()`: Método genérico para envio de emails

#### user_service.rs
Implementa a lógica de negócios para gerenciamento de usuários.

**Functions:**
- `create_user()`: Cria um novo usuário
- `get_user_by_id()`: Obtém um usuário por ID
- `get_user_by_email()`: Obtém um usuário por email
- `get_user_by_username()`: Obtém um usuário por nome de usuário
- `get_user_by_email_or_username()`: Obtém um usuário por email ou nome de usuário
- `update_user()`: Atualiza as informações de um usuário
- `delete_user()`: Exclui um usuário (somente admin)
- `change_password()`: Altera a senha de um usuário
- `hash_password()`: Gera hash de uma senha
- `verify_password()`: Verifica uma senha contra seu hash
- `list_users()`: Lista todos os usuários

#### keystroke_service.rs
Implementa a lógica de negócios para análise de ritmo de digitação.

**Functions:**
- `register_pattern()`: Registra um novo padrão de digitação
- `verify_keystroke_pattern()`: Verifica um padrão durante o login
- `toggle_keystroke_verification()`: Habilita/desabilita verificação
- `get_keystroke_status()`: Obtém o status atual da verificação
- `calculate_similarity()`: Calcula a similaridade entre padrões de digitação

#### keystroke_security_service.rs
Implementa monitoramento de segurança e detecção de anomalias para keystroke dynamics.

**Struct:**
- `KeystrokeSecurityService`: Serviço para monitorar tentativas de verificação de keystroke

**Methods:**
- `record_verification_attempt()`: Registra e analisa tentativas de verificação
- `check_for_suspicious_patterns()`: Detecta anomalias em padrões de digitação
- `check_consecutive_failures()`: Monitora ataques de força bruta
- `calculate_anomaly_score()`: Calcula pontuações de anomalia para padrões de digitação
- `is_user_suspicious()`: Verifica se um usuário está sob suspeita

#### token_service.rs
Implementa a lógica de negócios para gerenciamento de tokens JWT.

**Functions:**
- `rotate_token()`: Rotaciona um token JWT mantendo a família
- `revoke_token()`: Revoga um token específico
- `revoke_all_tokens()`: Revoga todos os tokens de um usuário
- `blacklist_token()`: Adiciona um token à lista negra
- `is_token_blacklisted()`: Verifica se um token está na lista negra
- `clean_expired_tokens()`: Limpa tokens expirados da lista negra
- `update_token_family()`: Atualiza a família de tokens de um usuário

#### two_factor_service.rs
Implementa a lógica de negócios para autenticação de dois fatores.

**Functions:**
- `setup_2fa()`: Configura 2FA para um usuário e gera QR code
- `enable_2fa()`: Ativa 2FA após verificar código TOTP
- `disable_2fa()`: Desativa 2FA após verificação
- `verify_totp_code()`: Verifica um código TOTP
- `generate_backup_codes()`: Gera códigos de backup para recuperação
- `verify_backup_code()`: Verifica um código de backup
- `get_2fa_status()`: Obtém o status atual do 2FA

#### oauth_service.rs
Implementa a lógica de negócios para autenticação OAuth com provedores sociais.

**Functions:**
- `get_authorization_url()`: Gera URL para redirecionamento ao provedor OAuth
- `process_callback()`: Processa o retorno do provedor OAuth
- `get_user_profile()`: Obtém o perfil do usuário do provedor OAuth
- `process_oauth_login()`: Processa o login OAuth e cria/atualiza o usuário
- `list_oauth_connections()`: Lista conexões OAuth de um usuário
- `remove_oauth_connection()`: Remove uma conexão OAuth
- `validate_token()`: Valida um token JWT
- `generate_jwt()`: Gera um token JWT
- `create_session()`: Cria uma nova sessão de usuário
- `log_auth_event()`: Registra eventos de autenticação
- `parse_expiration()`: Analisa o tempo de expiração do token

### Middleware Module (`src/middleware/`) 

#### email_verification.rs
Implementa middleware para verificação por email após login.

**Structs:**
- `EmailVerificationCheck`: Middleware para verificar se o usuário confirmou o código de email

**Methods:**
- `EmailVerificationCheck::new()`: Cria um novo middleware de verificação por email

#### auth.rs
Implementa middleware de autenticação.

**Structs:**
- `JwtAuth`: Middleware para autenticação JWT
- `AdminAuth`: Middleware para autorização de admin

**Methods:**
- `JwtAuth::new()`: Cria um novo middleware de autenticação JWT
- `AdminAuth::new()`: Cria um novo middleware de autorização de admin

#### cors.rs
Configura políticas CORS (Cross-Origin Resource Sharing).

**Functions:**
- `configure_cors()`: Configura definições CORS com base na configuração da aplicação

#### error.rs
Lida com transformação de erros para respostas de API consistentes.

**Struct:**
- `ErrorHandler`: Middleware para tratamento consistente de erros

#### logger.rs
Registra requisições e respostas HTTP.

**Struct:**
- `RequestLogger`: Middleware para registro de requisições

#### rate_limiter.rs
Implementa limitação de taxa para prevenir abusos.

**Struct:**
- `RateLimiter`: Middleware para limitação de taxa de requisições

**Methods:**
- `RateLimiter::new()`: Cria um novo limitador de taxa com limites especificados

#### keystroke_rate_limiter.rs
Implementa limitação de taxa especializada para verificação de ritmo de digitação.

**Struct:**
- `KeystrokeRateLimiter`: Middleware para limitação de taxa de tentativas de verificação de keystroke

**Methods:**
- `KeystrokeRateLimiter::new()`: Cria um novo limitador de taxa de keystroke com limites especificados
- `clean_keystroke_rate_limit_entries()`: Limpa entradas expiradas do limitador de taxa

#### security.rs
Implementa configurações de segurança para a API.

**Functions:**
- `configure_security()`: Configura headers de segurança e proteção CSRF
- `get_secure_headers()`: Cria headers de segurança padrão

### Routes Module (`src/routes/`) 

#### mod.rs
Configura rotas da API e middleware.

**Functions:**
- `configure_routes()`: Configura todas as rotas da API com seus respectivos middlewares

## API Endpoints 

### Authentication Endpoints 
- `POST /api/auth/register`: Registrar novo usuário
- `POST /api/auth/login`: Autenticar usuário
- `POST /api/auth/forgot-password`: Solicitar recuperação de senha
- `POST /api/auth/reset-password`: Redefinir senha
- `POST /api/auth/refresh`: Atualizar token JWT
- `POST /api/auth/unlock`: Desbloquear conta
- `GET /api/auth/me`: Obter perfil do usuário atual

### OAuth Endpoints 
- `GET /api/auth/oauth/login?provider=google`: Iniciar login OAuth
- `GET /api/auth/oauth/callback`: Callback para processamento OAuth
- `GET /api/auth/oauth/connections/{user_id}`: Listar conexões OAuth
- `DELETE /api/auth/oauth/connections/{user_id}/{connection_id}`: Remover conexão OAuth (requer autenticação)
- `POST /api/auth/token/rotate`: Rotacionar token JWT
- `POST /api/auth/token/revoke`: Revogar token JWT
- `POST /api/auth/revoke-all/{id}`: Revogar todos os tokens (logout de todos os dispositivos)

### Email Verification Endpoints 
- `POST /api/auth/email-verification/verify`: Verificar código enviado por email após login
- `POST /api/auth/email-verification/resend`: Reenviar código de verificação por email

### Device Management Endpoints 
- `GET /api/auth/devices`: Listar todos os dispositivos conectados
- `GET /api/auth/devices/{id}`: Obter detalhes de um dispositivo
- `PUT /api/auth/devices/{id}`: Atualizar informações de um dispositivo
- `DELETE /api/auth/devices/{id}`: Revogar acesso de um dispositivo

### Recovery Email Endpoints 
- `GET /api/auth/recovery-emails`: Listar emails de recuperação
- `POST /api/auth/recovery-emails`: Adicionar novo email de recuperação
- `POST /api/auth/recovery-emails/verify`: Verificar email de recuperação
- `DELETE /api/auth/recovery-emails/{id}`: Remover email de recuperação
- `POST /api/auth/recovery-emails/{id}/resend`: Reenviar email de verificação

### User Endpoints 
- `GET /api/users`: Listar todos os usuários (somente admin)
- `GET /api/users/{id}`: Obter usuário por ID
- `PUT /api/users/{id}`: Atualizar usuário
- `DELETE /api/users/{id}`: Excluir usuário (somente admin)
- `POST /api/users/{id}/change-password`: Alterar senha do usuário

### Two-Factor Authentication Endpoints 
- `GET /api/users/{id}/2fa/setup`: Iniciar configuração 2FA
- `POST /api/users/{id}/2fa/enable`: Ativar 2FA
- `POST /api/users/{id}/2fa/disable`: Desativar 2FA
- `POST /api/users/{id}/2fa/backup-codes`: Regenerar códigos de backup
- `GET /api/users/{id}/2fa/status`: Verificar status do 2FA

### Keystroke Dynamics Endpoints 
- `POST /api/users/{id}/keystroke/register`: Registrar padrão de digitação
- `POST /api/users/{id}/keystroke/verify`: Verificar padrão de digitação (com proteção contra ataques de força bruta)
- `PUT /api/users/{id}/keystroke/toggle`: Habilitar/desabilitar verificação
- `GET /api/users/{id}/keystroke/status`: Verificar status da verificação

### Health Check Endpoints 
- `GET /api/health`: Verificar saúde da API
- `GET /api/health/version`: Obter versão da API

### Admin Endpoints 
- `POST /api/admin/clean-tokens`: Limpar tokens expirados da lista negra
- `POST /api/admin/clean-verification-codes`: Limpar códigos de verificação expirados
- `POST /api/admin/clean-sessions`: Limpar sessões expiradas

## Security Features 

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
17. **Verificação por Email após Login**: Verificação adicional de segurança com código enviado por email após login 
18. **Gerenciamento de Dispositivos**: Controle completo sobre dispositivos conectados 
19. **Múltiplos Emails de Recuperação**: Suporte para cadastrar e verificar múltiplos emails de recuperação 
20. **OAuth Authentication**: Autenticação via provedores sociais (Google, Facebook, Microsoft, GitHub, Apple) 
21. **Token Validation Caching**: Cache em memória (Moka) para resultados de validação de token JWT, acelerando requisições subsequentes com o mesmo token. 

---
*Este índice foi gerado automaticamente e pode ser atualizado conforme o projeto evolui.*