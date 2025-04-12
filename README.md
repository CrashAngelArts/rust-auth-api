# Rust Auth API 🚀

API REST em Rust com autenticação avançada, análise de ritmo de digitação e banco de dados SQLite.

## Características Principais

### Segurança 🔒
- Autenticação JWT com rotação de tokens
- Hash de senhas com bcrypt e Argon2
- Validação de entrada estrita
- Rate limiting
- CORS configurável
- Logging detalhado
- Autenticação de dois fatores (2FA)
- Lista negra de tokens
- Análise de ritmo de digitação (keystroke dynamics)
- Códigos de backup para 2FA
- Verificação por email após login 📧
- Gerenciamento de dispositivos conectados 📱
- Múltiplos emails de recuperação verificados 📧
- Sistema de verificação de emails secundários 🔐
- Detecção de anomalias e monitoramento de segurança 🛡️
- Autenticação OAuth com provedores sociais 🌐

### Funcionalidades 🛠️
- Sistema completo de autenticação
- Gerenciamento de usuários
- Recuperação de senha
- Sistema de emails transacionais
- Logging de eventos de autenticação
- Sistema de bloqueio de contas
- Refresh tokens
- Suporte a múltiplos ambientes
- Autenticação de dois fatores com TOTP
- Verificação biométrica comportamental
- Rotação de família de tokens
- Revogação de tokens em todos os dispositivos
- Verificação por email após login com códigos de 6 dígitos 📨
- Gerenciamento completo de dispositivos conectados (listar, visualizar, atualizar, revogar) 📱
- Manutenção automática de tokens, códigos e sessões expiradas 🧹
- Login com Google, Facebook, Microsoft, GitHub e Apple 🔑

## Requisitos

- Rust 1.60.0 ou superior
- SQLite 3.31.1 ou superior
- SMTP server configurável
- Git

## Instalação

1. Clone o repositório:
```bash
git clone https://gitlab.com/gameoverstudios/rust-auth-api.git
cd rust-auth-api
```

2. Copie o arquivo `.env.example` para `.env` e configure as variáveis necessárias:
```bash
cp .env.example .env
```

3. Instale as dependências e execute:
```bash
cargo build --release
cargo run
```

## Configuração

As configurações podem ser definidas através do arquivo `.env`:

```env
# Servidor
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
LOG_LEVEL=info

# Banco de Dados
DATABASE_URL=./data/auth.db

# JWT
JWT_SECRET=sua_chave_secreta_aqui
JWT_EXPIRATION=24h
JWT_FAMILY_ENABLED=true
JWT_BLACKLIST_ENABLED=true

# Email
EMAIL_SMTP_SERVER=smtp.gmail.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=seu_email@gmail.com
EMAIL_PASSWORD=sua_senha
EMAIL_FROM=seu_email@gmail.com
EMAIL_FROM_NAME="Nome do Sistema"
EMAIL_BASE_URL=http://localhost:8080
EMAIL_ENABLED=true
EMAIL_VERIFICATION_ENABLED=true

# Segurança
SECURITY_SALT_ROUNDS=10
SECURITY_RATE_LIMIT_REQUESTS=100
SECURITY_RATE_LIMIT_DURATION=1h
SECURITY_2FA_ENABLED=true
SECURITY_2FA_ISSUER="Sua Empresa"
SECURITY_KEYSTROKE_ENABLED=true
SECURITY_KEYSTROKE_THRESHOLD=70

# Segurança de Keystroke Dynamics
SECURITY_KEYSTROKE_THRESHOLD=70  # Limiar de similaridade (0-100)
SECURITY_RATE_LIMIT_REQUESTS=5   # Máximo de tentativas de verificação
SECURITY_RATE_LIMIT_DURATION=60  # Duração da janela em segundos
SECURITY_BLOCK_DURATION=300      # Duração do bloqueio em segundos

# Configurações OAuth
OAUTH_REDIRECT_URL=http://localhost:8080/api/auth/oauth/callback
OAUTH_ENABLED=true

# Google OAuth
GOOGLE_CLIENT_ID=seu_client_id_google
GOOGLE_CLIENT_SECRET=seu_client_secret_google
GOOGLE_OAUTH_ENABLED=true

# Facebook OAuth
FACEBOOK_CLIENT_ID=seu_client_id_facebook
FACEBOOK_CLIENT_SECRET=seu_client_secret_facebook
FACEBOOK_OAUTH_ENABLED=true

# Microsoft OAuth
MICROSOFT_CLIENT_ID=seu_client_id_microsoft
MICROSOFT_CLIENT_SECRET=seu_client_secret_microsoft
MICROSOFT_OAUTH_ENABLED=true

# GitHub OAuth
GITHUB_CLIENT_ID=seu_client_id_github
GITHUB_CLIENT_SECRET=seu_client_secret_github
GITHUB_OAUTH_ENABLED=true

# Apple OAuth
APPLE_CLIENT_ID=seu_client_id_apple
APPLE_CLIENT_SECRET=seu_client_secret_apple
APPLE_TEAM_ID=seu_team_id_apple
APPLE_KEY_ID=seu_key_id_apple
APPLE_PRIVATE_KEY_PATH=./keys/apple_private_key.p8
APPLE_OAUTH_ENABLED=true
```

## Rotas da API

### Autenticação (`/api/auth`) 🔑

- `POST /register` - Registro de usuário
- `POST /login` - Login
- `POST /forgot-password` - Recuperação de senha
- `POST /reset-password` - Redefinição de senha
- `POST /unlock` - Desbloqueio de conta
- `POST /refresh` - Refresh token
- `GET /me` - Recuperação de perfil (autenticado)
- `POST /token/rotate` - Rotacionar token JWT
- `POST /token/revoke` - Revogar token JWT
- `POST /revoke-all/{id}` - Revogar todos os tokens (logout de todos os dispositivos)

### Verificação por Email (`/api/auth/email-verification`) 📧

- `POST /verify` - Verificar código enviado por email após login
- `POST /resend` - Reenviar código de verificação por email

### Gerenciamento de Dispositivos (`/api/auth/devices`) 📱

- `GET /` - Listar dispositivos conectados
- `GET /{id}` - Obter detalhes de um dispositivo
- `PUT /{id}` - Atualizar informações de um dispositivo
- `DELETE /{id}` - Revogar acesso de um dispositivo

### Emails de Recuperação (`/api/auth/recovery-emails`) 📧

- `GET /` - Listar emails de recuperação
- `POST /` - Adicionar novo email de recuperação
- `POST /verify` - Verificar email de recuperação
- `DELETE /{id}` - Remover email de recuperação
- `POST /{id}/resend` - Reenviar email de verificação

### Autenticação OAuth (`/api/auth/oauth`) 🌐

- `POST /login` - Iniciar login OAuth (obter URL de autorização)
- `GET /callback` - Callback OAuth (processar resposta do provedor)
- `GET /connections/{user_id}` - Listar conexões OAuth do usuário
- `DELETE /connections/{user_id}/{connection_id}` - Remover conexão OAuth

### Usuários (`/api/users`) 👤

- `GET /` - Lista de usuários (admin)
- `GET /{id}` - Detalhes do usuário
- `PUT /{id}` - Atualização do usuário
- `DELETE /{id}` - Exclusão do usuário (admin)
- `POST /{id}/change-password` - Alteração de senha

### Autenticação de Dois Fatores (`/api/users/{id}/2fa`) 📱

- `GET /setup` - Iniciar configuração 2FA
- `POST /enable` - Ativar 2FA
- `POST /disable` - Desativar 2FA
- `POST /backup-codes` - Regenerar códigos de backup
- `GET /status` - Verificar status do 2FA

### Análise de Ritmo de Digitação (`/api/users/{id}/keystroke`) 🎹

- `POST /register` - Registrar padrão de digitação
- `POST /verify` - Verificar padrão de digitação (com proteção contra ataques de força bruta)
- `PUT /toggle` - Habilitar/desabilitar verificação
- `GET /status` - Verificar status da verificação

### Health Check (`/api/health`) ✅

- `GET /` - Verificação de saúde
- `GET /version` - Versão da API

### Admin (`/api/admin`) 👑

- `POST /clean-tokens` - Limpar tokens expirados da lista negra
- `POST /clean-verification-codes` - Limpar códigos de verificação expirados
- `POST /clean-sessions` - Limpar sessões expiradas

### Rota Raiz

- `GET /` - Mensagem de boas-vindas e página de documentação da API

## Middleware 🔁

- JWT Authentication
- Admin Authorization
- Rate Limiter
- Request Logger
- Error Handler
- CORS
- Token Blacklist
- Two-Factor Verification
- Keystroke Dynamics Verification
- Keystroke Rate Limiter
- Keystroke Security Monitoring
- Email Verification Check
- Security Headers

## Modelos de Dados 📊

### User
- id: String
- email: String
- username: String
- password_hash: String
- first_name: String
- last_name: String
- is_active: bool
- is_locked: bool
- locked_until: Option<DateTime>
- failed_login_attempts: i32
- two_factor_enabled: bool
- two_factor_secret: Option<String>
- backup_codes: Option<Vec<String>>
- created_at: DateTime
- updated_at: DateTime

### AuthResponse
- access_token: String
- refresh_token: String
- token_type: String
- expires_in: i64
- requires_2fa: bool
- requires_email_verification: bool
- user: User

### TokenClaims
- sub: String
- exp: i64
- iat: i64
- family: Option<String>

### BlacklistedToken
- jti: String
- family: Option<String>
- exp: i64

### TwoFactorSetup
- secret: String
- qr_code: String
- backup_codes: Vec<String>

### KeystrokeDynamics
- user_id: String
- typing_pattern: Vec<u32>
- similarity_threshold: u8
- enabled: bool

### Session
- id: String
- user_id: String
- ip_address: Option<String>
- user_agent: Option<String>
- device_name: Option<String>
- device_type: Option<String>
- location: Option<String>
- last_active_at: Option<DateTime>
- is_current: bool
- created_at: DateTime
- expires_at: DateTime

### Device
- id: String
- user_id: String
- device_name: String
- device_type: String
- ip_address: Option<String>
- user_agent: Option<String>
- location: Option<String>
- last_active_at: DateTime
- is_current: bool
- created_at: DateTime

### EmailVerificationCode
- id: String
- user_id: String
- code: String
- expires_at: DateTime
- created_at: DateTime

### RecoveryEmail
- id: String
- user_id: String
- email: String
- is_verified: bool
- verification_code: Option<String>
- verification_expires_at: Option<DateTime>
- created_at: DateTime
- updated_at: DateTime

## Segurança 🛡️

- Senhas são armazenadas com hash bcrypt ou Argon2
- Tokens JWT com expiração configurável e rotação de família
- Rate limiting para prevenir brute force
- Sistema de bloqueio de contas após tentativas inválidas
- Validação de entrada rigorosa
- Proteção contra CORS malicioso
- Logging de eventos de segurança
- Autenticação de dois fatores (2FA) com TOTP
- Códigos de backup para recuperação de 2FA
- Lista negra de tokens para revogação imediata
- Análise de ritmo de digitação para verificação biométrica comportamental
- Rate limiting específico para keystroke dynamics
- Detecção de anomalias em padrões de digitação
- Proteção contra ataques de força bruta em keystroke dynamics
- Monitoramento de atividades suspeitas em tentativas de verificação
- Revogação de tokens em todos os dispositivos
- Verificação por email após login com códigos de 6 dígitos e expiração configurável 📧
- Gerenciamento de dispositivos conectados com detecção automática de tipo de dispositivo 📱
- Rastreamento de sessões ativas com informações detalhadas sobre cada dispositivo 🔍
- Capacidade de revogar acesso a dispositivos específicos 🔒
- Headers de segurança configuráveis como X-Content-Type-Options, X-Frame-Options, etc.

## Gerenciamento de Dispositivos 📱

O sistema inclui um gerenciamento completo de dispositivos conectados, permitindo:

- Rastreamento de dispositivos que acessam a conta
- Detecção automática de sistema operacional, navegador e dispositivo
- Possibilidade de nomear dispositivos para fácil identificação
- Revogação remota de acesso a qualquer dispositivo
- Visualização de data e hora do último acesso

Isso aumenta significativamente a segurança, permitindo que os usuários monitorem e controlem quem tem acesso às suas contas.

## Múltiplos Emails de Recuperação 📧

O sistema agora suporta múltiplos emails de recuperação com verificação obrigatória:

- Adição de vários emails de recuperação por conta
- Verificação obrigatória por email com token seguro
- Recuperação de senha usando qualquer email verificado
- Gerenciamento completo (adicionar, remover, listar)
- Reenvio de emails de verificação quando necessário

Esta funcionalidade melhora significativamente a segurança e a experiência do usuário, oferecendo múltiplas opções para recuperação de conta em caso de perda de acesso ao email principal. 🔐

## Autenticação OAuth 🌐

O sistema agora suporta autenticação via OAuth com os seguintes provedores:

- Google 🔵
- Facebook 🔷
- Microsoft 🟦
- GitHub 🐱
- Apple 🍎

### Funcionalidades OAuth

- Login com provedores sociais populares 🔑
- Vinculação de contas sociais a contas existentes 🔗
- Gerenciamento de conexões OAuth (adicionar/remover) ⚙️
- Perfil unificado com informações dos provedores 👤
- Configuração fácil via variáveis de ambiente 💻

### Endpoints OAuth

- `GET /oauth/login?provider=google` - Inicia o fluxo de login OAuth
- `GET /oauth/callback` - Callback para processamento da autenticação OAuth
- `GET /connections/{user_id}` - Lista conexões OAuth do usuário
- `DELETE /connections/{user_id}/{connection_id}` - Remove conexão OAuth

## Manutenção do Sistema 🧹

O sistema possui rotinas de manutenção automática para:

- Limpeza de tokens expirados na lista negra
- Remoção de códigos de verificação de email expirados
- Limpeza de sessões de dispositivos expiradas
- Monitoramento de atividades suspeitas
- Registro detalhado de eventos de segurança

Essas rotinas garantem que o sistema permaneça eficiente e seguro ao longo do tempo.

## Logs

O sistema gera logs em diferentes níveis:
- INFO: Informações gerais do sistema
- WARN: Avisos importantes
- ERROR: Erros críticos
- DEBUG: Informações detalhadas para debugging

## Contribuição 🤝

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/RecursoIncrivel`)
3. Commit suas mudanças (`git commit -m 'Adiciona algum RecursoIncrivel'`)
4. Push para a branch (`git push origin feature/RecursoIncrivel`)
5. Abra um Pull Request

## Demonstração 🎮

O projeto inclui uma página de demonstração para testar a análise de ritmo de digitação:

```bash
# Abra o arquivo no navegador
open examples/keystroke-demo.html
```

## Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Suporte

Para reportar bugs ou solicitar novas funcionalidades, abra uma issue no repositório.

## Roadmap 🗺️

- [x] Implementar autenticação de dois fatores (2FA)
- [x] Adicionar rotação de tokens JWT
- [x] Implementar lista negra de tokens
- [x] Adicionar análise de ritmo de digitação
- [x] Implementar rate limiting para keystroke dynamics
- [x] Adicionar detecção de anomalias em padrões de digitação
- [x] Implementar proteção contra ataques de força bruta em keystroke
- [x] Implementar verificação por email após login
- [x] Implementar gerenciamento de dispositivos conectados
- [x] Implementar múltiplos emails de recuperação
- [x] Adicionar manutenção automática de sessões e tokens
- [x] Implementar autenticação via OAuth
- [ ] Adicionar suporte a múltiplos tenants
- [ ] Implementar sistema de permissões granular
- [ ] Adicionar suporte a múltiplos idiomas
- [ ] Implementar cache de sessões
- [ ] Adicionar suporte a webhooks
- [ ] Adicionar autenticação com WebAuthn/FIDO2
