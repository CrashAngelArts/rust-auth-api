# Rust Auth API 🚀

API REST em Rust com autenticação avançada, análise de ritmo de digitação, RBAC e banco de dados SQLite.

## Características Principais

### Segurança 🔒
- Autenticação JWT com rotação de tokens
- Hash de senhas com bcrypt e Argon2
- Validação de entrada estrita
- Rate limiting (algoritmo Token Bucket configurável) 🚦
- Proteção CSRF (Double Submit Cookie) 🛡️🍪
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
- Cache de validação de token JWT (Moka) para otimizar performance ⚡
- RBAC (Role-Based Access Control) com gerenciamento fino de permissões 🎭
- Autorização granular baseada em permissões via middleware 🔐
- Perguntas de segurança para recuperação de conta 🔑

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
- Gerenciamento completo de Permissões e Papéis (CRUD) via serviço RBAC 📄🎭
- Associação entre Papéis/Permissões e Usuários/Papéis via serviço RBAC 🔗
- Verificação de permissões de usuário via serviço RBAC ✅
- Perguntas de segurança personalizáveis para recuperação de conta 🔐

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
LOG_LEVEL=info # ou debug, trace para mais detalhes

# Banco de Dados
DATABASE_URL=./data/auth.db

# JWT
JWT_SECRET=seu_segredo_jwt_forte_e_aleatorio_aqui
JWT_EXPIRATION=15m # Expiração curta para access tokens (ex: 15 minutos)
JWT_REFRESH_EXPIRATION_DAYS=7 # Expiração do refresh token em dias

# Email (Opcional, defina EMAIL_ENABLED=false para desabilitar)
EMAIL_ENABLED=true
EMAIL_SMTP_SERVER=smtp.example.com
EMAIL_SMTP_PORT=587
EMAIL_USERNAME=seu_email@example.com
EMAIL_PASSWORD=sua_senha_email_ou_app_password
EMAIL_FROM=noreply@example.com
EMAIL_FROM_NAME="Nome da Sua Aplicação"
EMAIL_BASE_URL=http://localhost:8080 # URL base para links nos emails
EMAIL_VERIFICATION_ENABLED=true # Habilita verificação por email após login

# Segurança
PASSWORD_SALT_ROUNDS=10 # Custo do Bcrypt (ou ignorado se USE_ARGON2=true)
# USE_ARGON2=true # Descomente para usar Argon2id em vez de Bcrypt (recomendado)

# Rate Limiting (Token Bucket)
RATE_LIMIT_CAPACITY=100       # Capacidade do balde (burst)
RATE_LIMIT_REFILL_RATE=10.0   # Taxa de recarga (tokens/segundo)

# CSRF Protection
CSRF_SECRET=seu_segredo_csrf_forte_e_aleatorio_aqui_32_bytes

# Keystroke Dynamics (Opcional)
SECURITY_KEYSTROKE_THRESHOLD=70  # Limiar de similaridade (0-100)
SECURITY_RATE_LIMIT_REQUESTS=5   # Tentativas de verificação / período
SECURITY_RATE_LIMIT_DURATION=60  # Período de rate limit (segundos)
SECURITY_BLOCK_DURATION=300      # Duração do bloqueio (segundos)

# OAuth (Opcional, defina OAUTH_ENABLED=false para desabilitar)
OAUTH_ENABLED=true
OAUTH_REDIRECT_URL=http://localhost:8080/api/auth/oauth/callback

# Google OAuth (Exemplo)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_OAUTH_ENABLED=true

# ... outras configurações OAuth (Facebook, Microsoft, GitHub, Apple) ...

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080 # Origens permitidas (separadas por vírgula)

# Admin Padrão (Primeira execução)
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=Admin@123
ADMIN_NAME=Administrador
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

### RBAC (Controle de Acesso Baseado em Papéis) (`/api/rbac`) 🎭

#### Permissões (`/permissions`)
- `POST /` - Criar nova permissão (requer permissão `permissions:manage`)
- `GET /` - Listar todas as permissões (requer login)
- `GET /{id}` - Obter detalhes de uma permissão (requer login)
- `GET /by-name/{name}` - Obter detalhes de uma permissão pelo nome (requer login)
- `PUT /{id}` - Atualizar uma permissão (requer permissão `permissions:manage`)
- `DELETE /{id}` - Deletar uma permissão (requer permissão `permissions:manage`)

#### Papéis (`/roles`)
- `POST /` - Criar novo papel (requer permissão `roles:manage`)
- `GET /` - Listar todos os papéis (requer login)
- `GET /{id}` - Obter detalhes de um papel (requer login)
- `GET /by-name/{name}` - Obter detalhes de um papel pelo nome (requer login)
- `PUT /{id}` - Atualizar um papel (requer permissão `roles:manage`)
- `DELETE /{id}` - Deletar um papel (requer permissão `roles:manage`)

#### Associações Papel <-> Permissão
- `POST /roles/{role_id}/permissions/{permission_id}` - Associar permissão a papel (requer `roles:assign-permission`)
- `DELETE /roles/{role_id}/permissions/{permission_id}` - Revogar permissão de papel (requer `roles:assign-permission`)
- `GET /roles/{role_id}/permissions` - Listar permissões de um papel (requer login)

#### Associações Usuário <-> Papel
- `POST /users/{user_id}/roles/{role_id}` - Associar papel a usuário (requer `users:assign-role`)
- `DELETE /users/{user_id}/roles/{role_id}` - Revogar papel de usuário (requer `users:assign-role`)
- `GET /users/{user_id}/roles` - Listar papéis de um usuário (requer login)

#### Verificação
- `GET /check-permission/{user_id}/{permission_name}` - Verificar se usuário tem permissão (requer login)

### Perguntas de Segurança (`/api/security-questions`) 🔐

#### Gerenciamento de Perguntas (Admin)
- `POST /admin` - Criar nova pergunta de segurança (requer permissão `security_questions:manage`)
- `PUT /admin/{id}` - Atualizar pergunta de segurança (requer permissão `security_questions:manage`)
- `DELETE /admin/{id}` - Excluir pergunta de segurança (requer permissão `security_questions:manage`)
- `PUT /admin/{id}/deactivate` - Desativar pergunta de segurança (requer permissão `security_questions:manage`)

#### Listagem e Consulta (Público)
- `GET /` - Listar perguntas de segurança (filtrável: apenas ativas)
- `GET /{id}` - Obter detalhes de pergunta específica

#### Respostas de Usuário (Autenticado)
- `POST /users/{user_id}/security-questions/{question_id}/answers` - Configurar resposta para pergunta de segurança
- `GET /users/{user_id}/security-questions/answers` - Listar respostas configuradas pelo usuário
- `POST /users/{user_id}/security-questions/{question_id}/verify` - Verificar resposta a uma pergunta
- `DELETE /users/{user_id}/security-questions/{question_id}/answers` - Remover resposta específica
- `DELETE /users/{user_id}/security-questions/answers` - Remover todas as respostas do usuário

### Recuperação por Perguntas de Segurança (`/api/auth`) 🔑
- `POST /security-questions` - Obter perguntas de segurança para um email
- `POST /verify-security-question` - Verificar resposta à pergunta de segurança (para recuperação)

### Rota Raiz

- `GET /` - Mensagem de boas-vindas e página de documentação da API

## Middleware 🔁

- JWT Authentication
- Admin Authorization
- Permission Authorization (RBAC) 🔐
- Rate Limiter (Token Bucket) 🚦
- CSRF Protection (Double Submit Cookie) 🛡️🍪
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

### OAuthConnection
- id: String
- user_id: String
- provider: String
- provider_user_id: String
- access_token: String
- refresh_token: Option<String>
- token_expires_at: Option<DateTime>
- created_at: DateTime
- updated_at: DateTime

### SecurityQuestion
- id: Uuid
- text: String
- active: bool
- created_at: DateTime
- updated_at: DateTime

### UserSecurityAnswer
- id: Uuid
- user_id: Uuid
- question_id: Uuid
- answer_hash: String
- created_at: DateTime
- updated_at: DateTime

## Segurança 🛡️

- Senhas são armazenadas com hash bcrypt ou Argon2 (configurável)
- Tokens JWT com expiração configurável e rotação de família
- Rate limiting global com algoritmo **Token Bucket** para suavizar rajadas e limitar taxa média 🚦
- Proteção contra **CSRF** usando Double Submit Cookie 🛡️🍪
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
- Perguntas de segurança para recuperação de conta com hashes Argon2 para respostas 🔐

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
- [x] Implementar cache de validação de token (Moka)
- [x] Implementar sistema RBAC com gerenciamento de permissões e papéis
- [x] Implementar perguntas de segurança para recuperação de conta
- [ ] Adicionar suporte a múltiplos tenants
- [ ] Implementar sistema de permissões granular
- [ ] Adicionar suporte a múltiplos idiomas
- [ ] Implementar cache de sessões
- [x] Adicionar suporte a webhooks
- [x] Adicionar autenticação com WebAuthn/FIDO2
