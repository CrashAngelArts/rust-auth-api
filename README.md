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

# Segurança
SECURITY_SALT_ROUNDS=10
SECURITY_RATE_LIMIT_REQUESTS=100
SECURITY_RATE_LIMIT_DURATION=1h
SECURITY_2FA_ENABLED=true
SECURITY_2FA_ISSUER="Sua Empresa"
SECURITY_KEYSTROKE_ENABLED=true
SECURITY_KEYSTROKE_THRESHOLD=80
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
- `POST /verify` - Verificar padrão de digitação
- `PUT /toggle` - Habilitar/desabilitar verificação
- `GET /status` - Verificar status da verificação

### Health Check (`/api/health`) ✅

- `GET /` - Verificação de saúde
- `GET /version` - Versão da API

### Admin (`/api/admin`) 👑

- `POST /clean-tokens` - Limpar tokens expirados da lista negra

### Rota Raiz

- `GET /` - Mensagem de boas-vindas

## Middleware 🔄

- JWT Authentication
- Admin Authorization
- Rate Limiter
- Request Logger
- Error Handler
- CORS
- Token Blacklist
- Two-Factor Verification
- Keystroke Dynamics Verification

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
- created_at: DateTime
- expires_at: DateTime

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
- Revogação de tokens em todos os dispositivos

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
- [ ] Implementar autenticação via OAuth
- [ ] Adicionar suporte a múltiplos tenants
- [ ] Implementar sistema de permissões granular
- [ ] Adicionar suporte a múltiplos idiomas
- [ ] Implementar cache de sessões
- [ ] Adicionar suporte a webhooks
- [ ] Adicionar autenticação com WebAuthn/FIDO2
