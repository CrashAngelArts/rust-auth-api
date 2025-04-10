# Rust Auth API

API REST em Rust com autenticação JWT e banco de dados SQLite.

## Características Principais

### Segurança
- Autenticação JWT
- Hash de senhas com bcrypt
- Validação de entrada estrita
- Rate limiting
- CORS configurável
- Logging detalhado

### Funcionalidades
- Sistema completo de autenticação
- Gerenciamento de usuários
- Recuperação de senha
- Sistema de emails transacionais
- Logging de eventos de autenticação
- Sistema de bloqueio de contas
- Refresh tokens
- Suporte a múltiplos ambientes

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
```

## Rotas da API

### Autenticação (`/api/auth`)

- `POST /register` - Registro de usuário
- `POST /login` - Login
- `POST /forgot-password` - Recuperação de senha
- `POST /reset-password` - Redefinição de senha
- `POST /unlock` - Desbloqueio de conta
- `POST /refresh` - Refresh token
- `GET /me` - Recuperação de perfil (autenticado)

### Usuários (`/api/users`)

- `GET /` - Lista de usuários (admin)
- `GET /{id}` - Detalhes do usuário
- `PUT /{id}` - Atualização do usuário
- `DELETE /{id}` - Exclusão do usuário (admin)
- `POST /{id}/change-password` - Alteração de senha

### Health Check (`/api/health`)

- `GET /` - Verificação de saúde
- `GET /version` - Versão da API

### Rota Raiz

- `GET /` - Mensagem de boas-vindas

## Middleware

- JWT Authentication
- Admin Authorization
- Rate Limiter
- Request Logger
- Error Handler
- CORS

## Modelos de Dados

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
- created_at: DateTime
- updated_at: DateTime

### AuthResponse
- access_token: String
- refresh_token: String
- token_type: String
- expires_in: i64
- user: User

### Session
- id: String
- user_id: String
- ip_address: Option<String>
- user_agent: Option<String>
- created_at: DateTime
- expires_at: DateTime

## Segurança

- Senhas são armazenadas com hash bcrypt
- Tokens JWT com expiração configurável
- Rate limiting para prevenir brute force
- Sistema de bloqueio de contas após tentativas inválidas
- Validação de entrada rigorosa
- Proteção contra CORS malicioso
- Logging de eventos de segurança

## Logs

O sistema gera logs em diferentes níveis:
- INFO: Informações gerais do sistema
- WARN: Avisos importantes
- ERROR: Erros críticos
- DEBUG: Informações detalhadas para debugging

## Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Suporte

Para reportar bugs ou solicitar novas funcionalidades, abra uma issue no repositório.

## Roadmap

- [ ] Implementar autenticação via OAuth
- [ ] Adicionar suporte a múltiplos tenants
- [ ] Implementar sistema de permissões granular
- [ ] Adicionar suporte a múltiplos idiomas
- [ ] Implementar cache de sessões
- [ ] Adicionar suporte a webhooks
