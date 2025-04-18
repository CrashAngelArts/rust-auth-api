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
- Senhas temporárias com limite de uso configurável 🔑
- Rastreamento e análise de localização de login 🌎
- Limite configurável de sessões ativas por usuário 🚫
- Sistema completo de auditoria com registro de ações críticas 📝🔍

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
- Criação de senhas temporárias com limite de uso para acesso controlado 🔑
- Detecção de logins suspeitos baseada em localização geográfica 🗺️
- Políticas de limite de sessões com estratégias personalizáveis 🛑
- Logs de auditoria com suporte a filtros e pesquisa 🔍

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

# Auditoria
AUDIT_LOG_RETENTION_DAYS=90    # Retenção de logs de auditoria em dias
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

### Logs de Auditoria (`/api/admin/audit-logs`) 📝

- `GET /` - Listar logs de auditoria (com filtros e paginação)
- `GET /{id}` - Obter detalhes de um log específico
- `DELETE /clean` - Limpar logs antigos (configurável por dias)

## Sistema de Logs de Auditoria 📋

O sistema inclui um mecanismo completo de auditoria para registrar ações críticas e sensíveis:

- Registro detalhado de todas as ações de segurança e administrativas 🔍
- Diferentes níveis de severidade (Info, Warning, High, Critical) 🌡️
- Classificação por tipo de ação (Create, Read, Update, Delete, Login, etc.) 📊
- Registro de metadados como IP, user-agent e detalhes da operação 🌐
- Busca avançada com diversos filtros (usuário, ação, data, recurso) 🔎
- Manutenção automática com limpeza de logs antigos ♻️
- Interface administrativa para análise de logs 👁️

A auditoria captura automaticamente ações como:
- Logins e tentativas de login 🔑
- Alterações de permissões e papéis 👑
- Ações administrativas como exclusão de usuários 👨‍💼
- Operações de segurança como revogação de tokens 🛡️
- Falhas de segurança e tentativas suspeitas ⚠️
- Atualizações de configuração do sistema ⚙️

Cada registro de auditoria inclui:
- Carimbo de data/hora preciso ⏰
- Identificação do usuário e/ou administrador 👤
- Detalhes completos da ação executada 📝
- Status da operação (sucesso ou falha) ✅❌
- Dados contextuais para análise de segurança 🔍

## Múltiplos Emails de Recuperação 📧

O sistema agora suporta múltiplos emails de recuperação com verificação obrigatória:

- Adição de vários emails de recuperação por conta
- Verificação obrigatória por email com token seguro
- Recuperação de senha usando qualquer email verificado
- Gerenciamento completo (adicionar, remover, listar)
- Reenvio de emails de verificação quando necessário

Esta funcionalidade melhora significativamente a segurança e a experiência do usuário, oferecendo múltiplas opções para recuperação de conta em caso de perda de acesso ao email principal. 🔐

## Senhas Temporárias 🔑

O sistema permite a criação de senhas temporárias com limite de uso configurável:

- Criação de senhas temporárias para acesso controlado e limitado a uma conta
- Limite de usos configurável (1-10) por senha temporária
- Desativação automática após atingir o limite de usos
- Verificação de força da senha para garantir segurança
- Notificação via email quando a senha temporária é utilizada
- Monitoramento de uso com contagem de usos restantes
- Hash seguro da senha temporária usando Argon2
- Suporte para múltiplas senhas temporárias (uma ativa por vez)

Esta funcionalidade é ideal para:
- Conceder acesso temporário a sistemas para novos colaboradores
- Permitir acesso emergencial quando o usuário não pode usar seu dispositivo habitual
- Compartilhar acesso de forma segura e controlada com terceiros por período limitado
- Acesso transitório para manutenção ou suporte técnico

Cada uso da senha temporária é registrado e monitorado, com informações sobre o dispositivo e localização de acesso. 🛡️

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

## Políticas de Sessão 🚦

O sistema inclui gerenciamento avançado de sessões com:

- Limite configurável de sessões ativas por usuário
- Diferentes estratégias quando o limite é atingido:
  - RevokeOldest: Revoga a sessão mais antiga
  - RevokeLeastRecentlyUsed: Revoga a sessão menos usada
  - BlockNew: Bloqueia novas sessões
  - RevokeAll: Revoga todas as sessões existentes
- Exceções personalizadas para usuários específicos
- Interface administrativa para gerenciar políticas

## Manutenção do Sistema 🧹

O sistema possui rotinas de manutenção automática para:

- Limpeza de tokens expirados na lista negra
- Remoção de códigos de verificação de email expirados
- Limpeza de sessões de dispositivos expiradas
- Monitoramento de atividades suspeitas
- Registro detalhado de eventos de segurança
- Limpeza de logs de auditoria antigos

## Notas de Manutenção ⚙️

### Última Atualização (Versão Atual)
- Corrigido erro de importação no módulo `session_policy_controller`
- Corrigido tipo incorreto em `audit_log_controller` (String vs Option<String>)
- Otimização do sistema de logs de auditoria
- Removidas importações não utilizadas em diversos módulos
- Melhorada tipagem em vários componentes do sistema

### Compatibilidade
- Compatível com sistemas Windows, Linux e macOS
- Suporte total a ambientes containerizados (Docker)
- Adaptado para ambientes Windows com suporte UTF-8 🪟
