# 🚀 Lista de Tarefas - Projeto Rust Auth API

Este documento lista as funcionalidades já implementadas (✅) e as tarefas pendentes para tornar o sistema mais robusto e completo.

## 🔐 Funcionalidades Base (Core) - Implementadas ✅

- [x] Autenticação JWT com rotação de tokens
- [x] RBAC (Role-Based Access Control) com permissões
- [x] Proteção CSRF (Double Submit Cookie)
- [x] Rate limiting (Token Bucket configurável)
- [x] Autenticação 2FA (TOTP)
- [x] Verificação por email após login
- [x] Análise de ritmo de digitação (keystroke dynamics)
- [x] Múltiplos emails de recuperação
- [x] Autenticação OAuth com provedores sociais
- [x] Gerenciamento de dispositivos conectados
- [x] Cache de validação de token JWT (Moka)

## 📋 Funcionalidades Recentes - Implementadas ✅

- [x] Substituição de função deprecada no middleware CSRF
- [x] Verificação de token na blacklist durante validação
- [x] Validação de audiência/issuer em tokens JWT 
- [x] Revogação automática de refresh tokens antigos no login
- [x] Perguntas de segurança para recuperação de conta

## 🆕 Novas Funcionalidades - A Implementar

### 1. Recuperação de Conta Aprimorada

- [x] **Perguntas de Segurança** (Prioridade Alta)
  - [x] Criar modelo `SecurityQuestion` 
  - [x] Criar modelo `UserSecurityAnswer`
  - [x] Implementar repositório `SqliteSecurityQuestionRepository`
  - [x] Implementar serviço `SecurityQuestionService`
  - [x] Implementar controller `security_question_controller.rs`
  - [x] Adicionar endpoints à rota `/api/security-questions`
  - [x] Integrar com `auth_service.rs` para recuperação de senha

- [ ] **Código Único de Recuperação** (Prioridade Alta)
  - [ ] Adicionar campos na tabela de usuários
  - [ ] Implementar geração de código único de recuperação
  - [ ] Implementar verificação de código de recuperação
  - [ ] Integrar no fluxo de reset de senha
  - [ ] Implementar limpeza do código após uso

### 2. Análise de Riscos Avançada na Autenticação (Prioridade Alta)

- [ ] **Detecção de Localização Suspeita**
  - [ ] Implementar comparação de IP com logins anteriores
  - [ ] Detectar mudanças geográficas significativas
  - [ ] Adicionar lógica de alerta/bloqueio para IPs suspeitos

- [ ] **Detecção de Dispositivo Novo**
  - [ ] Melhorar a detecção de dispositivos na função `create_session_with_device_info`
  - [ ] Implementar verificação adicional para dispositivos não reconhecidos
  - [ ] Integrar com o fluxo de login existente

- [ ] **Análise de Horário de Login**
  - [ ] Armazenar e analisar padrões de horário de login
  - [ ] Detectar logins em horários incomuns para o usuário
  - [ ] Adicionar pontuação de risco para login em horários incomuns

- [ ] **Pontuação de Risco Combinada**
  - [ ] Implementar sistema de pontuação combinando diferentes fatores
  - [ ] Definir níveis de risco (baixo, médio, alto)
  - [ ] Implementar ações baseadas no nível de risco

### 3. Gerenciamento de Sessões Aprimorado (Prioridade Média)

- [ ] **Revogação de Sessão Individual**
  - [ ] Melhorar endpoint para revogar sessão específica (sem revogar todas)
  - [ ] Atualizar o serviço DeviceService com uma função dedicada

- [ ] **Limite de Sessões Ativas**
  - [ ] Adicionar configuração para limite máximo de sessões por usuário
  - [ ] Implementar lógica para limitar sessões ativas
  - [ ] Adicionar regra para revogar sessões mais antigas quando limite é atingido

### 4. Auditoria e Logs Aprimorados (Prioridade Média)

- [ ] **Logs de Ações Críticas**
  - [ ] Expandir `log_auth_event` para capturar mais tipos de eventos
  - [ ] Implementar logging para ações de gerenciamento de permissões
  - [ ] Implementar logging para alterações de configurações de segurança

- [ ] **Endpoints de Admin para Auditoria**
  - [ ] Criar endpoints para buscar logs por critérios (usuário, tipo, data)
  - [ ] Implementar paginação e filtros para consulta de logs

### 5. WebAuthn/Passkeys (Prioridade Baixa)

- [ ] **Suporte para WebAuthn/FIDO2**
  - [ ] Adicionar modelos para armazenar credenciais WebAuthn
  - [ ] Implementar endpoints para registro de credenciais
  - [ ] Implementar endpoints para autenticação por WebAuthn
  - [ ] Integrar no fluxo de autenticação existente

### 6. Webhooks para Eventos de Segurança (Prioridade Baixa)

- [ ] **Sistema de Webhooks**
  - [ ] Criar modelo para armazenar inscrições de webhooks
  - [ ] Implementar endpoints para gerenciar inscrições
  - [ ] Implementar lógica para disparar webhooks em eventos específicos
  - [ ] Adicionar fila de trabalho assíncrono para envio de webhooks

## 📝 Notas Adicionais

- A ordem das tarefas está organizada por prioridade e dependências lógicas.
- Inicialmente, é recomendado focar nas funcionalidades de Recuperação de Conta e Análise de Riscos, pois elas têm maior impacto na segurança geral do sistema.
- Para cada funcionalidade, siga o padrão de desenvolvimento:
  1. Criar modelos de dados
  2. Implementar repositórios
  3. Implementar serviços
  4. Implementar controladores
  5. Adicionar rotas
  6. Integrar com o sistema existente
  7. Atualizar documentação 