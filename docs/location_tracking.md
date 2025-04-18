# 🌎 Sistema de Rastreamento de Localização

Este documento descreve como o sistema de rastreamento de localização funciona em nossa API de autenticação.

## 📋 Visão Geral

O sistema de rastreamento de localização é utilizado para detectar e prevenir atividades suspeitas durante o processo de login dos usuários. Ele coleta dados geográficos baseados no endereço IP do usuário e analisa padrões de comportamento para identificar possíveis tentativas de acesso não autorizado.

## 🧩 Componentes Principais

### 1. `LocationRiskAnalyzer`

Classe responsável por analisar o risco de cada login com base na localização geográfica:

- Utiliza o banco de dados MaxMind GeoIP2 para obter informações de geolocalização
- Calcula a distância e velocidade entre logins consecutivos
- Atribui uma pontuação de risco baseada em diversos fatores
- Marca logins como suspeitos quando necessário

### 2. `LoginLocationRepository`

Gerencia o armazenamento e recuperação de informações de localização de login:

- Salva novos registros de localização
- Recupera o histórico de localizações de um usuário
- Limpa dados antigos

### 3. `LoginLocation` (Modelo)

Estrutura que armazena dados relacionados a cada login:

- Informações geográficas (país, cidade, coordenadas)
- Pontuação de risco
- Indicador de suspeita e razões

## 🔄 Fluxo de Funcionamento

1. **Inicialização do Sistema**:
   - O banco de dados GeoIP é carregado na inicialização da aplicação
   - O caminho para o banco é definido em `main.rs` e armazenado globalmente

2. **Durante o Login**:
   - Quando um usuário faz login, o processo principal de autenticação acontece normalmente
   - Em paralelo, uma thread separada é iniciada para analisar a localização do IP
   - Isso garante que a análise de localização não bloqueie o processo de login

3. **Análise de Risco**:
   - O sistema busca a localização mais recente do usuário
   - Calcula a distância geográfica entre a localização anterior e a atual
   - Determina o tempo decorrido desde o último login
   - Calcula a velocidade implícita (distância/tempo)
   - Verifica mudanças de país, precisão da localização e outros fatores de risco

4. **Determinação de Suspeita**:
   - Se a pontuação de risco ultrapassar um limite (50.0), o login é marcado como suspeito
   - Velocidades extremamente altas (acima de 1800 km/h) são automaticamente marcadas como suspeitas
   - Mudanças de país aumentam significativamente a pontuação de risco

5. **Registro e Notificação**:
   - Todos os logins são registrados com suas informações de localização
   - Logins suspeitos são destacados nos logs do sistema
   - (Futuro) Notificações podem ser enviadas ao usuário ou administradores

## ⚙️ Configurações

O sistema possui os seguintes parâmetros configuráveis:

- `velocity_threshold_km_h`: 900.0 km/h (velocidade aproximada de um avião)
- `risk_threshold_distance_km`: 100 km (distância mínima para considerar risco)
- `max_accuracy_radius_km`: 200 km (raio máximo de precisão aceitável)

## 📊 Visualização de Dados

Os usuários podem acessar suas próprias informações de localização de login através do endpoint:
```
GET /api/locations
```

Administradores podem ver localizações de qualquer usuário:
```
GET /api/locations/users/{user_id}
```

## 🧹 Manutenção

Para manter o tamanho do banco de dados sob controle, dados antigos podem ser removidos:
```
DELETE /api/locations/clean?days=90
```

## 📚 Dependências

- MaxMind GeoIP2 Database: Necessário para resolução de IP para localização
- Biblioteca Haversine: Utilizada para cálculos de distância geodésica

## 🛠️ Instalação do Banco de Dados GeoIP

1. Crie um diretório `data` na raiz do projeto
2. Baixe o banco de dados GeoLite2-City.mmdb da MaxMind
3. Coloque o arquivo baixado em `data/GeoLite2-City.mmdb`

> **Nota**: Sem o banco de dados GeoIP, o sistema continuará funcionando, mas a análise de risco de localização será desativada. 