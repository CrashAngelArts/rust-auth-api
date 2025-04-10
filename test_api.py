#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import time
import random
import string
from colorama import init, Fore, Style
import sys
import sqlite3 # Adicionado para buscar token de desbloqueio
import os # Adicionado para encontrar o DB

# Inicializa colorama para formatação de cores no terminal
init()

# Configuração base
BASE_URL = "http://localhost:8080"
API_URL = f"{BASE_URL}/api"
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "auth.db") # Caminho para o DB
HEADERS = {"Content-Type": "application/json"}
DEFAULT_TIMEOUT = 15 # Timeout padrão para requisições em segundos
AUTH_TOKEN = None
ADMIN_TOKEN = None # Assumindo que não temos um admin por padrão nos testes
USER_ID = None

# Cores para os logs
class LogColors:
    INFO = Fore.CYAN
    SUCCESS = Fore.GREEN
    WARNING = Fore.YELLOW
    ERROR = Fore.RED
    DEBUG = Fore.MAGENTA
    RESET = Style.RESET_ALL

# Funções de log
def log_info(message):
    print(f"{LogColors.INFO}ℹ️ INFO: {message}{LogColors.RESET}")

def log_success(message):
    print(f"{LogColors.SUCCESS}✅ SUCESSO: {message}{LogColors.RESET}")

def log_warning(message):
    print(f"{LogColors.WARNING}⚠️ AVISO: {message}{LogColors.RESET}")

def log_error(message):
    print(f"{LogColors.ERROR}❌ ERRO: {message}{LogColors.RESET}")

def log_debug(message):
    print(f"{LogColors.DEBUG}🔍 DEBUG: {message}{LogColors.RESET}")

def log_separator():
    print(f"{LogColors.INFO}{'=' * 80}{LogColors.RESET}")

# Função para gerar dados aleatórios
def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Função para extrair dados da resposta da API (modificada para aceitar objeto response)
def extract_data(response):
    """Extrai dados da estrutura de resposta da API que usa um envelope padrão"""
    if not response:
        log_error("Nenhuma resposta recebida para extrair dados.")
        return None

    try:
        response_json = response.json()
        # Log da resposta JSON completa para depuração
        # log_debug(f"Resposta JSON ({response.status_code}): {json.dumps(response_json, indent=2, ensure_ascii=False)}")

        # Verifica se é o formato de envelope da API
        if isinstance(response_json, dict) and "status" in response_json:
            if response_json["status"] == "success":
                return response_json.get("data") # Retorna None se 'data' não existir
            else:
                # Loga o erro da API, mas retorna None para indicar falha na extração de 'data'
                log_warning(f"API retornou status '{response_json['status']}': {response_json.get('message', 'Erro desconhecido')}")
                return None
        else:
            # Se não for o formato de envelope, retorna o JSON como está (pode ser um erro não envelopado)
             log_warning(f"Resposta JSON ({response.status_code}) não segue o formato de envelope esperado.")
             return response_json

    except json.JSONDecodeError:
        log_warning(f"Resposta ({response.status_code}) não é JSON válido: {response.text[:200]}...") # Limita o log
        return None # Retorna None se não for JSON

# Função para fazer requisições HTTP com tratamento de erros (modificada para retornar response)
def make_request(method, endpoint, data=None, auth=False, admin=False):
    url = f"{API_URL}{endpoint}"
    headers = HEADERS.copy()

    token_to_use = None
    if admin and ADMIN_TOKEN:
        token_to_use = ADMIN_TOKEN
        # log_debug("Usando token de ADMIN") # Log menos verboso
    elif auth and AUTH_TOKEN:
        token_to_use = AUTH_TOKEN
        # log_debug("Usando token de AUTH") # Log menos verboso

    if token_to_use:
        headers["Authorization"] = f"Bearer {token_to_use}"

    try:
        log_debug(f"Requisição {method.upper()} para {url}")
        # if data: # Log de dados pode ser muito verboso, comentar se necessário
        #     log_debug(f"Dados: {json.dumps(data, indent=2, ensure_ascii=False)}")

        response = None
        req_method = method.lower()

        if req_method == "get":
            response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        elif req_method == "post":
            response = requests.post(url, headers=headers, json=data, timeout=DEFAULT_TIMEOUT)
        elif req_method == "put":
            response = requests.put(url, headers=headers, json=data, timeout=DEFAULT_TIMEOUT)
        elif req_method == "delete":
            response = requests.delete(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        else:
            log_error(f"Método HTTP não suportado: {method}")
            return None

        # Log básico da resposta
        log_debug(f"Resposta recebida: Status {response.status_code}")
        # Levanta uma exceção para erros HTTP (4xx, 5xx) para análise posterior se necessário
        # response.raise_for_status() # Comentado por enquanto, pois queremos analisar os status de erro nos testes

        return response # Retorna o objeto response completo

    except requests.exceptions.Timeout as e:
        log_error(f"Timeout ({DEFAULT_TIMEOUT}s) na requisição {method.upper()} para {url}: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        log_error(f"Erro de conexão na requisição {method.upper()} para {url}: {e}")
        return None
    except requests.exceptions.RequestException as e: # Captura outros erros do requests
        log_error(f"Erro na biblioteca Requests durante {method.upper()} para {url}: {type(e).__name__} - {e}")
        return None
    except Exception as e: # Captura qualquer outra exceção inesperada
        log_error(f"Erro inesperado durante a requisição {method.upper()} para {url}: {type(e).__name__} - {e}")
        return None


# --- Funções de Teste ---

def test_root():
    log_separator()
    log_info("Testando rota raiz")
    try:
        response = requests.get(BASE_URL, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            log_success(f"Rota raiz funcionando: {response.text}")
            return True
        else:
            log_error(f"Falha na rota raiz: Status {response.status_code}")
            return False
    except requests.RequestException as e:
        log_error(f"Erro ao acessar rota raiz: {e}")
        return False

def test_health():
    log_separator()
    log_info("Testando rotas de health check")
    success = True

    # Health check
    response = make_request("get", "/health")
    if response and response.status_code == 200:
        data = extract_data(response)
        # A resposta do health agora inclui mais dados, verificamos apenas o status principal
        if data and data.get("status") == "online":
            log_success(f"Health check funcionando: status '{data['status']}'")
        else:
            log_error(f"Falha no health check: Resposta inesperada {data}")
            success = False
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha no health check: Status {status}")
        success = False

    # Version
    response = make_request("get", "/health/version")
    if response and response.status_code == 200:
        data = extract_data(response)
        if data and "version" in data:
            log_success(f"Versão da API: {data['version']}")
        else:
            log_error(f"Falha ao obter versão: Resposta inesperada {data}")
            success = False
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha ao obter versão: Status {status}")
        success = False
    return success

def test_register_user(suffix_override=None):
    log_separator()
    log_info(f"Testando registro de usuário {'com sufixo ' + suffix_override if suffix_override else ''}")

    # Gera dados aleatórios para o usuário
    random_suffix = suffix_override or generate_random_string(6)
    email = f"user_{random_suffix}@example.com"
    password = "Password@123" # Senha forte
    username = f"user_{random_suffix}"
    first_name = f"Teste_{random_suffix}"
    last_name = "Sobrenome"

    payload = {
        "email": email,
        "username": username,
        "password": password,
        "confirm_password": password,
        "first_name": first_name,
        "last_name": last_name
    }

    response = make_request("post", "/auth/register", data=payload)

    if response and response.status_code == 201: # HTTP 201 Created
        data = extract_data(response)
        if data and "id" in data:
            log_success(f"Usuário registrado com sucesso: {email} (ID: {data['id']})")
            return email, password, username, data['id'] # Retorna também o ID
        else:
            log_error(f"Falha ao registrar usuário: Status 201, mas dados inesperados {data}")
            return None, None, None, None
    else:
        status = response.status_code if response else 'N/A'
        msg = ""
        if response:
            try:
                msg = response.json().get("message", response.text[:200])
            except:
                msg = response.text[:200]
        log_error(f"Falha ao registrar usuário: Status {status} - {msg}")
        return None, None, None, None

def test_login(username_or_email, password, expected_status=200):
    log_separator()
    log_info(f"Testando login para '{username_or_email}' (esperando status {expected_status})")

    payload = {
        "username_or_email": username_or_email,
        "password": password
    }

    response = make_request("post", "/auth/login", data=payload)

    # Melhor log de erro quando a resposta é None
    if not response:
        log_error(f"Login falhou: Nenhuma resposta recebida da API (esperado {expected_status}).")
        return False, None # Retorna False se não houve resposta

    # Verifica se o status code recebido é o esperado
    if response.status_code == expected_status:
        if expected_status == 200:
            # Se esperamos 200, tentamos extrair o token
            data = extract_data(response)
            if data and "access_token" in data:
                log_success("Login realizado com sucesso")
                global AUTH_TOKEN
                AUTH_TOKEN = data["access_token"]
                return True, AUTH_TOKEN # Retorna sucesso e token
            else:
                log_error(f"Login falhou: Status {expected_status}, mas resposta inesperada {data}")
                return False, None
        else:
            # Se esperamos um erro (e recebemos), o teste para essa chamada foi um sucesso
            try:
                msg = response.json().get("message", "")
            except:
                msg = response.text[:100] # Limita a mensagem
            log_success(f"Login falhou como esperado: Status {response.status_code} - {msg}")
            return True, None # Retorna sucesso (falha esperada) e sem token
    else:
        # Se o status code recebido for diferente do esperado
        status = response.status_code
        msg = ""
        try:
            msg = response.json().get("message", response.text[:200])
        except:
            msg = response.text[:200]
        log_error(f"Login falhou: Status esperado {expected_status}, recebido {status} - {msg}")
        return False, None


def test_me():
    log_separator()
    log_info("Testando rota /me (informações do usuário autenticado)")

    if not AUTH_TOKEN:
        log_error("Token de autenticação não disponível para /me")
        return False, None # Retorna falha e sem ID

    response = make_request("get", "/auth/me", auth=True)

    if response and response.status_code == 200:
        data = extract_data(response)
        if data and "id" in data:
            nome_completo = f"{data.get('first_name', '')} {data.get('last_name', '')}".strip()
            log_success(f"Informações do usuário obtidas: {nome_completo} ({data['email']}) ID: {data['id']}")
            global USER_ID
            USER_ID = data['id']
            return True, USER_ID # Retorna sucesso e ID
        else:
            log_error(f"Falha ao obter informações do usuário: Status 200, mas dados inesperados {data}")
            return False, None
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha ao obter informações do usuário: Status {status}")
        return False, None

# --- Testes de Bloqueio ---

def get_unlock_token_from_db(username_or_email):
    """Tenta buscar o token de desbloqueio diretamente do DB."""
    log_info(f"Tentando buscar token de desbloqueio para '{username_or_email}' no DB: {DB_PATH}")
    token = None
    conn = None
    try:
        if not os.path.exists(DB_PATH):
            log_error(f"Arquivo do banco de dados não encontrado em: {DB_PATH}")
            return None

        conn = sqlite3.connect(DB_PATH, timeout=10) # Timeout para evitar lock
        # Tentar modo WAL para leitura concorrente (pode não funcionar se o servidor estiver escrevendo muito)
        # conn.execute("PRAGMA journal_mode=WAL;")
        cursor = conn.cursor()
        # Esperar um pouco se o DB estiver bloqueado
        conn.execute("PRAGMA busy_timeout = 5000;") # 5 segundos

        cursor.execute(
            "SELECT unlock_token FROM users WHERE email = ? OR username = ?",
            (username_or_email, username_or_email)
        )
        result = cursor.fetchone()
        if result and result[0]:
            token = result[0]
            log_success(f"Token de desbloqueio encontrado no DB: {token}")
        else:
            log_warning("Token de desbloqueio não encontrado no DB para este usuário (ou ainda não foi gerado).")
    except sqlite3.OperationalError as e:
         if "database is locked" in str(e):
             log_error(f"Erro ao acessar o banco de dados SQLite: Banco de dados bloqueado. O servidor pode estar escrevendo. Tentando novamente em breve...")
             # Poderia tentar novamente aqui, mas por simplicidade, retornamos None
             return None
         else:
             log_error(f"Erro operacional ao acessar o banco de dados SQLite: {e}")
    except sqlite3.Error as e:
        log_error(f"Erro ao acessar o banco de dados SQLite: {e}")
    finally:
        if conn:
            conn.close()
    return token

def test_account_lockout_and_unlock():
    log_separator()
    log_info("Testando bloqueio e desbloqueio de conta")
    lock_suffix = generate_random_string(6)
    email, password, username, user_id = test_register_user(suffix_override=f"lock_{lock_suffix}")

    if not email:
        log_error("Falha ao registrar usuário para teste de bloqueio.")
        return False

    wrong_password = "WrongPassword123"
    max_attempts = 5 # Assumindo o padrão configurado na API
    lockout_triggered = False

    # 1. Tentar login com senha errada até bloquear
    log_info(f"Tentando login com senha incorreta {max_attempts + 1} vezes para '{username}'...")
    for i in range(max_attempts + 1):
        log_info(f"Tentativa {i+1}/{max_attempts + 1}...")
        # Espera 401 nas primeiras N-1 tentativas, 403 na N-ésima e 403 na N+1-ésima
        expected_status = 403 if i >= max_attempts else 401 # Correção: Bloqueio ocorre na 5a tentativa (índice 4)

        success, _ = test_login(username, wrong_password, expected_status=expected_status)

        if not success:
            log_error(f"Falha na tentativa {i+1} de login incorreto (status não correspondeu ao esperado {expected_status}).")
            # Se falhou na tentativa que deveria bloquear (403)
            if i >= max_attempts: # Se falhou a partir da tentativa de bloqueio
                 log_error(f"Falha crítica: Não recebeu status {expected_status} quando esperado.")
                 return False
            # Pausa maior se suspeitar de rate limit ou erro de conexão
            log_warning("Pausando por 3 segundos...")
            time.sleep(3)
        elif expected_status == 403:
             log_success(f"Conta bloqueada como esperado na tentativa {i+1} (Status 403 recebido).")
             lockout_triggered = True # Marca que o bloqueio ocorreu

        # Pausa entre tentativas para dar tempo ao servidor/DB
        # Aumentar a pausa pode ajudar se houver locks no DB ou rate limiting
        time.sleep(2)

    # Verifica se o bloqueio realmente ocorreu (se o status 403 foi recebido em algum momento >= max_attempts)
    if not lockout_triggered:
        log_error(f"A conta não foi bloqueada após {max_attempts} tentativas (não recebeu 403).")
        return False

    # 2. Tentar login com senha correta (deve falhar por bloqueio - 403)
    log_info("Tentando login com senha correta (deve falhar com status 403 por bloqueio)...")
    success, _ = test_login(username, password, expected_status=403)
    if not success:
        log_error("Falha ao verificar o bloqueio com senha correta (não recebeu 403).")
        return False
    log_success("Login com senha correta bloqueado (403) como esperado.")

    # 3. Obter token de desbloqueio do DB (com retentativas)
    unlock_token = None
    for attempt in range(3): # Tenta buscar o token algumas vezes
        log_info(f"Obtendo token de desbloqueio do banco de dados (tentativa {attempt+1}/3)...")
        unlock_token = get_unlock_token_from_db(username)
        if unlock_token:
            break
        log_warning("Token ainda não encontrado, esperando 2 segundos...")
        time.sleep(2)

    if not unlock_token:
        log_error("Não foi possível obter o token de desbloqueio do banco de dados após várias tentativas.")
        log_warning("Verifique os logs do servidor Rust para erros ao gerar/salvar o token ou se o email está habilitado.")
        return False # Não podemos continuar sem o token

    # 4. Desbloquear a conta
    log_info(f"Tentando desbloquear a conta com o token: {unlock_token}")
    payload = {"token": unlock_token}
    response = make_request("post", "/auth/unlock", data=payload)

    if response and response.status_code == 200:
        # Verificar a mensagem de sucesso
        try:
            msg = response.json().get("message", "")
            if "desbloqueada com sucesso" in msg.lower():
                 log_success(f"Conta desbloqueada com sucesso via API: {msg}")
            else:
                 log_warning(f"Conta desbloqueada (Status 200), mas mensagem inesperada: {msg}")
        except:
             log_warning(f"Conta desbloqueada (Status 200), mas resposta não JSON: {response.text[:100]}")

    else:
        status = response.status_code if response else 'N/A'
        msg = ""
        if response:
            try:
                msg = response.json().get("message", response.text[:200])
            except:
                msg = response.text[:200]
        log_error(f"Falha ao desbloquear a conta: Status {status} - {msg}")
        return False

    # 5. Tentar login com senha correta novamente (deve funcionar com status 200)
    log_info("Tentando login com senha correta após desbloqueio...")
    success, _ = test_login(username, password, expected_status=200)
    if not success:
        log_error("Falha ao fazer login após desbloqueio.")
        return False
    log_success("Login bem-sucedido após desbloqueio!")

    return True

# --- Funções de Teste Restantes (adaptadas para usar make_request e extract_data) ---

def test_forgot_password(email):
    log_separator()
    log_info(f"Testando recuperação de senha para '{email}'")
    payload = {"email": email}
    response = make_request("post", "/auth/forgot-password", data=payload)

    # Espera 200 OK mesmo que o email não exista ou email esteja desabilitado
    if response and response.status_code == 200:
         try:
            msg = response.json().get("message", "")
            log_success(f"Solicitação de recuperação de senha processada: {msg}")
            return True
         except:
             log_error(f"Resposta inesperada para forgot-password (Status 200): {response.text[:200]}")
             return False
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha na solicitação de recuperação de senha: Status {status}")
        return False

def test_reset_password():
    log_separator()
    log_info("Testando redefinição de senha (simulação)")
    log_warning("Este teste é apenas uma simulação, pois precisaríamos do token real enviado por email.")
    # Para um teste real:
    # 1. Chamar forgot_password
    # 2. Obter o token do DB ou de um mail catcher
    # 3. Chamar /auth/reset-password com o token real e nova senha
    # 4. Tentar login com a nova senha
    log_success("Simulação de redefinição de senha concluída (Nenhuma chamada API feita).")
    return True

def test_list_users():
    log_separator()
    log_info("Testando listagem de usuários (requer token válido, pode falhar se não for admin)")

    if not AUTH_TOKEN:
        log_error("Token de autenticação não disponível para listar usuários.")
        return False # Falha clara

    response = make_request("get", "/users", auth=True) # Tenta com token normal

    if not response: # Verifica se a resposta é None
        log_error("Falha ao listar usuários: Nenhuma resposta recebida da API.")
        return False

    if response.status_code == 200:
        data = extract_data(response) # Usa a função atualizada
        # A resposta paginada tem 'data' como a lista
        if data is not None and isinstance(data.get("data"), list):
            log_success(f"Lista de usuários obtida (como admin?): {len(data['data'])} usuários na página {data.get('page', '?')}/{data.get('total_pages', '?')}.")
            return True
        else:
             log_error(f"Falha ao listar usuários: Status 200, mas dados inesperados {data}")
             return False
    elif response.status_code == 403:
         log_warning("Acesso negado à listagem de usuários (provavelmente não é admin, esperado).")
         return True # Considera sucesso pois a proteção funcionou
    else:
        status = response.status_code
        msg = ""
        try:
            msg = response.json().get("message", response.text[:200])
        except:
            msg = response.text[:200]
        log_error(f"Falha ao listar usuários: Status {status} - {msg}")
        return False


def test_get_user(user_id_to_get):
    log_separator()
    log_info(f"Testando obtenção de usuário por ID: {user_id_to_get}")

    if not AUTH_TOKEN:
        log_error("Token de autenticação não disponível.")
        return False
    if not user_id_to_get:
        log_error("ID do usuário para buscar não fornecido.")
        return False

    response = make_request("get", f"/users/{user_id_to_get}", auth=True)

    if response and response.status_code == 200:
        data = extract_data(response)
        if data and data.get("id") == user_id_to_get:
            nome_completo = f"{data.get('first_name', '')} {data.get('last_name', '')}".strip()
            log_success(f"Informações do usuário {user_id_to_get} obtidas: {nome_completo} ({data['email']})")
            return True
        else:
            log_error(f"Falha ao obter usuário {user_id_to_get}: Status 200, mas dados inesperados {data}")
            return False
    elif response and response.status_code == 403:
         log_warning(f"Acesso negado para obter usuário {user_id_to_get} (não é admin nem o próprio usuário?).")
         return False # Falha em obter o usuário esperado
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha ao obter usuário {user_id_to_get}: Status {status}")
        return False

def test_update_user(user_id_to_update):
    log_separator()
    log_info(f"Testando atualização de usuário: {user_id_to_update}")

    if not AUTH_TOKEN:
        log_error("Token de autenticação não disponível.")
        return False
    if not user_id_to_update:
        log_error("ID do usuário para atualizar não fornecido.")
        return False

    novo_nome = f"Atualizado_{generate_random_string(4)}"
    payload = {
        "first_name": novo_nome,
        "last_name": "Testovich"
    }

    response = make_request("put", f"/users/{user_id_to_update}", data=payload, auth=True)

    if response and response.status_code == 200:
        data = extract_data(response)
        if data and data.get("id") == user_id_to_update and data.get("first_name") == novo_nome:
            log_success(f"Usuário {user_id_to_update} atualizado para: {data['first_name']} {data['last_name']}")
            return True
        else:
            log_error(f"Falha ao atualizar usuário {user_id_to_update}: Status 200, mas dados inesperados {data}")
            return False
    elif response and response.status_code == 403:
         log_warning(f"Acesso negado para atualizar usuário {user_id_to_update} (não é admin nem o próprio usuário?).")
         return False
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha ao atualizar usuário {user_id_to_update}: Status {status}")
        return False

def test_change_password(user_id_to_change, current_pw, new_pw):
    log_separator()
    log_info(f"Testando alteração de senha para usuário: {user_id_to_change}")

    if not AUTH_TOKEN:
        log_error("Token de autenticação não disponível.")
        return False
    if not user_id_to_change:
        log_error("ID do usuário para alterar senha não fornecido.")
        return False

    payload = {
        "current_password": current_pw,
        "new_password": new_pw,
        "confirm_password": new_pw
    }

    response = make_request("post", f"/users/{user_id_to_change}/change-password", data=payload, auth=True)

    if response and response.status_code == 200:
         try:
            # A resposta de sucesso aqui é apenas uma mensagem, não tem 'data' no envelope
            response_json = response.json()
            msg = response_json.get("message", "")
            if "senha alterada com sucesso" in msg.lower():
                log_success(f"Senha alterada com sucesso para {user_id_to_change}: {msg}")
                return True
            else:
                log_error(f"Resposta inesperada para change-password (Status 200): {msg}")
                return False
         except:
             log_error(f"Resposta inesperada para change-password (Status 200): {response.text[:200]}")
             return False
    elif response and response.status_code == 403:
         log_warning(f"Acesso negado para alterar senha do usuário {user_id_to_change} (não é o próprio usuário?).")
         return False
    elif response and response.status_code == 401: # Pode ser 401 se a current_password estiver errada
         try:
            msg = response.json().get("message", "")
            log_error(f"Falha ao alterar senha para {user_id_to_change}: Status {response.status_code} - {msg}")
         except:
            log_error(f"Falha ao alterar senha para {user_id_to_change}: Status {response.status_code} - {response.text[:200]}")
         return False
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha ao alterar senha para {user_id_to_change}: Status {status}")
        return False

def test_delete_user(user_id_to_delete):
    log_separator()
    log_info(f"Testando exclusão de usuário: {user_id_to_delete} (requer admin)")

    if not AUTH_TOKEN: # Precisa de um token, idealmente de admin
        log_error("Token de autenticação não disponível.")
        return False
    if not user_id_to_delete:
        log_error("ID do usuário para excluir não fornecido.")
        return False

    # Tenta excluir com o token atual (pode ser de usuário normal ou admin)
    response = make_request("delete", f"/users/{user_id_to_delete}", auth=True) # Usar auth=True ou admin=True se tiver token admin

    if response and response.status_code == 200:
         try:
            # Resposta de sucesso é apenas mensagem
            response_json = response.json()
            msg = response_json.get("message", "")
            if "usuário removido com sucesso" in msg.lower():
                log_success(f"Usuário {user_id_to_delete} excluído com sucesso: {msg}")
                return True
            else:
                 log_error(f"Resposta inesperada para delete-user (Status 200): {msg}")
                 return False
         except:
             log_error(f"Resposta inesperada para delete-user (Status 200): {response.text[:200]}")
             return False
    elif response and response.status_code == 403:
         log_warning(f"Acesso negado para excluir usuário {user_id_to_delete} (não é admin?).")
         return False # Considera falha pois não conseguiu excluir
    else:
        status = response.status_code if response else 'N/A'
        log_error(f"Falha ao excluir usuário {user_id_to_delete}: Status {status}")
        return False

# --- Execução Principal ---

def run_all_tests():
    log_separator()
    log_info("🚀 Iniciando testes da API REST em Rust")
    log_separator()

    # Verifica se a API está online
    if not test_root():
        log_error("API não está acessível ou rota raiz falhou. Abortando testes.")
        sys.exit(1)

    # Testes básicos
    if not test_health():
         log_warning("Testes de Health falharam, continuando mesmo assim...")

    # Testes de autenticação e usuário principal
    email, password, username, user_id = test_register_user()
    current_password = password # Guarda a senha atual
    new_password = "NewPassword@456"

    if email and password and user_id:
        login_ok, _ = test_login(email, password)
        if login_ok:
            me_ok, fetched_user_id = test_me()
            if not me_ok or fetched_user_id != user_id:
                 log_error("Falha no teste /me ou ID retornado não confere.")
                 # Considerar abortar ou continuar? Por enquanto continua.

            test_forgot_password(email)
            test_reset_password() # Simulado

            # Testes de usuário (usando o ID obtido de /me)
            test_list_users() # Pode falhar se não for admin
            test_get_user(user_id)
            test_update_user(user_id)
            if test_change_password(user_id, current_password, new_password):
                 # Teste de login com nova senha
                 test_login(email, new_password)
                 # current_password = new_password # Não precisamos mais da senha antiga
            else:
                 log_error("Não foi possível testar login com nova senha pois a alteração falhou.")

            # Teste de bloqueio/desbloqueio
            if not test_account_lockout_and_unlock():
                 log_error("Teste de bloqueio/desbloqueio falhou.")
            else:
                 log_success("Teste de bloqueio/desbloqueio passou.")


            # Teste de exclusão (opcional - requer admin ou ajuste de permissão)
            # log_info("Tentando excluir o usuário de teste (pode falhar se não for admin)...")
            # test_delete_user(user_id)

        else:
            log_error("Login inicial falhou, pulando testes autenticados.")
    else:
        log_error("Registro inicial falhou, pulando maioria dos testes.")


    log_separator()
    log_success("🎉 Testes concluídos!")
    log_separator()

if __name__ == "__main__":
    run_all_tests()
