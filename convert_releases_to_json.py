#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import json
import argparse
from typing import List, Dict, Any, Optional, Tuple

class ReleaseParser:
    def __init__(self, input_file: str, output_file: str):
        self.input_file = input_file
        self.output_file = output_file
        self.implementations = []
        self.current_id = 1
    
    def parse(self):
        """Analisa o arquivo releases.md e extrai as implementações"""
        print(f"🔍 Analisando arquivo {self.input_file}...")
        
        if not os.path.exists(self.input_file):
            print(f"❌ Arquivo {self.input_file} não encontrado!")
            return False
        
        # Ler o conteúdo do arquivo
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"❌ Erro ao ler o arquivo: {e}")
            return False
        
        # Iniciar a extração de implementações
        self.extract_implementations(content)
        
        # Salvar o resultado
        self.save_json()
        
        return True
    
    def extract_implementations(self, content: str):
        """Extrai implementações do conteúdo do arquivo"""
        
        # Buscar blocos de **Tarefas Pendentes e Próximos Passos**
        tasks_section_pattern = r'## Tarefas Pendentes e Próximos Passos.*?### Prioridade Alta(.*?)### Prioridade Média(.*?)### Prioridade Baixa(.*?)## Fluxo'
        tasks_match = re.search(tasks_section_pattern, content, re.DOTALL)
        
        if tasks_match:
            high_priority_content = tasks_match.group(1)
            medium_priority_content = tasks_match.group(2)
            low_priority_content = tasks_match.group(3)
            
            # Processar cada seção de prioridade
            self.process_priority_section(high_priority_content, "alta")
            self.process_priority_section(medium_priority_content, "média")
            self.process_priority_section(low_priority_content, "baixa")
        
        # Padrões para identificar implementações em todo o documento
        section_patterns = [
            # Implementações explícitas no formato "**Nome da Implementação** - Descrição:"
            r'\*\*([\w\s/]+)\*\*\s*-\s*(.*?):\s*```rust([^`]+)```',
            
            # Seções de "Melhorias Sugeridas" com itens numerados
            r'Melhorias Sugeridas:(.*?)(?:###|$)',
            
            # Outro padrão comum para capturar mais implementações
            r'(\d+)\.\s+([🔒✨🔧📝🛡️🔐🚀]*)\s+\*\*([\w\s/]+)\*\*(.*?)```rust([^`]+)```',
        ]
        
        # Extrai implementações diretas (formato **Nome** - Descrição: ```código```)
        direct_implementations = re.finditer(section_patterns[0], content, re.DOTALL)
        for match in direct_implementations:
            title = match.group(1).strip()
            description = match.group(2).strip()
            code_example = match.group(3).strip()
            
            category = self.extract_category_from_context(content, match.start())
            priority = self.determine_priority(content, match.start())
            tags = self.extract_tags(title, description, category)
            
            self.add_implementation(
                title=title,
                description=description,
                code_example=code_example,
                category=category,
                priority=priority,
                tags=tags
            )
        
        # Extrai seções "Melhorias Sugeridas"
        improvement_sections = re.finditer(section_patterns[1], content, re.DOTALL)
        for match in improvement_sections:
            improvement_text = match.group(1)
            self.process_improvements_section(improvement_text, content, match.start())
            
        # Extrai outro formato comum (itens numerados com código)
        numbered_implementations = re.finditer(section_patterns[2], content, re.DOTALL)
        for match in numbered_implementations:
            number = match.group(1)
            emoji = match.group(2)
            title = match.group(3).strip()
            description = match.group(4).strip()
            code_example = match.group(5).strip()
            
            category = self.extract_category_from_context(content, match.start())
            priority = self.determine_priority_from_emoji(emoji)
            tags = self.extract_tags(title, description, category)
            
            self.add_implementation(
                title=title,
                description=description,
                code_example=code_example,
                category=category,
                priority=priority,
                tags=tags
            )
    
    def process_priority_section(self, section_text: str, priority: str):
        """Processa uma seção de prioridade para extrair implementações"""
        # Padrão para encontrar implementações
        impl_pattern = r'(\d+)\.\s+\*\*([\w\s/]+)\*\*\s+(.*?)```rust([^`]+)```'
        
        implementations = re.finditer(impl_pattern, section_text, re.DOTALL)
        for impl in implementations:
            number = impl.group(1)
            title = impl.group(2).strip()
            description = impl.group(3).strip()
            code_example = impl.group(4).strip()
            
            # Determinar categoria baseada no título e descrição
            if "localização" in title.lower() or "geo" in title.lower():
                category = "Segurança"
            elif "sessão" in title.lower() or "session" in title.lower():
                category = "Gerenciamento de Sessões"
            elif "log" in title.lower() or "audit" in title.lower() or "monit" in title.lower():
                category = "Auditoria"
            elif "authn" in title.lower() or "webauthn" in title.lower() or "passkey" in title.lower():
                category = "Autenticação"
            elif "webhook" in title.lower() or "hook" in title.lower():
                category = "Integração"
            else:
                category = "Geral"
            
            tags = self.extract_tags(title, description, category)
            
            self.add_implementation(
                title=title,
                description=description,
                code_example=code_example,
                category=category,
                priority=priority,
                tags=tags
            )
    
    def process_improvements_section(self, section_text: str, full_content: str, section_start: int):
        """Processa uma seção de 'Melhorias Sugeridas' para extrair implementações individuais"""
        
        category = self.extract_category_from_context(full_content, section_start)
        
        # Primeiro padrão para itens numerados: "1. 🔒 **Nome** - Descrição:"
        item_pattern = r'(\d+)\.\s+([🔒✨🔧📝]*)\s*\*\*([\w\s/]+)\*\*\s*-\s*(.*?):\s*```rust([^`]+)```'
        items = re.finditer(item_pattern, section_text, re.DOTALL)
        
        for item in items:
            number = item.group(1)
            emoji = item.group(2)
            title = item.group(3).strip()
            description = item.group(4).strip()
            code_example = item.group(5).strip()
            
            priority = self.determine_priority_from_emoji(emoji)
            tags = self.extract_tags(title, description, category)
            
            self.add_implementation(
                title=title,
                description=description,
                code_example=code_example,
                category=category,
                priority=priority,
                tags=tags
            )
        
        # Segundo padrão mais simples: "1. **Nome** - Descrição:"
        simple_pattern = r'(\d+)\.\s+\*\*([\w\s/]+)\*\*\s*-\s*(.*?)(?=\d+\.\s+\*\*|\Z)'
        simple_items = re.finditer(simple_pattern, section_text, re.DOTALL)
        
        for item in simple_items:
            number = item.group(1)
            title = item.group(2).strip()
            description = item.group(3).strip()
            
            # Tenta extrair um exemplo de código, se existir
            code_match = re.search(r'```rust([^`]+)```', description, re.DOTALL)
            if code_match:
                code_example = code_match.group(1).strip()
                description = description.replace(code_match.group(0), "").strip()
            else:
                code_example = ""
            
            priority = self.determine_priority_from_context(title, description)
            tags = self.extract_tags(title, description, category)
            
            self.add_implementation(
                title=title,
                description=description,
                code_example=code_example,
                category=category,
                priority=priority,
                tags=tags
            )
    
    def extract_category_from_context(self, content: str, position: int) -> str:
        """Tenta extrair a categoria baseado no contexto (cabeçalho anterior)"""
        # Encontra o último cabeçalho antes da posição
        headers = re.finditer(r'###\s+`([^`]+)`', content[:position])
        last_header = None
        for header in headers:
            last_header = header.group(1)
        
        if last_header:
            # Remove "src/" e retorna apenas o módulo
            return last_header.replace("src/", "").split('/')[0].capitalize()
        
        # Procura outros padrões de cabeçalho
        module_headers = re.finditer(r'###\s+`?src/([^/`]+)', content[:position])
        last_module = None
        for module in module_headers:
            last_module = module.group(1)
            
        if last_module:
            return last_module.capitalize()
        
        # Se não encontrou cabeçalho, procura outras pistas de categoria
        section_before = content[max(0, position-500):position]
        
        category_patterns = {
            "Segurança": ["segurança", "security", "auth", "autenticação", "password", "senha", "criptografia", "jwt", "token"],
            "Banco de Dados": ["banco de dados", "database", "db", "sql", "sqlite", "postgresql", "migration"],
            "Interface": ["interface", "ui", "user interface", "frontend", "html", "css"],
            "API": ["api", "rest", "endpoint", "controller", "rota", "route"],
            "Auditoria": ["log", "audit", "registro", "monitora"],
            "Email": ["email", "smtp", "notificação", "notification"],
            "Configuração": ["config", "configuração", "settings", "ambiente", "env"]
        }
        
        for category, terms in category_patterns.items():
            if any(term in section_before.lower() for term in terms):
                return category
        
        return "Geral"
    
    def determine_priority(self, content: str, position: int) -> str:
        """Determina a prioridade baseada no contexto"""
        # Procura por indicadores de prioridade no contexto
        context = content[max(0, position-1000):position+1000]
        
        if "alta prioridade" in context.lower() or "prioridade alta" in context.lower():
            return "alta"
        elif "baixa prioridade" in context.lower() or "prioridade baixa" in context.lower():
            return "baixa"
        
        # Procura seções de prioridade
        if "Prioridade Alta" in context or "alta prioridade" in context.lower():
            return "alta"
        elif "Prioridade Média" in context or "média prioridade" in context.lower():
            return "média"
        elif "Prioridade Baixa" in context or "baixa prioridade" in context.lower():
            return "baixa"
        
        # Default
        return "média"
    
    def determine_priority_from_emoji(self, emoji: str) -> str:
        """Determina a prioridade baseada no emoji usado"""
        if "🔒" in emoji or "🛡️" in emoji or "🔐" in emoji:  # Segurança é geralmente alta prioridade
            return "alta"
        elif "🔧" in emoji or "🚀" in emoji:  # Ferramentas/configurações são média prioridade
            return "média"
        elif "📝" in emoji or "✨" in emoji:  # Documentação é geralmente baixa prioridade
            return "baixa"
        else:
            return "média"  # Padrão
    
    def determine_priority_from_context(self, title: str, description: str) -> str:
        """Determina a prioridade baseada no título e descrição"""
        text = (title + " " + description).lower()
        
        high_priority_terms = ["crítica", "urgente", "segurança", "vulnerabilidade", "falha", "senha", "autenticação"]
        low_priority_terms = ["cosmético", "refatoração", "documentação", "visual", "estético"]
        
        if any(term in text for term in high_priority_terms):
            return "alta"
        elif any(term in text for term in low_priority_terms):
            return "baixa"
        else:
            return "média"
    
    def extract_tags(self, title: str, description: str, category: str) -> List[str]:
        """Extrai tags baseadas no título, descrição e categoria"""
        tags = []
        
        # Adiciona a categoria como tag
        tags.append(category.lower())
        
        # Palavras-chave comuns para adicionar como tags
        keyword_mapping = {
            "segurança": ["segurança", "security", "proteção"],
            "jwt": ["jwt", "token", "autenticação"],
            "password": ["senha", "password", "credential", "credencial"],
            "cache": ["cache", "performance", "otimização"],
            "log": ["log", "logging", "monitoramento", "auditoria", "audit"],
            "database": ["banco de dados", "database", "db", "armazenamento", "persistência"],
            "test": ["teste", "testing", "tdd"],
            "api": ["api", "endpoint", "rest"],
            "ui": ["interface", "ui", "frontend"],
            "auth": ["autenticação", "auth", "login"],
            "user": ["usuário", "user", "perfil"],
            "email": ["email", "smtp", "notificação"],
            "config": ["configuração", "config", "settings"],
            "session": ["sessão", "session"],
            "webhook": ["webhook", "callback", "evento"],
            "oauth": ["oauth", "social", "external"],
            "2fa": ["2fa", "mfa", "dois fatores"],
            "geolocation": ["geo", "localização", "location"],
            "risk": ["risco", "risk", "análise", "detection"],
            "backup": ["backup", "cópia", "restore"],
            "monitoring": ["monitoramento", "monitor", "observabilidade"],
            "rate-limit": ["taxa", "limite", "rate", "throttle"],
            "recovery": ["recuperação", "recovery", "restore"]
        }
        
        # Verifica texto completo (título + descrição)
        full_text = (title + " " + description).lower()
        
        for tag, keywords in keyword_mapping.items():
            if any(keyword in full_text for keyword in keywords):
                if tag not in tags:
                    tags.append(tag)
        
        return tags
    
    def add_implementation(self, title: str, description: str, code_example: str, 
                           category: str, priority: str, tags: List[str]):
        """Adiciona uma implementação à lista"""
        # Removida a verificação de duplicatas para permitir implementações com mesmo título
        # mas de contextos diferentes no documento
        
        implementation = {
            "id": self.current_id,
            "title": title,
            "description": description,
            "priority": priority,
            "category": category,
            "code_example": code_example,
            "status": "pendente",
            "tags": tags,
            # Adiciona uma referência ao contexto para diferenciar implementações com mesmo título
            "context": category
        }
        
        self.implementations.append(implementation)
        self.current_id += 1
        
        print(f"✅ Extraída implementação: {title} [{category}]")
    
    def save_json(self):
        """Salva as implementações em um arquivo JSON"""
        try:
            # Se já existe um arquivo, lê as implementações existentes
            existing_implementations = []
            if os.path.exists(self.output_file):
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    try:
                        existing_implementations = json.load(f)
                    except json.JSONDecodeError:
                        # Se o arquivo estiver vazio ou mal-formado, começa com uma lista vazia
                        existing_implementations = []
            
            # Adiciona as novas implementações
            # Não vamos mais filtrar por título, mas vamos usar uma verificação mais precisa
            # baseada em título + categoria + parte da descrição para evitar duplicatas
            existing_signatures = []
            for impl in existing_implementations:
                title = impl.get("title", "")
                category = impl.get("category", "")
                # Usamos os primeiros 50 caracteres da descrição como parte da assinatura
                desc_start = impl.get("description", "")[:50] if impl.get("description") else ""
                signature = f"{title}|{category}|{desc_start}"
                existing_signatures.append(signature)
            
            # Adiciona novas implementações 
            for impl in self.implementations:
                title = impl.get("title", "")
                category = impl.get("category", "")
                desc_start = impl.get("description", "")[:50] if impl.get("description") else ""
                signature = f"{title}|{category}|{desc_start}"
                
                if signature not in existing_signatures:
                    existing_implementations.append(impl)
                    existing_signatures.append(signature)
            
            # Reordena os IDs para garantir unicidade
            for i, impl in enumerate(existing_implementations, 1):
                impl["id"] = i
            
            # Salva o arquivo JSON
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(existing_implementations, f, ensure_ascii=False, indent=2)
            
            print(f"✅ Salvo arquivo JSON com {len(existing_implementations)} implementações em {self.output_file}")
            
        except Exception as e:
            print(f"❌ Erro ao salvar o arquivo JSON: {e}")
            return False
        
        return True


def main():
    parser = argparse.ArgumentParser(description="Conversor de releases.md para JSON 🚀")
    parser.add_argument("--input", default="releases.md", help="Arquivo de entrada (releases.md)")
    parser.add_argument("--output", default="releases_implementations.json", help="Arquivo de saída (JSON)")
    args = parser.parse_args()
    
    converter = ReleaseParser(args.input, args.output)
    converter.parse()


if __name__ == "__main__":
    main() 