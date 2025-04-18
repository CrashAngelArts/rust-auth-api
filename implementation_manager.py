#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Script para gerenciar tarefas de implementação

import os
import json
import argparse
import datetime
from enum import Enum
from typing import List, Dict, Optional, Any

class PriorityLevel(Enum):
    HIGH = "alta"
    MEDIUM = "média"
    LOW = "baixa"

class ImplementationStatus(Enum):
    PENDING = "pendente"
    IN_PROGRESS = "em progresso"
    COMPLETED = "concluída"
    CANCELED = "cancelada"

class Implementation:
    def __init__(
        self,
        id: int,
        title: str,
        description: str,
        priority: PriorityLevel,
        category: str,
        code_example: Optional[str] = None,
        status: ImplementationStatus = ImplementationStatus.PENDING,
        checkout_date: Optional[str] = None,
        completed_date: Optional[str] = None,
        estimated_hours: Optional[float] = None,
        tags: List[str] = None
    ):
        self.id = id
        self.title = title
        self.description = description
        self.priority = priority
        self.category = category
        self.code_example = code_example
        self.status = status
        self.checkout_date = checkout_date
        self.completed_date = completed_date
        self.estimated_hours = estimated_hours
        self.tags = tags or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "category": self.category,
            "code_example": self.code_example,
            "status": self.status.value,
            "checkout_date": self.checkout_date,
            "completed_date": self.completed_date,
            "estimated_hours": self.estimated_hours,
            "tags": self.tags
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Implementation':
        return cls(
            id=data["id"],
            title=data["title"],
            description=data["description"],
            priority=PriorityLevel(data["priority"]),
            category=data["category"],
            code_example=data.get("code_example"),
            status=ImplementationStatus(data["status"]),
            checkout_date=data.get("checkout_date"),
            completed_date=data.get("completed_date"),
            estimated_hours=data.get("estimated_hours"),
            tags=data.get("tags", [])
        )

    def __str__(self) -> str:
        return f"#{self.id}: {self.title} [{self.priority.value}] - {self.status.value}"

    def details(self) -> str:
        result = [
            f"ID: {self.id}",
            f"Titulo: {self.title}",
            f"Prioridade: {self.priority.value}",
            f"Categoria: {self.category}",
            f"Status: {self.status.value}",
            f"Descricao: {self.description}"
        ]
        
        if self.checkout_date:
            result.append(f"Data de checkout: {self.checkout_date}")
        
        if self.completed_date:
            result.append(f"Data de conclusao: {self.completed_date}")
        
        if self.estimated_hours:
            result.append(f"Horas estimadas: {self.estimated_hours}")
            
        if self.tags:
            result.append(f"Tags: {', '.join(self.tags)}")
            
        if self.code_example:
            result.append("\nExemplo de codigo:")
            result.append(f"```\n{self.code_example}\n```")
            
        return "\n".join(result)


class ImplementationManager:
    def __init__(self, data_file: str = "implementations.json"):
        self.data_file = data_file
        self.implementations: List[Implementation] = []
        self.load_data()

    def load_data(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.implementations = [Implementation.from_dict(item) for item in data]
            except Exception as e:
                print(f"❌ Erro ao carregar dados: {e}")
                self.implementations = []
        else:
            self.implementations = []
            print(f"📝 Arquivo de dados {self.data_file} não encontrado. Iniciando com lista vazia.")

    def save_data(self):
        try:
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump([impl.to_dict() for impl in self.implementations], f, ensure_ascii=False, indent=2)
            print(f"✅ Dados salvos com sucesso em {self.data_file}!")
        except Exception as e:
            print(f"❌ Erro ao salvar dados: {e}")

    def add_implementation(self, implementation: Implementation):
        if not implementation.id:
            # Auto-generate ID if not provided
            implementation.id = self.get_next_id()
        self.implementations.append(implementation)
        self.save_data()
        print(f"✅ Implementação '{implementation.title}' adicionada com sucesso!")
        return implementation

    def get_next_id(self) -> int:
        return max([impl.id for impl in self.implementations], default=0) + 1

    def get_implementation_by_id(self, id: int) -> Optional[Implementation]:
        for impl in self.implementations:
            if impl.id == id:
                return impl
        return None

    def list_implementations(self, 
                            status: Optional[ImplementationStatus] = None,
                            priority: Optional[PriorityLevel] = None,
                            category: Optional[str] = None) -> List[Implementation]:
        
        filtered_implementations = self.implementations
        
        if status:
            filtered_implementations = [impl for impl in filtered_implementations if impl.status == status]
            
        if priority:
            filtered_implementations = [impl for impl in filtered_implementations if impl.priority == priority]
            
        if category:
            filtered_implementations = [impl for impl in filtered_implementations if impl.category.lower() == category.lower()]
            
        return filtered_implementations

    def get_next_implementation(self) -> Optional[Implementation]:
        pending_implementations = self.list_implementations(status=ImplementationStatus.PENDING)
        if not pending_implementations:
            return None
        
        # Prioridade: alta > média > baixa
        for priority in [PriorityLevel.HIGH, PriorityLevel.MEDIUM, PriorityLevel.LOW]:
            priority_implementations = [impl for impl in pending_implementations if impl.priority == priority]
            if priority_implementations:
                return priority_implementations[0]
                
        return pending_implementations[0]  # Fallback, não deve ocorrer

    def checkout_implementation(self, implementation_id: int) -> bool:
        implementation = self.get_implementation_by_id(implementation_id)
        if not implementation:
            print(f"❌ Implementação com ID {implementation_id} não encontrada!")
            return False
            
        if implementation.status == ImplementationStatus.IN_PROGRESS:
            print(f"⚠️ Implementação '{implementation.title}' já está em progresso!")
            return False
            
        if implementation.status == ImplementationStatus.COMPLETED:
            print(f"⚠️ Implementação '{implementation.title}' já está concluída!")
            return False
            
        # Atualizar status
        implementation.status = ImplementationStatus.IN_PROGRESS
        implementation.checkout_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.save_data()
        
        print(f"✅ Checkout realizado para '{implementation.title}'")
        return True

    def complete_implementation(self, implementation_id: int) -> bool:
        implementation = self.get_implementation_by_id(implementation_id)
        if not implementation:
            print(f"❌ Implementação com ID {implementation_id} não encontrada!")
            return False
            
        if implementation.status == ImplementationStatus.COMPLETED:
            print(f"⚠️ Implementação '{implementation.title}' já está concluída!")
            return False
            
        # Atualizar status
        implementation.status = ImplementationStatus.COMPLETED
        implementation.completed_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.save_data()
        
        print(f"🎉 Implementação '{implementation.title}' marcada como concluída! Parabéns!")
        return True
        
    def cancel_implementation(self, implementation_id: int) -> bool:
        implementation = self.get_implementation_by_id(implementation_id)
        if not implementation:
            print(f"❌ Implementação com ID {implementation_id} não encontrada!")
            return False
            
        if implementation.status == ImplementationStatus.CANCELED:
            print(f"⚠️ Implementação '{implementation.title}' já está cancelada!")
            return False
            
        # Atualizar status
        implementation.status = ImplementationStatus.CANCELED
        self.save_data()
        
        print(f"❌ Implementação '{implementation.title}' cancelada.")
        return True
        
    def reset_implementation(self, implementation_id: int) -> bool:
        implementation = self.get_implementation_by_id(implementation_id)
        if not implementation:
            print(f"❌ Implementação com ID {implementation_id} não encontrada!")
            return False
            
        # Atualizar status
        implementation.status = ImplementationStatus.PENDING
        implementation.checkout_date = None
        implementation.completed_date = None
        self.save_data()
        
        print(f"🔄 Implementação '{implementation.title}' redefinida para pendente.")
        return True


def create_initial_implementations():
    manager = ImplementationManager()
    
    # Se já existirem implementações, não criar novamente
    if manager.implementations:
        return
    
    # Exemplos de implementações do arquivo releases.md
    implementations = [
        # Prioridade Alta
        Implementation(
            id=1,
            title="Código Único de Recuperação",
            description="Implementar sistema de códigos de recuperação únicos para usuários.",
            priority=PriorityLevel.HIGH,
            category="Segurança",
            tags=["recuperação", "segurança", "usuários"],
            code_example="// Adicionar campos na tabela de usuários\nCREATE TABLE IF NOT EXISTS recovery_codes (\n  id INTEGER PRIMARY KEY,\n  user_id INTEGER NOT NULL,\n  code TEXT NOT NULL,\n  created_at TEXT NOT NULL,\n  expires_at TEXT NOT NULL,\n  used INTEGER DEFAULT 0\n);"
        ),
        
        Implementation(
            id=2,
            title="Detecção de Localização Suspeita",
            description="Implementar análise de risco baseada em localização geográfica do login.",
            priority=PriorityLevel.HIGH,
            category="Segurança",
            tags=["análise de risco", "geolocalização", "segurança"],
            code_example="pub struct LocationRiskAnalyzer {\n    pub geo_database: GeoIpDatabase,\n    pub velocity_threshold_km_h: f64,\n    pub risk_threshold_distance_km: u32,\n}"
        ),
        
        Implementation(
            id=3,
            title="Análise de Horário de Login",
            description="Implementar detecção de atividades suspeitas baseadas em padrões temporais.",
            priority=PriorityLevel.HIGH,
            category="Segurança",
            tags=["análise de risco", "padrão temporal", "segurança"],
            code_example="pub struct TimePatternAnalyzer {\n    pub unusual_hour_threshold: f64,\n    pub timezone_mismatch_weight: f64,\n}"
        ),
        
        # Prioridade Média
        Implementation(
            id=4,
            title="Revogação de Sessão Individual",
            description="Permitir a revogação de sessões específicas do usuário.",
            priority=PriorityLevel.MEDIUM,
            category="Gerenciamento de Sessões",
            tags=["sessões", "revogação", "segurança"],
            code_example="pub async fn revoke_specific_session(\n    pool: &DbPool,\n    user_id: &str,\n    session_id: &str,\n) -> Result<bool, ApiError> {\n    // Implementação\n}"
        ),
        
        Implementation(
            id=5,
            title="Limite de Sessões Ativas",
            description="Implementar política de limitação de número de sessões simultâneas por usuário.",
            priority=PriorityLevel.MEDIUM,
            category="Gerenciamento de Sessões",
            tags=["sessões", "limite", "segurança"],
            code_example="pub struct SessionLimitPolicy {\n    pub max_sessions_per_user: u32,\n    pub revoke_strategy: RevocationStrategy,\n}"
        ),
        
        Implementation(
            id=6,
            title="Logs de Ações Críticas",
            description="Implementar registro detalhado de ações sensíveis no sistema.",
            priority=PriorityLevel.MEDIUM,
            category="Auditoria",
            tags=["logs", "auditoria", "segurança"],
            code_example="pub struct AuditLogEntry {\n    pub id: String,\n    pub user_id: Option<String>,\n    pub admin_id: Option<String>,\n    pub action: AuditAction,\n    // ...\n}"
        ),
        
        # Prioridade Baixa
        Implementation(
            id=7,
            title="WebAuthn/Passkeys",
            description="Implementar autenticação sem senha usando WebAuthn/FIDO2.",
            priority=PriorityLevel.LOW,
            category="Autenticação",
            tags=["webauthn", "passwordless", "fido2"],
            code_example="pub struct WebAuthnCredential {\n    pub id: String,\n    pub user_id: String,\n    pub public_key: String,\n    // ...\n}"
        ),
        
        Implementation(
            id=8,
            title="Sistema de Webhooks",
            description="Implementar sistema de notificações via webhooks para eventos do sistema.",
            priority=PriorityLevel.LOW,
            category="Integração",
            tags=["webhooks", "notificações", "integração"],
            code_example="pub struct WebhookSubscription {\n    pub id: String,\n    pub client_id: String,\n    pub event_types: Vec<String>,\n    // ...\n}"
        ),
        
        Implementation(
            id=9,
            title="Rotação de JWT Key",
            description="Implementar suporte para rotação de chaves JWT.",
            priority=PriorityLevel.MEDIUM,
            category="Segurança",
            tags=["jwt", "rotação de chaves", "segurança"],
            code_example="struct JwtKeyManager {\n    current_key: String,\n    previous_keys: Vec<String>,\n    rotation_timestamp: DateTime<Utc>,\n}"
        ),
        
        Implementation(
            id=10,
            title="Verificação de Integridade do Banco",
            description="Implementar verificação periódica de integridade do banco de dados.",
            priority=PriorityLevel.MEDIUM,
            category="Banco de Dados",
            tags=["banco de dados", "integridade", "manutenção"],
            code_example="fn validate_db_integrity(conn: &Connection) -> Result<(), ApiError> {\n    let integrity_check: String = conn.query_row(\"PRAGMA integrity_check\", [], |row| row.get(0))?;\n    if integrity_check != \"ok\" {\n        return Err(ApiError::DatabaseError(format!(\"Falha na verificação de integridade: {}\", integrity_check)));\n    }\n    Ok()\n}"
        ),
    ]
    
    for implementation in implementations:
        manager.add_implementation(implementation)
    
    print(f"🎉 {len(implementations)} implementações iniciais foram criadas!")


def setup_argparse():
    parser = argparse.ArgumentParser(description="Gerenciador de Implementações Rust Auth API 🚀")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponíveis")
    
    # Comando: list
    list_parser = subparsers.add_parser("list", help="Listar implementações")
    list_parser.add_argument("--status", choices=["pendente", "em progresso", "concluída", "cancelada"], 
                             help="Filtrar por status")
    list_parser.add_argument("--priority", choices=["alta", "média", "baixa"], 
                             help="Filtrar por prioridade")
    list_parser.add_argument("--category", help="Filtrar por categoria")
    
    # Comando: next
    subparsers.add_parser("next", help="Ver próxima implementação recomendada")
    
    # Comando: show
    show_parser = subparsers.add_parser("show", help="Exibir detalhes de uma implementação")
    show_parser.add_argument("id", type=int, help="ID da implementação")
    
    # Comando: checkout
    checkout_parser = subparsers.add_parser("checkout", help="Iniciar trabalho em uma implementação")
    checkout_parser.add_argument("id", type=int, help="ID da implementação")
    
    # Comando: complete
    complete_parser = subparsers.add_parser("complete", help="Marcar implementação como concluída")
    complete_parser.add_argument("id", type=int, help="ID da implementação")
    
    # Comando: cancel
    cancel_parser = subparsers.add_parser("cancel", help="Cancelar implementação")
    cancel_parser.add_argument("id", type=int, help="ID da implementação")
    
    # Comando: reset
    reset_parser = subparsers.add_parser("reset", help="Redefinir implementação para pendente")
    reset_parser.add_argument("id", type=int, help="ID da implementação")
    
    # Comando: add
    add_parser = subparsers.add_parser("add", help="Adicionar nova implementação")
    add_parser.add_argument("--title", required=True, help="Título da implementação")
    add_parser.add_argument("--description", required=True, help="Descrição da implementação")
    add_parser.add_argument("--priority", required=True, choices=["alta", "média", "baixa"], 
                            help="Prioridade da implementação")
    add_parser.add_argument("--category", required=True, help="Categoria da implementação")
    add_parser.add_argument("--tags", help="Tags separadas por vírgula")
    add_parser.add_argument("--code", help="Exemplo de código")
    add_parser.add_argument("--hours", type=float, help="Horas estimadas")
    
    # Comando: stats
    subparsers.add_parser("stats", help="Mostrar estatísticas das implementações")
    
    return parser


def main():
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Criar implementações iniciais se necessário
    create_initial_implementations()
    
    manager = ImplementationManager()
    
    if args.command == "list":
        status = None
        if args.status:
            status = ImplementationStatus(args.status)
            
        priority = None
        if args.priority:
            priority = PriorityLevel(args.priority)
            
        implementations = manager.list_implementations(status=status, priority=priority, category=args.category)
        
        status_filter = f" com status '{args.status}'" if args.status else ""
        priority_filter = f" com prioridade '{args.priority}'" if args.priority else ""
        category_filter = f" na categoria '{args.category}'" if args.category else ""
        
        print(f"\n📋 Lista de Implementações{status_filter}{priority_filter}{category_filter}:\n")
        
        if not implementations:
            print("   Nenhuma implementação encontrada com estes filtros.")
            return
        
        for impl in implementations:
            print(f"   {impl}")
    
    elif args.command == "next":
        next_implementation = manager.get_next_implementation()
        if not next_implementation:
            print("\nNao ha implementacoes pendentes! Tudo concluido!")
        else:
            print("\nProxima implementacao recomendada:\n")
            print(next_implementation.details())
    
    elif args.command == "show":
        implementation = manager.get_implementation_by_id(args.id)
        if not implementation:
            print(f"\n❌ Implementação com ID {args.id} não encontrada!")
        else:
            print(f"\n📝 Detalhes da Implementação #{args.id}:\n")
            print(implementation.details())
    
    elif args.command == "checkout":
        manager.checkout_implementation(args.id)
    
    elif args.command == "complete":
        manager.complete_implementation(args.id)
    
    elif args.command == "cancel":
        manager.cancel_implementation(args.id)
    
    elif args.command == "reset":
        manager.reset_implementation(args.id)
    
    elif args.command == "add":
        tags = args.tags.split(",") if args.tags else []
        tags = [tag.strip() for tag in tags]
        
        implementation = Implementation(
            id=manager.get_next_id(),
            title=args.title,
            description=args.description,
            priority=PriorityLevel(args.priority),
            category=args.category,
            code_example=args.code,
            tags=tags,
            estimated_hours=args.hours
        )
        
        manager.add_implementation(implementation)
    
    elif args.command == "stats":
        all_implementations = manager.implementations
        
        # Contagem por status
        status_counts = {}
        for status in ImplementationStatus:
            status_counts[status.value] = len([i for i in all_implementations if i.status == status])
        
        # Contagem por prioridade
        priority_counts = {}
        for priority in PriorityLevel:
            priority_counts[priority.value] = len([i for i in all_implementations if i.priority == priority])
        
        # Categorias
        categories = {}
        for impl in all_implementations:
            categories[impl.category] = categories.get(impl.category, 0) + 1
        
        # Implementações concluídas
        completed = [i for i in all_implementations if i.status == ImplementationStatus.COMPLETED]
        completed_percent = (len(completed) / len(all_implementations)) * 100 if all_implementations else 0
        
        print("\n📊 Estatísticas de Implementações:\n")
        print(f"   Total de implementações: {len(all_implementations)}")
        print(f"   Progresso geral: {completed_percent:.1f}% concluído")
        
        print("\n   Por Status:")
        for status, count in status_counts.items():
            print(f"      - {status}: {count}")
        
        print("\n   Por Prioridade:")
        for priority, count in priority_counts.items():
            print(f"      - {priority}: {count}")
        
        print("\n   Por Categoria:")
        for category, count in categories.items():
            print(f"      - {category}: {count}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 