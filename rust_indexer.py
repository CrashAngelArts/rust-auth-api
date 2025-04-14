import os
import re
import sqlite3
import argparse
import markdown
from pathlib import Path

class RustCodeIndexer:
    def __init__(self, db_path="rust_code_index.db"):
        """🔍 Inicializa o indexador de código Rust"""
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.create_tables()
        
    def create_tables(self):
        """📊 Cria tabelas no banco de dados se não existirem"""
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            path TEXT UNIQUE,
            name TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS structs (
            id INTEGER PRIMARY KEY,
            file_id INTEGER,
            name TEXT,
            description TEXT,
            FOREIGN KEY (file_id) REFERENCES files (id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS functions (
            id INTEGER PRIMARY KEY,
            file_id INTEGER,
            struct_id INTEGER NULL,
            name TEXT,
            signature TEXT,
            description TEXT,
            is_method INTEGER,
            is_impl INTEGER,
            FOREIGN KEY (file_id) REFERENCES files (id),
            FOREIGN KEY (struct_id) REFERENCES structs (id)
        )
        ''')
        
        self.conn.commit()
    
    def parse_rust_file(self, file_path):
        """📝 Analisa um arquivo Rust para extrair estruturas e funções"""
        print(f"🔍 Analisando: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"❌ Erro ao ler arquivo {file_path}: {e}")
            return
        
        # Adiciona o arquivo ao banco
        cursor = self.conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO files (path, name) VALUES (?, ?)",
                      (file_path, os.path.basename(file_path)))
        self.conn.commit()
        
        cursor.execute("SELECT id FROM files WHERE path = ?", (file_path,))
        file_id = cursor.fetchone()[0]
        
        # Extrai structs
        struct_pattern = r'(?:///\s*([^\n]*)\s*\n)*\s*(?:pub\s+)?struct\s+([A-Za-z0-9_]+)'
        struct_matches = re.finditer(struct_pattern, content)
        
        structs = {}
        for match in struct_matches:
            description = match.group(1) or ""
            struct_name = match.group(2)
            
            # Captura comentários multi-linha
            start_pos = match.start()
            comment_section = content[max(0, start_pos-200):start_pos]
            comments = []
            
            for line in reversed(comment_section.split('\n')):
                line = line.strip()
                if line.startswith('///'):
                    comments.insert(0, line[3:].strip())
                elif line.startswith('//!'):
                    comments.insert(0, line[3:].strip())
                elif not line.strip():
                    continue
                else:
                    break
                    
            full_description = description if not comments else '\n'.join(comments)
            
            cursor.execute(
                "INSERT INTO structs (file_id, name, description) VALUES (?, ?, ?)",
                (file_id, struct_name, full_description)
            )
            self.conn.commit()
            
            cursor.execute("SELECT id FROM structs WHERE file_id = ? AND name = ?", 
                          (file_id, struct_name))
            struct_id = cursor.fetchone()[0]
            structs[struct_name] = struct_id
        
        # Extrai funções e métodos
        function_pattern = r'(?:///\s*((?:[^\n]*\n\s*///\s*)*[^\n]*)\s*\n)?\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*(\([^)]*\)(?:\s*->\s*[^{;]+)?)'
        function_matches = re.finditer(function_pattern, content)
        
        for match in function_matches:
            description = match.group(1) or ""
            func_name = match.group(2)
            signature = match.group(3)
            
            # Captura comentários multi-linha
            start_pos = match.start()
            comment_section = content[max(0, start_pos-200):start_pos]
            comments = []
            
            for line in reversed(comment_section.split('\n')):
                line = line.strip()
                if line.startswith('///'):
                    comments.insert(0, line[3:].strip())
                elif line.startswith('//!'):
                    comments.insert(0, line[3:].strip())
                elif not line.strip():
                    continue
                else:
                    break
                    
            full_description = description if not comments else '\n'.join(comments)
            
            # Verifica se é um método de implementação
            impl_section = content[max(0, start_pos-500):start_pos]
            impl_match = re.search(r'impl(?:<[^>]+>)?\s+(?:for\s+)?([A-Za-z0-9_]+)', impl_section)
            
            struct_id = None
            is_method = 0
            is_impl = 0
            
            if impl_match:
                struct_name = impl_match.group(1)
                if struct_name in structs:
                    struct_id = structs[struct_name]
                    is_method = 1
                    is_impl = 1
            
            cursor.execute(
                """INSERT INTO functions 
                   (file_id, struct_id, name, signature, description, is_method, is_impl)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (file_id, struct_id, func_name, signature, full_description, is_method, is_impl)
            )
            self.conn.commit()
    
    def index_directory(self, directory):
        """📂 Indexa todos os arquivos Rust em um diretório recursivamente"""
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.rs'):
                    full_path = os.path.join(root, file)
                    self.parse_rust_file(full_path)
    
    def export_to_markdown(self, output_file="Index.md"):
        """📄 Exporta os dados para um arquivo Markdown"""
        cursor = self.conn.cursor()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# 📚 Índice do Código Rust\n\n")
            
            # Lista de arquivos
            cursor.execute("SELECT id, path, name FROM files ORDER BY path")
            files = cursor.fetchall()
            
            f.write("## 📂 Arquivos\n\n")
            for file_id, path, name in files:
                f.write(f"### 📄 {name}\n")
                f.write(f"**Caminho:** `{path}`\n\n")
                
                # Estruturas no arquivo
                cursor.execute("SELECT id, name, description FROM structs WHERE file_id = ?", (file_id,))
                structs = cursor.fetchall()
                
                if structs:
                    f.write("#### 🧩 Estruturas\n\n")
                    for struct_id, struct_name, struct_desc in structs:
                        f.write(f"##### 🔹 `{struct_name}`\n\n")
                        if struct_desc:
                            f.write(f"{struct_desc}\n\n")
                        
                        # Métodos da estrutura
                        cursor.execute(
                            """SELECT name, signature, description FROM functions 
                               WHERE file_id = ? AND struct_id = ? ORDER BY name""", 
                            (file_id, struct_id)
                        )
                        methods = cursor.fetchall()
                        
                        if methods:
                            f.write("**Métodos:**\n\n")
                            for method_name, method_sig, method_desc in methods:
                                f.write(f"- `{method_name}{method_sig}`\n")
                                if method_desc:
                                    f.write(f"  - 📝 {method_desc}\n")
                            f.write("\n")
                
                # Funções no arquivo (que não são métodos)
                cursor.execute(
                    """SELECT name, signature, description FROM functions 
                       WHERE file_id = ? AND struct_id IS NULL ORDER BY name""", 
                    (file_id,)
                )
                functions = cursor.fetchall()
                
                if functions:
                    f.write("#### 🔧 Funções\n\n")
                    for func_name, func_sig, func_desc in functions:
                        f.write(f"##### 🔸 `{func_name}{func_sig}`\n\n")
                        if func_desc:
                            f.write(f"{func_desc}\n\n")
                
                f.write("\n---\n\n")
            
            f.write("\n## 📊 Resumo\n\n")
            cursor.execute("SELECT COUNT(*) FROM files")
            f.write(f"- Total de arquivos: **{cursor.fetchone()[0]}**\n")
            cursor.execute("SELECT COUNT(*) FROM structs")
            f.write(f"- Total de estruturas: **{cursor.fetchone()[0]}**\n")
            cursor.execute("SELECT COUNT(*) FROM functions")
            f.write(f"- Total de funções: **{cursor.fetchone()[0]}**\n")
        
        print(f"✅ Índice exportado para {output_file}")
    
    def export_tree(self, output_file="ArvoreIndex.md"):
        """🌳 Exporta os dados em formato de árvore para um arquivo Markdown"""
        cursor = self.conn.cursor()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# 🌲 Árvore de Funções do Código Rust\n\n")
            
            # Lista de arquivos
            cursor.execute("SELECT id, path, name FROM files ORDER BY path")
            files = cursor.fetchall()
            
            for file_id, path, name in files:
                f.write(f"## 📄 {name}\n\n")
                
                # Estruturas no arquivo
                cursor.execute("SELECT id, name, description FROM structs WHERE file_id = ?", (file_id,))
                structs = cursor.fetchall()
                
                if structs:
                    for struct_id, struct_name, struct_desc in structs:
                        f.write(f"└── 🔹 `{struct_name}`")
                        if struct_desc and struct_desc.strip():
                            f.write(f" - {struct_desc.split('\n')[0]}")
                        f.write("\n")
                        
                        # Métodos da estrutura
                        cursor.execute(
                            """SELECT name, signature, description FROM functions 
                               WHERE file_id = ? AND struct_id = ? ORDER BY name""", 
                            (file_id, struct_id)
                        )
                        methods = cursor.fetchall()
                        
                        for i, (method_name, _, method_desc) in enumerate(methods):
                            is_last = i == len(methods) - 1
                            prefix = "    └── " if is_last else "    ├── "
                            f.write(f"{prefix}🔸 `{method_name}`")
                            if method_desc and method_desc.strip():
                                # Pega apenas a primeira linha da descrição para manter compacto
                                f.write(f" - {method_desc.split('\n')[0]}")
                            f.write("\n")
                
                # Funções no arquivo (que não são métodos)
                cursor.execute(
                    """SELECT name, signature, description FROM functions 
                       WHERE file_id = ? AND struct_id IS NULL ORDER BY name""", 
                    (file_id,)
                )
                functions = cursor.fetchall()
                
                if functions:
                    for i, (func_name, _, func_desc) in enumerate(functions):
                        is_last = i == len(functions) - 1 and not structs
                        prefix = "└── " if is_last else "├── "
                        f.write(f"{prefix}🔧 `{func_name}`")
                        if func_desc and func_desc.strip():
                            # Pega apenas a primeira linha da descrição para manter compacto
                            f.write(f" - {func_desc.split('\n')[0]}")
                        f.write("\n")
                
                f.write("\n")
            
        print(f"✅ Árvore exportada para {output_file}")
    
    def search(self, term):
        """🔎 Pesquisa no banco de dados"""
        cursor = self.conn.cursor()
        results = []
        
        # Pesquisa em structs
        cursor.execute("""
            SELECT s.name, s.description, f.path 
            FROM structs s
            JOIN files f ON s.file_id = f.id
            WHERE s.name LIKE ? OR s.description LIKE ?
        """, (f'%{term}%', f'%{term}%'))
        structs = cursor.fetchall()
        
        for name, desc, path in structs:
            results.append({
                'type': 'struct',
                'name': name,
                'description': desc,
                'file': path
            })
        
        # Pesquisa em funções
        cursor.execute("""
            SELECT fn.name, fn.signature, fn.description, f.path, s.name as struct_name
            FROM functions fn
            JOIN files f ON fn.file_id = f.id
            LEFT JOIN structs s ON fn.struct_id = s.id
            WHERE fn.name LIKE ? OR fn.description LIKE ?
        """, (f'%{term}%', f'%{term}%'))
        functions = cursor.fetchall()
        
        for name, sig, desc, path, struct_name in functions:
            results.append({
                'type': 'function' if not struct_name else 'method',
                'name': name,
                'signature': sig,
                'description': desc,
                'file': path,
                'struct': struct_name
            })
        
        return results
    
    def close(self):
        """🔒 Fecha a conexão com o banco de dados"""
        self.conn.close()

def main():
    parser = argparse.ArgumentParser(description="🦀 Indexador de Código Rust")
    subparsers = parser.add_subparsers(dest="command", help="Comandos disponíveis")
    
    # Comando para indexar
    index_parser = subparsers.add_parser("indexar", help="Indexa um diretório de código Rust")
    index_parser.add_argument("diretorio", help="Diretório raiz com código Rust para indexar")
    index_parser.add_argument("--db", default="rust_code_index.db", help="Caminho para o banco de dados SQLite")
    
    # Comando para pesquisar
    search_parser = subparsers.add_parser("pesquisar", help="Pesquisa no índice")
    search_parser.add_argument("termo", help="Termo para pesquisar")
    search_parser.add_argument("--db", default="rust_code_index.db", help="Caminho para o banco de dados SQLite")
    
    # Comando para exportar
    export_parser = subparsers.add_parser("exportar", help="Exporta o índice para Markdown")
    export_parser.add_argument("--output", default="Index.md", help="Arquivo de saída Markdown")
    export_parser.add_argument("--db", default="rust_code_index.db", help="Caminho para o banco de dados SQLite")
    
    # Comando para exportar como árvore
    tree_parser = subparsers.add_parser("arvore", help="Exporta o índice como árvore")
    tree_parser.add_argument("--output", default="ArvoreIndex.md", help="Arquivo de saída Markdown")
    tree_parser.add_argument("--db", default="rust_code_index.db", help="Caminho para o banco de dados SQLite")
    
    args = parser.parse_args()
    
    if args.command == "indexar":
        indexer = RustCodeIndexer(args.db)
        print(f"🔍 Indexando diretório: {args.diretorio}")
        indexer.index_directory(args.diretorio)
        print(f"✅ Indexação concluída! Banco de dados salvo em {args.db}")
        indexer.close()
    
    elif args.command == "pesquisar":
        indexer = RustCodeIndexer(args.db)
        results = indexer.search(args.termo)
        
        if not results:
            print(f"❌ Nenhum resultado encontrado para '{args.termo}'")
        else:
            print(f"🔍 Resultados para '{args.termo}':")
            for i, result in enumerate(results, 1):
                print(f"\n{i}. {result['type'].upper()}: {result['name']}")
                if result['type'] in ('function', 'method'):
                    print(f"   Assinatura: {result['signature']}")
                if result['description']:
                    print(f"   Descrição: {result['description']}")
                print(f"   Arquivo: {result['file']}")
                if 'struct' in result and result['struct']:
                    print(f"   Struct: {result['struct']}")
        
        indexer.close()
    
    elif args.command == "exportar":
        indexer = RustCodeIndexer(args.db)
        indexer.export_to_markdown(args.output)
        indexer.close()
    
    elif args.command == "arvore":
        indexer = RustCodeIndexer(args.db)
        indexer.export_tree(args.output)
        indexer.close()
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()