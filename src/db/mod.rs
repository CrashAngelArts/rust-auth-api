// Remover módulos não utilizados
// pub mod migrations;
// pub mod pool;

use crate::errors::ApiError;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
// Remover import duplicado, precisamos apenas da macro
use refinery_macros::embed_migrations;
use rusqlite::Connection;
use std::path::Path;
use tracing::{error, info}; // <-- Adicionar 'error' ao import do tracing
// Remover imports não utilizados:
// use crate::{models::role::Role, models::permission::Permission};
use rusqlite::{params, Error as RusqliteError, OptionalExtension}; // <-- Adicionar OptionalExtension
use uuid::Uuid; // Adicionar Uuid

// Incorpora as migrações SQL do diretório 'migrations'
embed_migrations!("migrations");

pub type DbPool = Pool<SqliteConnectionManager>;
// pub type DbConnection = r2d2::PooledConnection<SqliteConnectionManager>; // Não utilizado

/// Função para semear dados RBAC essenciais (permissões e papel admin)
fn seed_rbac_data(conn: &mut Connection) -> Result<(), RusqliteError> {
    info!("🌱 Verificando e semeando dados RBAC essenciais...");

    let tx = conn.transaction()?;

    // 1. Definir Permissões Essenciais
    let permissions = vec![
        ("permissions:manage", "Gerenciar todas as permissões."),
        ("roles:manage", "Gerenciar todos os papéis."),
        ("roles:assign-permission", "Associar/Revogar permissões de papéis."),
        ("users:assign-role", "Associar/Revogar papéis de usuários."),
        // Adicione outras permissões base se necessário (ex: "users:read", "admin:access")
    ];

    let mut created_permissions = 0;
    for (name, desc) in permissions.iter() {
        // Usar INSERT OR IGNORE para evitar erro se já existir
        // Usar UUID v7 para IDs de permissão
        let changes = tx.execute(
            "INSERT OR IGNORE INTO permissions (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![Uuid::now_v7().to_string(), name, desc],
        )?;
        if changes > 0 {
            created_permissions += 1;
            info!("   📄 Permissão criada: {}", name);
        }
    }
    if created_permissions > 0 {
         info!("   Total de {} permissões essenciais criadas.", created_permissions);
    } else {
         info!("   Permissões essenciais já existem.");
    }


    // 2. Criar Papel "Admin" (se não existir)
    let admin_role_name = "Admin";
    let admin_role_desc = "Papel com acesso administrativo total.";
    let admin_role_id = Uuid::now_v7().to_string(); // Gerar ID mesmo se não inserir
    let admin_created = tx.execute(
         "INSERT OR IGNORE INTO roles (id, name, description, created_at, updated_at) VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
        params![&admin_role_id, admin_role_name, admin_role_desc],
    )?;

    let final_admin_role_id: String = if admin_created > 0 {
        info!("   🎭 Papel '{}' criado.", admin_role_name);
        admin_role_id // Usar o ID gerado se foi inserido
    } else {
        info!("   🎭 Papel '{}' já existe.", admin_role_name);
        // Se não foi inserido, buscar o ID existente
         tx.query_row(
            "SELECT id FROM roles WHERE name = ?1",
            params![admin_role_name],
            |row| row.get(0),
        )?
    };


    // 3. Associar Permissões Essenciais ao Papel "Admin"
    let mut assigned_permissions = 0;
    let mut stmt_perm = tx.prepare("SELECT id FROM permissions WHERE name = ?1")?;
    let mut stmt_assoc = tx.prepare("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?1, ?2)")?;

    for (name, _) in permissions.iter() {
        // Encontrar o ID da permissão
        // Usar query_row().optional() para o caso de a permissão não ter sido criada (embora devesse)
        let permission_id_opt: Option<String> = stmt_perm.query_row(params![name], |row| row.get(0)).optional()?;

        if let Some(permission_id) = permission_id_opt {
            // Associar ao papel Admin (usando o ID correto)
            let changes = stmt_assoc.execute(params![&final_admin_role_id, &permission_id])?;
            if changes > 0 {
                assigned_permissions += 1;
            }
        } else {
            error!("   ❌ Permissão '{}' não encontrada para associação com o papel Admin!", name);
        }
    }
    drop(stmt_perm); // Liberar prepared statement
    drop(stmt_assoc);

    if assigned_permissions > 0 {
         info!("   🔗 {} permissões associadas ao papel '{}'.", assigned_permissions, admin_role_name);
    } else {
         info!("   🔗 Permissões essenciais já estavam associadas ao papel '{}'.", admin_role_name);
    }

    tx.commit()?;
    info!("🌱 Seeding RBAC concluído com sucesso.");
    Ok(())
}

// Inicializa o banco de dados
pub fn init_db(database_url: &str) -> Result<DbPool, ApiError> {
    info!("🗃️ Inicializando banco de dados em: {}", database_url);
    // Garante que o diretório do banco de dados existe
    if let Some(parent) = Path::new(database_url).parent() {
        std::fs::create_dir_all(parent).map_err(|e| ApiError::InternalServerError(format!("Falha ao criar diretório do banco de dados: {}", e)))?;
    }

    // 1. Abrir conexão inicial para aplicar migrações e PRAGMAs
    let mut conn = Connection::open(database_url)?;
    info!("✔️ Conexão inicial com o banco de dados estabelecida.");

    // 2. Aplicar otimizações PRAGMA
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 30000000000;
         PRAGMA cache_size = -64000;
         PRAGMA foreign_keys = ON;"
    )?;
    info!("✔️ Otimizações PRAGMA aplicadas.");

    // 3. Executar migrações usando refinery
    info!("🔄 Executando migrações do banco de dados...");
    // Usar o módulo 'migrations' gerado pela macro embed_migrations!
    match migrations::runner().run(&mut conn) { // Esta chamada deve funcionar agora
        Ok(report) => {
            if !report.applied_migrations().is_empty() {
                info!("✅ Migrações aplicadas com sucesso: {:?}", report.applied_migrations().iter().map(|m| m.name()).collect::<Vec<_>>());
            } else {
                info!("✅ Nenhuma nova migração para aplicar. Banco de dados atualizado.");
            }
        }
        Err(e) => {
            return Err(ApiError::DatabaseError(format!("Falha ao executar migrações: {}", e)));
        }
    }

    // 4. Semear dados RBAC após migrações bem-sucedidas
    if let Err(e) = seed_rbac_data(&mut conn) {
        error!("❌ Falha ao semear dados RBAC: {}", e);
        // Decide se retorna erro ou apenas loga.
        // Retornar erro se a aplicação não pode funcionar sem estes dados.
        return Err(ApiError::DatabaseError(format!("Falha crítica ao semear dados RBAC: {}", e)));
    }

    // Fechar a conexão inicial (não é estritamente necessário, mas limpa)
    drop(conn);

    // 5. Configura o pool de conexões R2D2 (sem with_init, pois PRAGMAs já foram aplicados)
    let manager = SqliteConnectionManager::file(database_url);

    let pool = Pool::builder()
        .max_size(10)
        .build(manager)
        .map_err(|e| ApiError::DatabaseError(format!("Falha ao criar pool de conexões: {}", e)))?;

    // Remover chamada antiga de migração

    Ok(pool)
}

// // Função para obter uma conexão do pool (Não utilizada)
// pub fn get_connection(pool: &DbPool) -> Result<DbConnection, ApiError> {
//     pool.get()
//         .map_err(|e| ApiError::DatabaseError(format!("Falha ao obter conexão do pool: {}", e)))
// }

// Remover função antiga de criação de DB de teste
// A lógica de teste precisará ser adaptada para usar refinery::runner().run(&mut conn)
// em uma conexão em memória.
