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
use tracing::info; // Usar tracing em vez de log

// Incorpora as migrações SQL do diretório 'migrations'
embed_migrations!("migrations");

pub type DbPool = Pool<SqliteConnectionManager>;
// pub type DbConnection = r2d2::PooledConnection<SqliteConnectionManager>; // Não utilizado

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

    // Fechar a conexão inicial (não é estritamente necessário, mas limpa)
    drop(conn);

    // 4. Configura o pool de conexões R2D2 (sem with_init, pois PRAGMAs já foram aplicados)
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
