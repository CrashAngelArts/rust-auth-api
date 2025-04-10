use actix_web::web;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

// Tipo para o pool de conexões
pub type DbPool = Pool<SqliteConnectionManager>;

// Extrator para obter uma conexão do pool
pub struct DbConnection(pub r2d2::PooledConnection<SqliteConnectionManager>);

// Implementação para extrair uma conexão do pool a partir do contexto da requisição
impl DbConnection {
    pub fn get(pool: &web::Data<DbPool>) -> Result<Self, r2d2::Error> {
        let conn = pool.get()?;
        Ok(DbConnection(conn))
    }
}

// Implementação para acessar a conexão diretamente
impl std::ops::Deref for DbConnection {
    type Target = r2d2::PooledConnection<SqliteConnectionManager>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Implementação para acessar a conexão mutável diretamente
impl std::ops::DerefMut for DbConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
