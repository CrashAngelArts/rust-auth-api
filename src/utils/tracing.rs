use tracing::subscriber::set_global_default;
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};
use std::env;

/// Configura o sistema de logging estruturado com tracing
pub fn init_tracing() -> Result<(), String> {
    // Configura o LogTracer para capturar logs da crate log
    if let Err(e) = LogTracer::init() {
        return Err(format!("❌ Falha ao inicializar LogTracer: {}", e));
    }

    // Obtém o nível de log da variável de ambiente ou usa o padrão
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
    });

    // Cria uma camada de formatação JSON para logs estruturados
    let formatting_layer = BunyanFormattingLayer::new(
        "rust-auth-api".into(),
        std::io::stdout,
    );

    // Combina as camadas e define o subscriber global
    let subscriber = Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer);

    match set_global_default(subscriber) {
        Ok(_) => {
            tracing::info!("✅ Sistema de logging estruturado inicializado com sucesso");
            Ok(())
        },
        Err(e) => Err(format!("❌ Falha ao definir subscriber global: {}", e)),
    }
}

/// Registra informações sobre o ambiente de execução
pub fn log_startup_info() {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "🚀 Iniciando API de Autenticação em Rust"
    );
    
    tracing::info!(
        rust_version = rustc_version_runtime::version().to_string(),
        "🦀 Versão do Rust"
    );
    
    // Registra informações do sistema
    tracing::info!(
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        "💻 Informações do sistema"
    );
}
