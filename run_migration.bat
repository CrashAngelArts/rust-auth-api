@echo off
echo 🔄 Executando migração do banco de dados...
cargo run --bin rust-auth-api
echo ✅ Migração concluída!
