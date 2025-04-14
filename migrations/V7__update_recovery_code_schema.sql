-- Renomeia a coluna recovery_code para hashed_recovery_code 🔐
ALTER TABLE users RENAME COLUMN recovery_code TO hashed_recovery_code;

-- Remove a coluna recovery_code_expires_at que não é mais necessária 🗑️
ALTER TABLE users DROP COLUMN recovery_code_expires_at; 