-- Criação da tabela de localizações de login dos usuários
CREATE TABLE IF NOT EXISTS user_login_locations (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  country_code TEXT,
  city TEXT,
  latitude REAL,
  longitude REAL,
  accuracy_radius INTEGER,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  risk_score REAL DEFAULT 0,
  is_suspicious BOOLEAN DEFAULT 0,
  suspicious_reason TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Índices para melhorar a performance das consultas
CREATE INDEX IF NOT EXISTS idx_user_login_locations_user_id ON user_login_locations (user_id);
CREATE INDEX IF NOT EXISTS idx_user_login_locations_ip_address ON user_login_locations (ip_address);
CREATE INDEX IF NOT EXISTS idx_user_login_locations_created_at ON user_login_locations (created_at);
CREATE INDEX IF NOT EXISTS idx_user_login_locations_is_suspicious ON user_login_locations (is_suspicious);

-- Comentário: Esta tabela armazena o histórico de localizações de login dos usuários
-- permitindo análise de padrões de localização e detecção de atividades suspeitas. 