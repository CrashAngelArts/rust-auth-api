# 🌲 Árvore de Funções do Código Rust

## 📄 mod.rs

└── 🔹 `Config`
    └── 🔸 `from_env`
└── 🔹 `ServerConfig`
└── 🔹 `DatabaseConfig`
└── 🔹 `JwtConfig`
└── 🔹 `EmailConfig`
└── 🔹 `SecurityConfig`
└── 🔹 `CorsConfig`
└── 🔹 `OAuthConfig`
├── 🔧 `load_config`

## 📄 auth_controller.rs

├── 🔧 `forgot_password`
├── 🔧 `login`
├── 🔧 `me`
├── 🔧 `refresh_token`
├── 🔧 `register`
├── 🔧 `reset_password`
└── 🔧 `unlock_account`

## 📄 device_controller.rs

├── 🔧 `clean_expired_sessions`
├── 🔧 `get_device`
├── 🔧 `list_devices`
├── 🔧 `revoke_device`
└── 🔧 `update_device`

## 📄 email_verification_controller.rs

├── 🔧 `clean_expired_codes`
├── 🔧 `resend_verification_code`
└── 🔧 `verify_email_code`

## 📄 health_controller.rs

└── 🔹 `HealthResponse`
├── 🔧 `health_check`
├── 🔧 `version`

## 📄 keystroke_controller.rs

├── 🔧 `get_keystroke_status` - Obtém o status da verificação de ritmo de digitação
├── 🔧 `register_keystroke_pattern` - Registra um novo padrão de digitação
├── 🔧 `toggle_keystroke_verification` - Habilita ou desabilita a verificação de ritmo de digitação
└── 🔧 `verify_keystroke_pattern` - Verifica um padrão de digitação durante o login

## 📄 mod.rs


## 📄 oauth_controller.rs

├── 🔧 `list_oauth_connections`
├── 🔧 `oauth_callback`
├── 🔧 `oauth_login`
└── 🔧 `remove_oauth_connection`

## 📄 rbac_controller.rs

├── 🔧 `assign_permission_to_role_handler`
├── 🔧 `assign_role_to_user_handler`
├── 🔧 `check_user_permission_handler`
├── 🔧 `configure_rbac_routes`
├── 🔧 `create_permission_handler`
├── 🔧 `create_role_handler`
├── 🔧 `delete_permission_handler`
├── 🔧 `delete_role_handler`
├── 🔧 `get_permission_by_id_handler`
├── 🔧 `get_permission_by_name_handler`
├── 🔧 `get_role_by_id_handler`
├── 🔧 `get_role_by_name_handler`
├── 🔧 `get_role_permissions_handler`
├── 🔧 `get_user_roles_handler`
├── 🔧 `list_permissions_handler`
├── 🔧 `list_roles_handler`
├── 🔧 `revoke_permission_from_role_handler`
├── 🔧 `revoke_role_from_user_handler`
├── 🔧 `update_permission_handler`
└── 🔧 `update_role_handler`

## 📄 recovery_email_controller.rs

├── 🔧 `add_recovery_email`
├── 🔧 `list_recovery_emails`
├── 🔧 `remove_recovery_email`
├── 🔧 `resend_verification_email`
└── 🔧 `verify_recovery_email`

## 📄 token_controller.rs

├── 🔧 `clean_expired_tokens`
├── 🔧 `revoke_all_tokens`
├── 🔧 `revoke_token`
└── 🔧 `rotate_token`

## 📄 two_factor_controller.rs

├── 🔧 `disable_2fa`
├── 🔧 `enable_2fa`
├── 🔧 `get_2fa_status`
├── 🔧 `regenerate_backup_codes`
└── 🔧 `setup_2fa`

## 📄 user_controller.rs

└── 🔹 `ListUsersQuery`
├── 🔧 `change_password`
├── 🔧 `delete_user`
├── 🔧 `get_user`
├── 🔧 `list_users`
├── 🔧 `update_user`

## 📄 migrations.rs


## 📄 mod.rs

├── 🔧 `get_connection`
├── 🔧 `init_db`
└── 🔧 `seed_rbac_data` - Função para semear dados RBAC essenciais (permissões e papel admin)

## 📄 pool.rs

└── 🔹 `DbConnection`
    ├── 🔸 `deref`
    ├── 🔸 `deref_mut`
    └── 🔸 `get`

## 📄 mod.rs

└── 🔹 `ErrorResponse`
├── 🔧 `error_response`
├── 🔧 `fmt`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `log_error`
├── 🔧 `status_code`

## 📄 lib.rs


## 📄 main.rs

└── 🔧 `main`

## 📄 auth.rs

└── 🔹 `AuthenticatedUser`
└── 🔹 `JwtAuth`
    ├── 🔸 `clone`
    └── 🔸 `new`
└── 🔹 `JwtAuthMiddleware`
└── 🔹 `AdminAuth`
    ├── 🔸 `clone`
    └── 🔸 `new`
└── 🔹 `AdminAuthMiddleware`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `from_request`
├── 🔧 `new_transform`
├── 🔧 `new_transform`

## 📄 cors.rs

└── 🔧 `configure_cors`

## 📄 csrf.rs

└── 🔹 `CsrfProtect`
    └── 🔸 `from_config` - Cria uma nova instância do Transform CSRF a partir da configuração da aplicação.
└── 🔹 `CsrfProtectMiddleware`
├── 🔧 `call`
├── 🔧 `constant_time_compare` - Implementação segura de comparação de tempo constante para evitar ataques de timing
├── 🔧 `error_response`
├── 🔧 `generate_csrf_token`
├── 🔧 `new_transform`
├── 🔧 `status_code`

## 📄 email_verification.rs

└── 🔹 `EmailVerificationCheck`
    ├── 🔸 `new`
    └── 🔸 `new_transform`
└── 🔹 `EmailVerificationCheckMiddleware`
├── 🔧 `call`

## 📄 error.rs

└── 🔹 `ErrorHandler`
    ├── 🔸 `new`
    └── 🔸 `new_transform`
└── 🔹 `ErrorHandlerMiddleware`
├── 🔧 `call`

## 📄 keystroke_rate_limiter.rs

└── 🔹 `KeystrokeAttempts`
└── 🔹 `KeystrokeRateLimiter`
    ├── 🔸 `default`
    └── 🔸 `new`
└── 🔹 `KeystrokeRateLimiterMiddleware`
├── 🔧 `call`
├── 🔧 `clean_keystroke_rate_limit_entries`
├── 🔧 `new_transform`
├── 🔧 `poll_ready`

## 📄 logger.rs

└── 🔹 `RequestLogger`
    ├── 🔸 `new`
    └── 🔸 `new_transform`
└── 🔹 `RequestLoggerMiddleware`
├── 🔧 `call`

## 📄 mod.rs


## 📄 permission.rs

└── 🔹 `PermissionAuth`
    └── 🔸 `new`
└── 🔹 `PermissionAuthMiddleware`
├── 🔧 `call`
├── 🔧 `new_transform`

## 📄 rate_limiter.rs

└── 🔹 `TokenBucketInfo`
└── 🔹 `RateLimiter`
    └── 🔸 `new` - Cria um novo Rate Limiter com o algoritmo Token Bucket.
└── 🔹 `RateLimiterMiddleware`
├── 🔧 `call`
├── 🔧 `new_transform`

## 📄 security.rs

└── 🔹 `SecurityHeaders`
    └── 🔸 `new`
└── 🔹 `SecurityHeadersMiddleware`
└── 🔹 `CsrfProtectionMiddleware`
    └── 🔸 `new`
└── 🔹 `CsrfProtectionService`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `clone`
├── 🔧 `configure_security`
├── 🔧 `generate_csrf_token`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `with_header`

## 📄 auth.rs

└── 🔹 `LoginDto`
└── 🔹 `RegisterDto`
└── 🔹 `ForgotPasswordDto`
└── 🔹 `ResetPasswordDto`
└── 🔹 `TokenClaims`
└── 🔹 `AuthResponse`
└── 🔹 `PasswordResetToken`
    ├── 🔸 `is_expired`
    └── 🔸 `new`
└── 🔹 `RefreshToken`
    └── 🔸 `new`
└── 🔹 `RefreshTokenDto`
└── 🔹 `Session`
    ├── 🔸 `is_expired`
    └── 🔸 `new`
└── 🔹 `AuthLog`
    └── 🔸 `new`
└── 🔹 `UnlockAccountDto`
├── 🔧 `is_expired`

## 📄 device.rs

└── 🔹 `Device`
└── 🔹 `DeviceInfo`
└── 🔹 `UpdateDeviceDto`
└── 🔹 `DeviceListResponse`

## 📄 email_verification.rs

└── 🔹 `EmailVerificationCode`
    └── 🔸 `new`
└── 🔹 `VerifyEmailCodeDto`
└── 🔹 `EmailVerificationResponse`
├── 🔧 `generate_code`
├── 🔧 `is_expired`

## 📄 keystroke_dynamics.rs

└── 🔹 `KeystrokeDynamics`
└── 🔹 `RegisterKeystrokePatternDto`
└── 🔹 `VerifyKeystrokePatternDto`
└── 🔹 `KeystrokeVerificationResponse`
└── 🔹 `KeystrokeStatusResponse`

## 📄 mod.rs


## 📄 oauth.rs

└── 🔹 `OAuthLoginRequest`
└── 🔹 `OAuthCallbackRequest`
└── 🔹 `OAuthUrlResponse`
└── 🔹 `OAuthUserProfile`
└── 🔹 `OAuthConnection`
    └── 🔸 `new`
└── 🔹 `OAuthConnectionResponse`
└── 🔹 `OAuthErrorResponse`
├── 🔧 `fmt`
├── 🔧 `from`
├── 🔧 `from`

## 📄 permission.rs

└── 🔹 `Permission`
    └── 🔸 `new` - Cria uma nova instância de Permissão.
└── 🔹 `CreatePermissionDto`
└── 🔹 `UpdatePermissionDto`

## 📄 recovery_email.rs

└── 🔹 `RecoveryEmail`
    ├── 🔸 `generate_verification_token`
    └── 🔸 `new`
└── 🔹 `AddRecoveryEmailDto`
└── 🔹 `VerifyRecoveryEmailDto`
└── 🔹 `RecoveryEmailResponse`
├── 🔧 `from`
├── 🔧 `verify`

## 📄 response.rs

└── 🔹 `ApiResponse`
    └── 🔸 `message`
└── 🔹 `PaginatedResponse`
    ├── 🔸 `new`
    └── 🔸 `with_message`
├── 🔧 `error`
├── 🔧 `fmt`
├── 🔧 `success`
├── 🔧 `success_with_message`

## 📄 role.rs

└── 🔹 `Role`
    └── 🔸 `new` - Cria uma nova instância de Role.
└── 🔹 `CreateRoleDto`
└── 🔹 `UpdateRoleDto`
└── 🔹 `RolePermissionDto`
└── 🔹 `UserRoleDto`

## 📄 security_question.rs

└── 🔹 `SecurityQuestion`
    └── 🔸 `new` - Cria uma nova instância de SecurityQuestion.
└── 🔹 `UserSecurityAnswer`
    └── 🔸 `new` - Cria uma nova instância de UserSecurityAnswer.
└── 🔹 `CreateSecurityQuestionDto`
└── 🔹 `UpdateSecurityQuestionDto`
└── 🔹 `SetSecurityAnswerDto`
└── 🔹 `VerifySecurityAnswerDto`
└── 🔹 `RecoveryCode`
    ├── 🔸 `is_expired` - Verifica se o código já expirou.
    └── 🔸 `new` - Gera um novo código de recuperação com prazo de validade.
└── 🔹 `VerifyRecoveryCodeDto`
├── 🔧 `generate_recovery_code` - Gera um código de recuperação forte e legível (24 caracteres).

## 📄 token.rs

└── 🔹 `BlacklistedToken`
    └── 🔸 `new`
└── 🔹 `TokenClaims`
└── 🔹 `TokenResponse`
└── 🔹 `RefreshTokenDto`

## 📄 two_factor.rs

└── 🔹 `Enable2FADto`
└── 🔹 `Verify2FADto`
└── 🔹 `Disable2FADto`
└── 🔹 `UseBackupCodeDto`
└── 🔹 `TwoFactorSetupResponse`
└── 🔹 `TwoFactorEnabledResponse`
└── 🔹 `TwoFactorStatusResponse`

## 📄 user.rs

└── 🔹 `User`
    └── 🔸 `new`
└── 🔹 `CreateUserDto`
└── 🔹 `UpdateUserDto`
└── 🔹 `ChangePasswordDto`
└── 🔹 `UserResponse`
├── 🔧 `from`
├── 🔧 `full_name`
├── 🔧 `is_locked`

## 📄 mod.rs


## 📄 rbac_repository.rs

└── 🔹 `SqliteRbacRepository`
    └── 🔸 `create_permission` - Cria uma nova permissão no banco de dados.
└── 🔹 `Permission` - Mapeia uma linha do banco de dados para a
└── 🔹 `Role` - Mapeia uma linha do banco de dados para a
├── 🔧 `assign_permission_to_role` - Associa uma permissão a um papel.
├── 🔧 `assign_role_to_user` - Associa um papel a um usuário.
├── 🔧 `check_user_permission` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├── 🔧 `create_role` - Cria um novo papel no banco de dados.
├── 🔧 `delete_permission` - Deleta uma permissão pelo seu ID no banco de dados.
├── 🔧 `delete_role` - Deleta um papel pelo seu ID no banco de dados.
├── 🔧 `get_permission_by_id` - Busca uma permissão pelo seu ID no banco de dados.
├── 🔧 `get_permission_by_name` - Busca uma permissão pelo seu nome único no banco de dados.
├── 🔧 `get_role_by_id` - Busca um papel pelo seu ID no banco de dados.
├── 🔧 `get_role_by_name` - Busca um papel pelo seu nome único no banco de dados.
├── 🔧 `get_role_permissions` - Lista todas as permissões associadas a um papel específico.
├── 🔧 `get_user_roles` - Lista todos os papéis associados a um usuário específico.
├── 🔧 `list_permissions` - Lista todas as permissões do banco de dados.
├── 🔧 `list_roles` - Lista todos os papéis do banco de dados.
├── 🔧 `map_row_to_permission` - Mapeia uma linha do banco de dados para a struct Permission.
├── 🔧 `map_row_to_role` - Mapeia uma linha do banco de dados para a struct Role.
├── 🔧 `revoke_permission_from_role` - Remove a associação entre uma permissão e um papel.
├── 🔧 `revoke_role_from_user` - Remove a associação entre um usuário e um papel.
├── 🔧 `update_permission` - Atualiza uma permissão existente no banco de dados.
├── 🔧 `update_role` - Atualiza um papel existente no banco de dados.

## 📄 security_question_repository.rs

└── 🔹 `SqliteSecurityQuestionRepository` - Repositório para operações CRUD de perguntas de segurança e respostas de usuários.
    └── 🔸 `create_security_question` - Cria uma nova pergunta de segurança.
├── 🔧 `deactivate_security_question` - Desativa uma pergunta de segurança em vez de excluí-la.
├── 🔧 `delete_all_user_security_answers` - Remove todas as respostas de um usuário.
├── 🔧 `delete_security_question` - Exclui uma pergunta de segurança.
├── 🔧 `delete_user_security_answer` - Remove uma resposta específica de um usuário.
├── 🔧 `get_security_question_by_id` - Busca uma pergunta de segurança pelo ID.
├── 🔧 `get_security_questions_for_email` - Obtém perguntas de segurança configuradas para um usuário pelo email.
├── 🔧 `get_user_security_answers` - Obtém todas as respostas de segurança de um usuário.
├── 🔧 `list_security_questions` - Lista todas as perguntas de segurança, opcionalmente filtrando por status ativo.
├── 🔧 `map_row_to_security_question` - Mapeia uma linha do banco de dados para um objeto SecurityQuestion.
├── 🔧 `set_recovery_code` - Configura um código de recuperação para um usuário.
├── 🔧 `set_user_security_answer` - Configura ou atualiza a resposta de um usuário a uma pergunta de segurança.
├── 🔧 `update_security_question` - Atualiza uma pergunta de segurança existente.
├── 🔧 `verify_recovery_code` - Verifica e consome um código de recuperação.

## 📄 mod.rs

└── 🔧 `configure_routes`

## 📄 auth_service.rs

└── 🔹 `AuthService`
    └── 🔸 `register`
├── 🔧 `create_session`
├── 🔧 `find_and_validate_refresh_token`
├── 🔧 `forgot_password`
├── 🔧 `generate_auth_tokens`
├── 🔧 `generate_jwt`
├── 🔧 `hash_token`
├── 🔧 `log_auth_event`
├── 🔧 `login`
├── 🔧 `parse_expiration`
├── 🔧 `refresh_token`
├── 🔧 `reset_password`
├── 🔧 `revoke_all_user_refresh_tokens`
├── 🔧 `revoke_refresh_token`
├── 🔧 `save_refresh_token`
├── 🔧 `unlock_account`
├── 🔧 `validate_token`

## 📄 device_service.rs

└── 🔹 `DeviceService`
    └── 🔸 `list_user_devices`
├── 🔧 `clean_expired_sessions`
├── 🔧 `create_session_with_device_info`
├── 🔧 `detect_device_type`
├── 🔧 `generate_device_name`
├── 🔧 `get_device_details`
├── 🔧 `revoke_device`
├── 🔧 `set_current_device`
├── 🔧 `update_device`
├── 🔧 `update_last_active`

## 📄 email_service.rs

└── 🔹 `EmailService`
    ├── 🔸 `get_base_url`
    ├── 🔸 `is_enabled`
    └── 🔸 `new`
├── 🔧 `send_account_unlock_email`
├── 🔧 `send_email`
├── 🔧 `send_password_reset_email`
├── 🔧 `send_welcome_email`

## 📄 email_verification_service.rs

└── 🔹 `EmailVerificationService`
    └── 🔸 `generate_and_send_code`
├── 🔧 `clean_expired_codes`
├── 🔧 `has_pending_code`
├── 🔧 `send_verification_email`
├── 🔧 `verify_code`

## 📄 keystroke_security_service.rs

└── 🔹 `KeystrokeVerificationAttempt`
└── 🔹 `UserVerificationHistory`
└── 🔹 `KeystrokeSecurityService`
    └── 🔸 `new`
├── 🔧 `calculate_anomaly_score`
├── 🔧 `check_consecutive_failures`
├── 🔧 `check_for_suspicious_patterns`
├── 🔧 `clean_old_history`
├── 🔧 `default`
├── 🔧 `get_user_anomaly_score`
├── 🔧 `is_user_suspicious`
├── 🔧 `record_verification_attempt`

## 📄 keystroke_service.rs

└── 🔹 `KeystrokeService`
    └── 🔸 `register_pattern` - Registra um novo padrão de digitação para o usuário
├── 🔧 `calculate_pattern_similarity` - Calcula a similaridade entre dois padrões de digitação
├── 🔧 `get_keystroke_status` - Obtém o status da verificação de ritmo de digitação
├── 🔧 `normalize_pattern` - Normaliza um padrão de digitação para valores entre 0.0 e 1.0
├── 🔧 `toggle_keystroke_verification` - Habilita ou desabilita a verificação de ritmo de digitação
├── 🔧 `verify_keystroke_pattern` - Verifica o padrão de digitação durante o login

## 📄 mod.rs


## 📄 oauth_service.rs

└── 🔹 `OAuthService`
    ├── 🔸 `get_authorization_url` - Cria URL de autorização para o provedor OAuth especificado
    └── 🔸 `new`
├── 🔧 `create_oauth_client` - Cria um cliente OAuth para o provedor especificado
├── 🔧 `create_oauth_connection` - Cria uma nova conexão OAuth
├── 🔧 `find_oauth_connection` - Encontra uma conexão OAuth existente
├── 🔧 `get_apple_profile` - Obtém o perfil do usuário da Apple
├── 🔧 `get_facebook_profile` - Obtém o perfil do usuário do Facebook
├── 🔧 `get_github_profile` - Obtém o perfil do usuário do GitHub
├── 🔧 `get_google_profile` - Obtém o perfil do usuário do Google
├── 🔧 `get_microsoft_profile` - Obtém o perfil do usuário do Microsoft
├── 🔧 `get_user_profile` - Obtém o perfil do usuário do provedor OAuth
├── 🔧 `list_user_oauth_connections` - Lista todas as conexões OAuth de um usuário
├── 🔧 `process_callback` - Processa o callback OAuth e retorna o perfil do usuário
├── 🔧 `process_oauth_login` - Cria ou atualiza um usuário com base no perfil OAuth
├── 🔧 `remove_oauth_connection` - Remove uma conexão OAuth

## 📄 rbac_service.rs

└── 🔹 `RbacService`
    ├── 🔸 `create_permission` - Cria uma nova permissão.
    └── 🔸 `new` - Cria uma nova instância do RbacService.
├── 🔧 `assign_permission_to_role` - Associa uma permissão a um papel.
├── 🔧 `assign_role_to_user` - Associa um papel a um usuário.
├── 🔧 `check_user_permission` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├── 🔧 `create_role` - Cria um novo papel.
├── 🔧 `delete_permission` - Deleta uma permissão.
├── 🔧 `delete_role` - Deleta um papel.
├── 🔧 `get_permission_by_id` - Busca uma permissão pelo seu ID.
├── 🔧 `get_permission_by_name` - Busca uma permissão pelo seu nome.
├── 🔧 `get_role_by_id` - Busca um papel pelo seu ID.
├── 🔧 `get_role_by_name` - Busca um papel pelo seu nome.
├── 🔧 `get_role_permissions` - Lista todas as permissões associadas a um papel específico.
├── 🔧 `get_user_roles` - Lista todos os papéis associados a um usuário específico.
├── 🔧 `list_permissions` - Lista todas as permissões.
├── 🔧 `list_roles` - Lista todos os papéis.
├── 🔧 `revoke_permission_from_role` - Remove a associação entre uma permissão e um papel.
├── 🔧 `revoke_role_from_user` - Remove a associação entre um usuário e um papel.
├── 🔧 `update_permission` - Atualiza uma permissão existente.
├── 🔧 `update_role` - Atualiza um papel existente.

## 📄 recovery_email_service.rs

└── 🔹 `RecoveryEmailService`
    └── 🔸 `add_recovery_email`
├── 🔧 `get_user_id_by_recovery_email`
├── 🔧 `list_recovery_emails`
├── 🔧 `remove_recovery_email`
├── 🔧 `resend_verification_email`
├── 🔧 `send_verification_email`
├── 🔧 `verify_recovery_email`

## 📄 token_service.rs

└── 🔹 `TokenService`
    └── 🔸 `generate_token`
├── 🔧 `blacklist_token`
├── 🔧 `clean_expired_tokens`
├── 🔧 `is_token_blacklisted`
├── 🔧 `rotate_token`
├── 🔧 `validate_token`

## 📄 two_factor_service.rs

└── 🔹 `TwoFactorService`
    └── 🔸 `generate_setup`
├── 🔧 `disable_2fa`
├── 🔧 `enable_2fa`
├── 🔧 `generate_backup_codes`
├── 🔧 `regenerate_backup_codes`
├── 🔧 `verify_backup_code`
├── 🔧 `verify_totp`

## 📄 user_service.rs

└── 🔹 `UserService`
    └── 🔸 `create_user`
├── 🔧 `change_password`
├── 🔧 `delete_user`
├── 🔧 `get_user_by_email`
├── 🔧 `get_user_by_email_or_username`
├── 🔧 `get_user_by_id`
├── 🔧 `list_users`
├── 🔧 `update_password`
├── 🔧 `update_user`
├── 🔧 `verify_password`

## 📄 jwt.rs

├── 🔧 `extract_user_id` - Extrai o ID do usuário do token JWT na requisição
└── 🔧 `is_admin` - Verifica se o usuário é administrador

## 📄 mod.rs


## 📄 password.rs

├── 🔧 `as_str`
├── 🔧 `check_password_strength`
├── 🔧 `generate_random_password`
└── 🔧 `meets_requirements`

## 📄 password_argon2.rs

├── 🔧 `hash_password` - Gera um hash seguro de senha usando Argon2id (mais seguro que bcrypt)
├── 🔧 `is_argon2_hash` - Verifica se um hash foi gerado com Argon2
└── 🔧 `verify_password` - Verifica se uma senha corresponde ao hash armazenado

## 📄 tracing.rs

├── 🔧 `init_tracing` - Configura o sistema de logging estruturado com tracing
└── 🔧 `log_startup_info` - Registra informações sobre o ambiente de execução

## 📄 validator.rs

└── 🔧 `validate_dto`

