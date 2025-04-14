# 🌲 Árvore de Funções do Código Rust

## 📄 mod.rs

└── 🔹 `Config`
    ├── 🔸 `from_env`
    └── 🔸 `from_env`
└── 🔹 `ServerConfig`
└── 🔹 `DatabaseConfig`
└── 🔹 `JwtConfig`
└── 🔹 `EmailConfig`
└── 🔹 `SecurityConfig`
└── 🔹 `CorsConfig`
└── 🔹 `OAuthConfig`
└── 🔹 `Config`
└── 🔹 `ServerConfig`
└── 🔹 `DatabaseConfig`
└── 🔹 `JwtConfig`
└── 🔹 `EmailConfig`
└── 🔹 `SecurityConfig`
└── 🔹 `CorsConfig`
└── 🔹 `OAuthConfig`
├── 🔧 `load_config`
├── 🔧 `load_config`

## 📄 auth_controller.rs

├── 🔧 `forgot_password`
├── 🔧 `forgot_password`
├── 🔧 `login`
├── 🔧 `login`
├── 🔧 `me`
├── 🔧 `me`
├── 🔧 `refresh_token`
├── 🔧 `refresh_token`
├── 🔧 `register`
├── 🔧 `register`
├── 🔧 `reset_password`
├── 🔧 `reset_password`
├── 🔧 `unlock_account`
└── 🔧 `unlock_account`

## 📄 device_controller.rs

├── 🔧 `clean_expired_sessions`
├── 🔧 `clean_expired_sessions`
├── 🔧 `get_device`
├── 🔧 `get_device`
├── 🔧 `list_devices`
├── 🔧 `list_devices`
├── 🔧 `revoke_device`
├── 🔧 `revoke_device`
├── 🔧 `update_device`
└── 🔧 `update_device`

## 📄 email_verification_controller.rs

├── 🔧 `clean_expired_codes`
├── 🔧 `clean_expired_codes`
├── 🔧 `resend_verification_code`
├── 🔧 `resend_verification_code`
├── 🔧 `verify_email_code`
└── 🔧 `verify_email_code`

## 📄 health_controller.rs

└── 🔹 `HealthResponse`
└── 🔹 `HealthResponse`
├── 🔧 `health_check`
├── 🔧 `health_check`
├── 🔧 `version`
├── 🔧 `version`

## 📄 keystroke_controller.rs

├── 🔧 `get_keystroke_status` - Obtém o status da verificação de ritmo de digitação
├── 🔧 `get_keystroke_status` - Obtém o status da verificação de ritmo de digitação
├── 🔧 `register_keystroke_pattern` - Registra um novo padrão de digitação
├── 🔧 `register_keystroke_pattern` - Registra um novo padrão de digitação
├── 🔧 `toggle_keystroke_verification` - Habilita ou desabilita a verificação de ritmo de digitação
├── 🔧 `toggle_keystroke_verification` - Habilita ou desabilita a verificação de ritmo de digitação
├── 🔧 `verify_keystroke_pattern` - Verifica um padrão de digitação durante o login
└── 🔧 `verify_keystroke_pattern` - Verifica um padrão de digitação durante o login

## 📄 mod.rs


## 📄 oauth_controller.rs

├── 🔧 `list_oauth_connections`
├── 🔧 `list_oauth_connections`
├── 🔧 `oauth_callback`
├── 🔧 `oauth_callback`
├── 🔧 `oauth_login`
├── 🔧 `oauth_login`
├── 🔧 `remove_oauth_connection`
└── 🔧 `remove_oauth_connection`

## 📄 rbac_controller.rs

├── 🔧 `assign_permission_to_role_handler`
├── 🔧 `assign_permission_to_role_handler`
├── 🔧 `assign_role_to_user_handler`
├── 🔧 `assign_role_to_user_handler`
├── 🔧 `check_user_permission_handler`
├── 🔧 `check_user_permission_handler`
├── 🔧 `configure_rbac_routes`
├── 🔧 `configure_rbac_routes`
├── 🔧 `create_permission_handler`
├── 🔧 `create_permission_handler`
├── 🔧 `create_role_handler`
├── 🔧 `create_role_handler`
├── 🔧 `delete_permission_handler`
├── 🔧 `delete_permission_handler`
├── 🔧 `delete_role_handler`
├── 🔧 `delete_role_handler`
├── 🔧 `get_permission_by_id_handler`
├── 🔧 `get_permission_by_id_handler`
├── 🔧 `get_permission_by_name_handler`
├── 🔧 `get_permission_by_name_handler`
├── 🔧 `get_role_by_id_handler`
├── 🔧 `get_role_by_id_handler`
├── 🔧 `get_role_by_name_handler`
├── 🔧 `get_role_by_name_handler`
├── 🔧 `get_role_permissions_handler`
├── 🔧 `get_role_permissions_handler`
├── 🔧 `get_user_roles_handler`
├── 🔧 `get_user_roles_handler`
├── 🔧 `list_permissions_handler`
├── 🔧 `list_permissions_handler`
├── 🔧 `list_roles_handler`
├── 🔧 `list_roles_handler`
├── 🔧 `revoke_permission_from_role_handler`
├── 🔧 `revoke_permission_from_role_handler`
├── 🔧 `revoke_role_from_user_handler`
├── 🔧 `revoke_role_from_user_handler`
├── 🔧 `update_permission_handler`
├── 🔧 `update_permission_handler`
├── 🔧 `update_role_handler`
└── 🔧 `update_role_handler`

## 📄 recovery_email_controller.rs

├── 🔧 `add_recovery_email`
├── 🔧 `add_recovery_email`
├── 🔧 `list_recovery_emails`
├── 🔧 `list_recovery_emails`
├── 🔧 `remove_recovery_email`
├── 🔧 `remove_recovery_email`
├── 🔧 `resend_verification_email`
├── 🔧 `resend_verification_email`
├── 🔧 `verify_recovery_email`
└── 🔧 `verify_recovery_email`

## 📄 security_question_controller.rs

└── 🔹 `ListQuestionsQuery`
└── 🔹 `ListResponse`
└── 🔹 `UpdateSecurityAnswerDto`
├── 🔧 `add_security_answer`
├── 🔧 `config`
├── 🔧 `create_question`
├── 🔧 `delete_question`
├── 🔧 `delete_security_answer`
├── 🔧 `get_question`
├── 🔧 `list_active_questions`
├── 🔧 `list_questions`
├── 🔧 `list_user_answers`
├── 🔧 `update_question`
├── 🔧 `update_security_answer`

## 📄 token_controller.rs

├── 🔧 `clean_expired_tokens`
├── 🔧 `clean_expired_tokens`
├── 🔧 `revoke_all_tokens`
├── 🔧 `revoke_all_tokens`
├── 🔧 `revoke_token`
├── 🔧 `revoke_token`
├── 🔧 `rotate_token`
└── 🔧 `rotate_token`

## 📄 two_factor_controller.rs

├── 🔧 `disable_2fa`
├── 🔧 `disable_2fa`
├── 🔧 `enable_2fa`
├── 🔧 `enable_2fa`
├── 🔧 `get_2fa_status`
├── 🔧 `get_2fa_status`
├── 🔧 `regenerate_backup_codes`
├── 🔧 `regenerate_backup_codes`
├── 🔧 `setup_2fa`
└── 🔧 `setup_2fa`

## 📄 user_controller.rs

└── 🔹 `ListUsersQuery`
└── 🔹 `ListUsersQuery`
├── 🔧 `change_password`
├── 🔧 `change_password`
├── 🔧 `delete_user`
├── 🔧 `delete_user`
├── 🔧 `get_user`
├── 🔧 `get_user`
├── 🔧 `list_users`
├── 🔧 `list_users`
├── 🔧 `update_user`
├── 🔧 `update_user`

## 📄 migrations.rs


## 📄 mod.rs

├── 🔧 `get_connection`
├── 🔧 `get_connection`
├── 🔧 `init_db`
├── 🔧 `init_db`
├── 🔧 `seed_rbac_data` - Função para semear dados RBAC essenciais (permissões e papel admin)
└── 🔧 `seed_rbac_data` - Função para semear dados RBAC essenciais (permissões e papel admin)

## 📄 pool.rs

└── 🔹 `DbConnection`
    ├── 🔸 `deref`
    ├── 🔸 `deref`
    ├── 🔸 `deref_mut`
    ├── 🔸 `deref_mut`
    ├── 🔸 `get`
    └── 🔸 `get`
└── 🔹 `DbConnection`

## 📄 mod.rs

└── 🔹 `ErrorResponse`
└── 🔹 `ErrorResponse`
├── 🔧 `error_response`
├── 🔧 `error_response`
├── 🔧 `fmt`
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
├── 🔧 `log_error`
├── 🔧 `status_code`
├── 🔧 `status_code`

## 📄 lib.rs


## 📄 main.rs

├── 🔧 `main`
└── 🔧 `main`

## 📄 auth.rs

└── 🔹 `AuthenticatedUser`
└── 🔹 `JwtAuth`
    ├── 🔸 `clone`
    ├── 🔸 `clone`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `JwtAuthMiddleware`
└── 🔹 `AdminAuth`
    ├── 🔸 `clone`
    ├── 🔸 `clone`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `AdminAuthMiddleware`
└── 🔹 `AuthenticatedUser`
└── 🔹 `JwtAuth`
└── 🔹 `JwtAuthMiddleware`
└── 🔹 `AdminAuth`
└── 🔹 `AdminAuthMiddleware`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `from_request`
├── 🔧 `from_request`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `new_transform`

## 📄 cors.rs

├── 🔧 `configure_cors`
└── 🔧 `configure_cors`

## 📄 csrf.rs

└── 🔹 `CsrfProtect`
    ├── 🔸 `from_config` - Cria uma nova instância do Transform CSRF a partir da configuração da aplicação.
    └── 🔸 `from_config` - Cria uma nova instância do Transform CSRF a partir da configuração da aplicação.
└── 🔹 `CsrfProtectMiddleware`
└── 🔹 `CsrfProtect`
└── 🔹 `CsrfProtectMiddleware`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `constant_time_compare` - Implementação segura de comparação de tempo constante para evitar ataques de timing
├── 🔧 `constant_time_compare` - Implementação segura de comparação de tempo constante para evitar ataques de timing
├── 🔧 `error_response`
├── 🔧 `error_response`
├── 🔧 `generate_csrf_token`
├── 🔧 `generate_csrf_token`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `status_code`
├── 🔧 `status_code`

## 📄 email_verification.rs

└── 🔹 `EmailVerificationCheck`
    ├── 🔸 `new`
    ├── 🔸 `new`
    ├── 🔸 `new_transform`
    └── 🔸 `new_transform`
└── 🔹 `EmailVerificationCheckMiddleware`
└── 🔹 `EmailVerificationCheck`
└── 🔹 `EmailVerificationCheckMiddleware`
├── 🔧 `call`
├── 🔧 `call`

## 📄 error.rs

└── 🔹 `ErrorHandler`
    ├── 🔸 `new`
    ├── 🔸 `new`
    ├── 🔸 `new_transform`
    └── 🔸 `new_transform`
└── 🔹 `ErrorHandlerMiddleware`
└── 🔹 `ErrorHandler`
└── 🔹 `ErrorHandlerMiddleware`
├── 🔧 `call`
├── 🔧 `call`

## 📄 keystroke_rate_limiter.rs

└── 🔹 `KeystrokeAttempts`
└── 🔹 `KeystrokeRateLimiter`
    ├── 🔸 `default`
    ├── 🔸 `default`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `KeystrokeRateLimiterMiddleware`
└── 🔹 `KeystrokeAttempts`
└── 🔹 `KeystrokeRateLimiter`
└── 🔹 `KeystrokeRateLimiterMiddleware`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `clean_keystroke_rate_limit_entries`
├── 🔧 `clean_keystroke_rate_limit_entries`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `poll_ready`
├── 🔧 `poll_ready`

## 📄 logger.rs

└── 🔹 `RequestLogger`
    ├── 🔸 `new`
    ├── 🔸 `new`
    ├── 🔸 `new_transform`
    └── 🔸 `new_transform`
└── 🔹 `RequestLoggerMiddleware`
└── 🔹 `RequestLogger`
└── 🔹 `RequestLoggerMiddleware`
├── 🔧 `call`
├── 🔧 `call`

## 📄 mod.rs


## 📄 permission.rs

└── 🔹 `PermissionAuth`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `PermissionAuthMiddleware`
└── 🔹 `PermissionAuth`
└── 🔹 `PermissionAuthMiddleware`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `new_transform`
├── 🔧 `new_transform`

## 📄 rate_limiter.rs

└── 🔹 `TokenBucketInfo`
└── 🔹 `RateLimiter`
    ├── 🔸 `new` - Cria um novo Rate Limiter com o algoritmo Token Bucket.
    └── 🔸 `new` - Cria um novo Rate Limiter com o algoritmo Token Bucket.
└── 🔹 `RateLimiterMiddleware`
└── 🔹 `TokenBucketInfo`
└── 🔹 `RateLimiter`
└── 🔹 `RateLimiterMiddleware`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `new_transform`
├── 🔧 `new_transform`

## 📄 security.rs

└── 🔹 `SecurityHeaders`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `SecurityHeadersMiddleware`
└── 🔹 `CsrfProtectionMiddleware`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `CsrfProtectionService`
└── 🔹 `SecurityHeaders`
└── 🔹 `SecurityHeadersMiddleware`
└── 🔹 `CsrfProtectionMiddleware`
└── 🔹 `CsrfProtectionService`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `call`
├── 🔧 `clone`
├── 🔧 `clone`
├── 🔧 `configure_security`
├── 🔧 `configure_security`
├── 🔧 `generate_csrf_token`
├── 🔧 `generate_csrf_token`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `new_transform`
├── 🔧 `with_header`
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
    ├── 🔸 `is_expired`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `RefreshToken`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `RefreshTokenDto`
└── 🔹 `Session`
    ├── 🔸 `is_expired`
    ├── 🔸 `is_expired`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `AuthLog`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `UnlockAccountDto`
└── 🔹 `LoginDto`
└── 🔹 `RegisterDto`
└── 🔹 `ForgotPasswordDto`
└── 🔹 `ResetPasswordDto`
└── 🔹 `TokenClaims`
└── 🔹 `AuthResponse`
└── 🔹 `PasswordResetToken`
└── 🔹 `RefreshToken`
└── 🔹 `RefreshTokenDto`
└── 🔹 `Session`
└── 🔹 `AuthLog`
└── 🔹 `UnlockAccountDto`
├── 🔧 `is_expired`
├── 🔧 `is_expired`
├── 🔧 `validate_reset_method`

## 📄 device.rs

└── 🔹 `Device`
└── 🔹 `DeviceInfo`
└── 🔹 `UpdateDeviceDto`
└── 🔹 `DeviceListResponse`
└── 🔹 `Device`
└── 🔹 `DeviceInfo`
└── 🔹 `UpdateDeviceDto`
└── 🔹 `DeviceListResponse`

## 📄 email_verification.rs

└── 🔹 `EmailVerificationCode`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `VerifyEmailCodeDto`
└── 🔹 `EmailVerificationResponse`
└── 🔹 `EmailVerificationCode`
└── 🔹 `VerifyEmailCodeDto`
└── 🔹 `EmailVerificationResponse`
├── 🔧 `generate_code`
├── 🔧 `generate_code`
├── 🔧 `is_expired`
├── 🔧 `is_expired`

## 📄 keystroke_dynamics.rs

└── 🔹 `KeystrokeDynamics`
└── 🔹 `RegisterKeystrokePatternDto`
└── 🔹 `VerifyKeystrokePatternDto`
└── 🔹 `KeystrokeVerificationResponse`
└── 🔹 `KeystrokeStatusResponse`
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
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `OAuthConnectionResponse`
└── 🔹 `OAuthErrorResponse`
└── 🔹 `OAuthLoginRequest`
└── 🔹 `OAuthCallbackRequest`
└── 🔹 `OAuthUrlResponse`
└── 🔹 `OAuthUserProfile`
└── 🔹 `OAuthConnection`
└── 🔹 `OAuthConnectionResponse`
└── 🔹 `OAuthErrorResponse`
├── 🔧 `fmt`
├── 🔧 `fmt`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `from`

## 📄 permission.rs

└── 🔹 `Permission`
    ├── 🔸 `new` - Cria uma nova instância de Permissão.
    └── 🔸 `new` - Cria uma nova instância de Permissão.
└── 🔹 `CreatePermissionDto`
└── 🔹 `UpdatePermissionDto`
└── 🔹 `Permission`
└── 🔹 `CreatePermissionDto`
└── 🔹 `UpdatePermissionDto`

## 📄 recovery_email.rs

└── 🔹 `RecoveryEmail`
    ├── 🔸 `generate_verification_token`
    ├── 🔸 `generate_verification_token`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `AddRecoveryEmailDto`
└── 🔹 `VerifyRecoveryEmailDto`
└── 🔹 `RecoveryEmailResponse`
└── 🔹 `RecoveryEmail`
└── 🔹 `AddRecoveryEmailDto`
└── 🔹 `VerifyRecoveryEmailDto`
└── 🔹 `RecoveryEmailResponse`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `verify`
├── 🔧 `verify`

## 📄 response.rs

└── 🔹 `ApiResponse`
    ├── 🔸 `message`
    └── 🔸 `message`
└── 🔹 `PaginatedResponse`
    ├── 🔸 `new`
    ├── 🔸 `new`
    ├── 🔸 `with_message`
    └── 🔸 `with_message`
└── 🔹 `ApiResponse`
└── 🔹 `PaginatedResponse`
├── 🔧 `error`
├── 🔧 `error`
├── 🔧 `fmt`
├── 🔧 `fmt`
├── 🔧 `success`
├── 🔧 `success`
├── 🔧 `success_with_message`
├── 🔧 `success_with_message`

## 📄 role.rs

└── 🔹 `Role`
    ├── 🔸 `new` - Cria uma nova instância de Role.
    └── 🔸 `new` - Cria uma nova instância de Role.
└── 🔹 `CreateRoleDto`
└── 🔹 `UpdateRoleDto`
└── 🔹 `RolePermissionDto`
└── 🔹 `UserRoleDto`
└── 🔹 `Role`
└── 🔹 `CreateRoleDto`
└── 🔹 `UpdateRoleDto`
└── 🔹 `RolePermissionDto`
└── 🔹 `UserRoleDto`

## 📄 security_question.rs

└── 🔹 `SecurityQuestion`
    ├── 🔸 `new` - Cria uma nova instância de SecurityQuestion.
    └── 🔸 `new`
└── 🔹 `UserSecurityAnswer`
    ├── 🔸 `new` - Cria uma nova instância de UserSecurityAnswer.
    └── 🔸 `new`
└── 🔹 `CreateSecurityQuestionDto`
└── 🔹 `UpdateSecurityQuestionDto`
└── 🔹 `SetSecurityAnswerDto`
└── 🔹 `VerifySecurityAnswerDto`
└── 🔹 `RecoveryCode`
    ├── 🔸 `is_expired` - Verifica se o código já expirou.
    └── 🔸 `new` - Gera um novo código de recuperação com prazo de validade.
└── 🔹 `VerifyRecoveryCodeDto`
└── 🔹 `SecurityQuestion`
└── 🔹 `UserSecurityAnswer`
└── 🔹 `CreateSecurityQuestionDto`
└── 🔹 `UpdateSecurityQuestionDto`
└── 🔹 `CreateUserSecurityAnswerDto`
└── 🔹 `SecurityQuestionResponse`
└── 🔹 `UserQuestionResponse`
├── 🔧 `from`
├── 🔧 `generate_recovery_code` - Gera um código de recuperação forte e legível (24 caracteres).

## 📄 token.rs

└── 🔹 `BlacklistedToken`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `TokenClaims`
└── 🔹 `TokenResponse`
└── 🔹 `RefreshTokenDto`
└── 🔹 `BlacklistedToken`
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
└── 🔹 `Enable2FADto`
└── 🔹 `Verify2FADto`
└── 🔹 `Disable2FADto`
└── 🔹 `UseBackupCodeDto`
└── 🔹 `TwoFactorSetupResponse`
└── 🔹 `TwoFactorEnabledResponse`
└── 🔹 `TwoFactorStatusResponse`

## 📄 user.rs

└── 🔹 `User`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `CreateUserDto`
└── 🔹 `UpdateUserDto`
└── 🔹 `ChangePasswordDto`
└── 🔹 `UserResponse`
└── 🔹 `User`
└── 🔹 `CreateUserDto`
└── 🔹 `UpdateUserDto`
└── 🔹 `ChangePasswordDto`
└── 🔹 `UserResponse`
├── 🔧 `from`
├── 🔧 `from`
├── 🔧 `full_name`
├── 🔧 `full_name`
├── 🔧 `is_locked`
├── 🔧 `is_locked`

## 📄 mod.rs


## 📄 rbac_repository.rs

└── 🔹 `SqliteRbacRepository`
    ├── 🔸 `create_permission` - Cria uma nova permissão no banco de dados.
    └── 🔸 `create_permission` - Cria uma nova permissão no banco de dados.
└── 🔹 `Permission` - Mapeia uma linha do banco de dados para a
└── 🔹 `Role` - Mapeia uma linha do banco de dados para a
└── 🔹 `SqliteRbacRepository`
└── 🔹 `Permission` - Mapeia uma linha do banco de dados para a
└── 🔹 `Role` - Mapeia uma linha do banco de dados para a
├── 🔧 `assign_permission_to_role` - Associa uma permissão a um papel.
├── 🔧 `assign_permission_to_role` - Associa uma permissão a um papel.
├── 🔧 `assign_role_to_user` - Associa um papel a um usuário.
├── 🔧 `assign_role_to_user` - Associa um papel a um usuário.
├── 🔧 `check_user_permission` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├── 🔧 `check_user_permission` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├── 🔧 `create_role` - Cria um novo papel no banco de dados.
├── 🔧 `create_role` - Cria um novo papel no banco de dados.
├── 🔧 `delete_permission` - Deleta uma permissão pelo seu ID no banco de dados.
├── 🔧 `delete_permission` - Deleta uma permissão pelo seu ID no banco de dados.
├── 🔧 `delete_role` - Deleta um papel pelo seu ID no banco de dados.
├── 🔧 `delete_role` - Deleta um papel pelo seu ID no banco de dados.
├── 🔧 `get_permission_by_id` - Busca uma permissão pelo seu ID no banco de dados.
├── 🔧 `get_permission_by_id` - Busca uma permissão pelo seu ID no banco de dados.
├── 🔧 `get_permission_by_name` - Busca uma permissão pelo seu nome único no banco de dados.
├── 🔧 `get_permission_by_name` - Busca uma permissão pelo seu nome único no banco de dados.
├── 🔧 `get_role_by_id` - Busca um papel pelo seu ID no banco de dados.
├── 🔧 `get_role_by_id` - Busca um papel pelo seu ID no banco de dados.
├── 🔧 `get_role_by_name` - Busca um papel pelo seu nome único no banco de dados.
├── 🔧 `get_role_by_name` - Busca um papel pelo seu nome único no banco de dados.
├── 🔧 `get_role_permissions` - Lista todas as permissões associadas a um papel específico.
├── 🔧 `get_role_permissions` - Lista todas as permissões associadas a um papel específico.
├── 🔧 `get_user_roles` - Lista todos os papéis associados a um usuário específico.
├── 🔧 `get_user_roles` - Lista todos os papéis associados a um usuário específico.
├── 🔧 `list_permissions` - Lista todas as permissões do banco de dados.
├── 🔧 `list_permissions` - Lista todas as permissões do banco de dados.
├── 🔧 `list_roles` - Lista todos os papéis do banco de dados.
├── 🔧 `list_roles` - Lista todos os papéis do banco de dados.
├── 🔧 `map_row_to_permission` - Mapeia uma linha do banco de dados para a struct Permission.
├── 🔧 `map_row_to_permission` - Mapeia uma linha do banco de dados para a struct Permission.
├── 🔧 `map_row_to_role` - Mapeia uma linha do banco de dados para a struct Role.
├── 🔧 `map_row_to_role` - Mapeia uma linha do banco de dados para a struct Role.
├── 🔧 `revoke_permission_from_role` - Remove a associação entre uma permissão e um papel.
├── 🔧 `revoke_permission_from_role` - Remove a associação entre uma permissão e um papel.
├── 🔧 `revoke_role_from_user` - Remove a associação entre um usuário e um papel.
├── 🔧 `revoke_role_from_user` - Remove a associação entre um usuário e um papel.
├── 🔧 `update_permission` - Atualiza uma permissão existente no banco de dados.
├── 🔧 `update_permission` - Atualiza uma permissão existente no banco de dados.
├── 🔧 `update_role` - Atualiza um papel existente no banco de dados.
├── 🔧 `update_role` - Atualiza um papel existente no banco de dados.

## 📄 security_question_repository.rs

└── 🔹 `SqliteSecurityQuestionRepository` - Repositório para operações CRUD de perguntas de segurança e respostas de usuários.
    ├── 🔸 `create_question`
    └── 🔸 `create_security_question` - Cria uma nova pergunta de segurança.
└── 🔹 `SqliteSecurityQuestionRepository`
├── 🔧 `add_user_answer`
├── 🔧 `deactivate_security_question` - Desativa uma pergunta de segurança em vez de excluí-la.
├── 🔧 `delete_all_user_security_answers` - Remove todas as respostas de um usuário.
├── 🔧 `delete_question`
├── 🔧 `delete_security_question` - Exclui uma pergunta de segurança.
├── 🔧 `delete_user_answer`
├── 🔧 `delete_user_answers`
├── 🔧 `delete_user_security_answer` - Remove uma resposta específica de um usuário.
├── 🔧 `get_question_by_id`
├── 🔧 `get_security_question_by_id` - Busca uma pergunta de segurança pelo ID.
├── 🔧 `get_security_questions_for_email` - Obtém perguntas de segurança configuradas para um usuário pelo email.
├── 🔧 `get_user_answer_by_id`
├── 🔧 `get_user_security_answers` - Obtém todas as respostas de segurança de um usuário.
├── 🔧 `list_questions`
├── 🔧 `list_security_questions` - Lista todas as perguntas de segurança, opcionalmente filtrando por status ativo.
├── 🔧 `list_user_answers`
├── 🔧 `map_row_to_security_question` - Mapeia uma linha do banco de dados para um objeto SecurityQuestion.
├── 🔧 `set_recovery_code` - Configura um código de recuperação para um usuário.
├── 🔧 `set_user_security_answer` - Configura ou atualiza a resposta de um usuário a uma pergunta de segurança.
├── 🔧 `update_question`
├── 🔧 `update_security_question` - Atualiza uma pergunta de segurança existente.
├── 🔧 `update_user_answer`
├── 🔧 `verify_answer`
├── 🔧 `verify_recovery_code` - Verifica e consome um código de recuperação.

## 📄 mod.rs

├── 🔧 `configure_routes`
└── 🔧 `configure_routes`

## 📄 auth_service.rs

└── 🔹 `AuthService`
    ├── 🔸 `register`
    └── 🔸 `register`
└── 🔹 `AuthService`
├── 🔧 `create_session`
├── 🔧 `create_session`
├── 🔧 `find_and_validate_refresh_token`
├── 🔧 `find_and_validate_refresh_token`
├── 🔧 `forgot_password`
├── 🔧 `forgot_password`
├── 🔧 `generate_and_set_recovery_code` - Generates a unique recovery code for a user and updates the database.
├── 🔧 `generate_auth_tokens`
├── 🔧 `generate_auth_tokens`
├── 🔧 `generate_jwt`
├── 🔧 `generate_jwt`
├── 🔧 `generate_recovery_code_internal`
├── 🔧 `hash_token`
├── 🔧 `hash_token`
├── 🔧 `log_auth_event`
├── 🔧 `log_auth_event`
├── 🔧 `login`
├── 🔧 `login`
├── 🔧 `parse_expiration`
├── 🔧 `parse_expiration`
├── 🔧 `refresh_token`
├── 🔧 `refresh_token`
├── 🔧 `reset_password`
├── 🔧 `reset_password`
├── 🔧 `revoke_all_user_refresh_tokens`
├── 🔧 `revoke_all_user_refresh_tokens`
├── 🔧 `revoke_refresh_token`
├── 🔧 `revoke_refresh_token`
├── 🔧 `save_refresh_token`
├── 🔧 `save_refresh_token`
├── 🔧 `unlock_account`
├── 🔧 `unlock_account`
├── 🔧 `validate_token`
├── 🔧 `validate_token`
├── 🔧 `verify_recovery_code` - Verifies a recovery code and returns the associated user if valid.

## 📄 device_service.rs

└── 🔹 `DeviceService`
    ├── 🔸 `list_user_devices`
    └── 🔸 `list_user_devices`
└── 🔹 `DeviceService`
├── 🔧 `clean_expired_sessions`
├── 🔧 `clean_expired_sessions`
├── 🔧 `create_session_with_device_info`
├── 🔧 `create_session_with_device_info`
├── 🔧 `detect_device_type`
├── 🔧 `detect_device_type`
├── 🔧 `generate_device_name`
├── 🔧 `generate_device_name`
├── 🔧 `get_device_details`
├── 🔧 `get_device_details`
├── 🔧 `revoke_device`
├── 🔧 `revoke_device`
├── 🔧 `set_current_device`
├── 🔧 `set_current_device`
├── 🔧 `update_device`
├── 🔧 `update_device`
├── 🔧 `update_last_active`
├── 🔧 `update_last_active`

## 📄 email_service.rs

└── 🔹 `EmailService`
    ├── 🔸 `get_base_url`
    ├── 🔸 `get_base_url`
    ├── 🔸 `is_enabled`
    ├── 🔸 `is_enabled`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `EmailService`
├── 🔧 `send_account_unlock_email`
├── 🔧 `send_account_unlock_email`
├── 🔧 `send_email`
├── 🔧 `send_email`
├── 🔧 `send_password_reset_email`
├── 🔧 `send_password_reset_email`
├── 🔧 `send_welcome_email`
├── 🔧 `send_welcome_email`

## 📄 email_verification_service.rs

└── 🔹 `EmailVerificationService`
    ├── 🔸 `generate_and_send_code`
    └── 🔸 `generate_and_send_code`
└── 🔹 `EmailVerificationService`
├── 🔧 `clean_expired_codes`
├── 🔧 `clean_expired_codes`
├── 🔧 `has_pending_code`
├── 🔧 `has_pending_code`
├── 🔧 `send_verification_email`
├── 🔧 `send_verification_email`
├── 🔧 `verify_code`
├── 🔧 `verify_code`

## 📄 keystroke_security_service.rs

└── 🔹 `KeystrokeVerificationAttempt`
└── 🔹 `UserVerificationHistory`
└── 🔹 `KeystrokeSecurityService`
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `KeystrokeVerificationAttempt`
└── 🔹 `UserVerificationHistory`
└── 🔹 `KeystrokeSecurityService`
├── 🔧 `calculate_anomaly_score`
├── 🔧 `calculate_anomaly_score`
├── 🔧 `check_consecutive_failures`
├── 🔧 `check_consecutive_failures`
├── 🔧 `check_for_suspicious_patterns`
├── 🔧 `check_for_suspicious_patterns`
├── 🔧 `clean_old_history`
├── 🔧 `clean_old_history`
├── 🔧 `default`
├── 🔧 `default`
├── 🔧 `get_user_anomaly_score`
├── 🔧 `get_user_anomaly_score`
├── 🔧 `is_user_suspicious`
├── 🔧 `is_user_suspicious`
├── 🔧 `record_verification_attempt`
├── 🔧 `record_verification_attempt`

## 📄 keystroke_service.rs

└── 🔹 `KeystrokeService`
    ├── 🔸 `register_pattern` - Registra um novo padrão de digitação para o usuário
    └── 🔸 `register_pattern` - Registra um novo padrão de digitação para o usuário
└── 🔹 `KeystrokeService`
├── 🔧 `calculate_pattern_similarity` - Calcula a similaridade entre dois padrões de digitação
├── 🔧 `calculate_pattern_similarity` - Calcula a similaridade entre dois padrões de digitação
├── 🔧 `get_keystroke_status` - Obtém o status da verificação de ritmo de digitação
├── 🔧 `get_keystroke_status` - Obtém o status da verificação de ritmo de digitação
├── 🔧 `normalize_pattern` - Normaliza um padrão de digitação para valores entre 0.0 e 1.0
├── 🔧 `normalize_pattern` - Normaliza um padrão de digitação para valores entre 0.0 e 1.0
├── 🔧 `toggle_keystroke_verification` - Habilita ou desabilita a verificação de ritmo de digitação
├── 🔧 `toggle_keystroke_verification` - Habilita ou desabilita a verificação de ritmo de digitação
├── 🔧 `verify_keystroke_pattern` - Verifica o padrão de digitação durante o login
├── 🔧 `verify_keystroke_pattern` - Verifica o padrão de digitação durante o login

## 📄 mod.rs


## 📄 oauth_service.rs

└── 🔹 `OAuthService`
    ├── 🔸 `get_authorization_url` - Cria URL de autorização para o provedor OAuth especificado
    ├── 🔸 `get_authorization_url` - Cria URL de autorização para o provedor OAuth especificado
    ├── 🔸 `new`
    └── 🔸 `new`
└── 🔹 `OAuthService`
├── 🔧 `create_oauth_client` - Cria um cliente OAuth para o provedor especificado
├── 🔧 `create_oauth_client` - Cria um cliente OAuth para o provedor especificado
├── 🔧 `create_oauth_connection` - Cria uma nova conexão OAuth
├── 🔧 `create_oauth_connection` - Cria uma nova conexão OAuth
├── 🔧 `find_oauth_connection` - Encontra uma conexão OAuth existente
├── 🔧 `find_oauth_connection` - Encontra uma conexão OAuth existente
├── 🔧 `get_apple_profile` - Obtém o perfil do usuário da Apple
├── 🔧 `get_apple_profile` - Obtém o perfil do usuário da Apple
├── 🔧 `get_facebook_profile` - Obtém o perfil do usuário do Facebook
├── 🔧 `get_facebook_profile` - Obtém o perfil do usuário do Facebook
├── 🔧 `get_github_profile` - Obtém o perfil do usuário do GitHub
├── 🔧 `get_github_profile` - Obtém o perfil do usuário do GitHub
├── 🔧 `get_google_profile` - Obtém o perfil do usuário do Google
├── 🔧 `get_google_profile` - Obtém o perfil do usuário do Google
├── 🔧 `get_microsoft_profile` - Obtém o perfil do usuário do Microsoft
├── 🔧 `get_microsoft_profile` - Obtém o perfil do usuário do Microsoft
├── 🔧 `get_user_profile` - Obtém o perfil do usuário do provedor OAuth
├── 🔧 `get_user_profile` - Obtém o perfil do usuário do provedor OAuth
├── 🔧 `list_user_oauth_connections` - Lista todas as conexões OAuth de um usuário
├── 🔧 `list_user_oauth_connections` - Lista todas as conexões OAuth de um usuário
├── 🔧 `process_callback` - Processa o callback OAuth e retorna o perfil do usuário
├── 🔧 `process_callback` - Processa o callback OAuth e retorna o perfil do usuário
├── 🔧 `process_oauth_login` - Cria ou atualiza um usuário com base no perfil OAuth
├── 🔧 `process_oauth_login` - Cria ou atualiza um usuário com base no perfil OAuth
├── 🔧 `remove_oauth_connection` - Remove uma conexão OAuth
├── 🔧 `remove_oauth_connection` - Remove uma conexão OAuth

## 📄 rbac_service.rs

└── 🔹 `RbacService`
    ├── 🔸 `create_permission` - Cria uma nova permissão.
    ├── 🔸 `create_permission` - Cria uma nova permissão.
    ├── 🔸 `new` - Cria uma nova instância do RbacService.
    └── 🔸 `new` - Cria uma nova instância do RbacService.
└── 🔹 `RbacService`
├── 🔧 `assign_permission_to_role` - Associa uma permissão a um papel.
├── 🔧 `assign_permission_to_role` - Associa uma permissão a um papel.
├── 🔧 `assign_role_to_user` - Associa um papel a um usuário.
├── 🔧 `assign_role_to_user` - Associa um papel a um usuário.
├── 🔧 `check_user_permission` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├── 🔧 `check_user_permission` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├── 🔧 `create_role` - Cria um novo papel.
├── 🔧 `create_role` - Cria um novo papel.
├── 🔧 `delete_permission` - Deleta uma permissão.
├── 🔧 `delete_permission` - Deleta uma permissão.
├── 🔧 `delete_role` - Deleta um papel.
├── 🔧 `delete_role` - Deleta um papel.
├── 🔧 `get_permission_by_id` - Busca uma permissão pelo seu ID.
├── 🔧 `get_permission_by_id` - Busca uma permissão pelo seu ID.
├── 🔧 `get_permission_by_name` - Busca uma permissão pelo seu nome.
├── 🔧 `get_permission_by_name` - Busca uma permissão pelo seu nome.
├── 🔧 `get_role_by_id` - Busca um papel pelo seu ID.
├── 🔧 `get_role_by_id` - Busca um papel pelo seu ID.
├── 🔧 `get_role_by_name` - Busca um papel pelo seu nome.
├── 🔧 `get_role_by_name` - Busca um papel pelo seu nome.
├── 🔧 `get_role_permissions` - Lista todas as permissões associadas a um papel específico.
├── 🔧 `get_role_permissions` - Lista todas as permissões associadas a um papel específico.
├── 🔧 `get_user_roles` - Lista todos os papéis associados a um usuário específico.
├── 🔧 `get_user_roles` - Lista todos os papéis associados a um usuário específico.
├── 🔧 `list_permissions` - Lista todas as permissões.
├── 🔧 `list_permissions` - Lista todas as permissões.
├── 🔧 `list_roles` - Lista todos os papéis.
├── 🔧 `list_roles` - Lista todos os papéis.
├── 🔧 `revoke_permission_from_role` - Remove a associação entre uma permissão e um papel.
├── 🔧 `revoke_permission_from_role` - Remove a associação entre uma permissão e um papel.
├── 🔧 `revoke_role_from_user` - Remove a associação entre um usuário e um papel.
├── 🔧 `revoke_role_from_user` - Remove a associação entre um usuário e um papel.
├── 🔧 `update_permission` - Atualiza uma permissão existente.
├── 🔧 `update_permission` - Atualiza uma permissão existente.
├── 🔧 `update_role` - Atualiza um papel existente.
├── 🔧 `update_role` - Atualiza um papel existente.

## 📄 recovery_email_service.rs

└── 🔹 `RecoveryEmailService`
    ├── 🔸 `add_recovery_email`
    └── 🔸 `add_recovery_email`
└── 🔹 `RecoveryEmailService`
├── 🔧 `get_user_id_by_recovery_email`
├── 🔧 `get_user_id_by_recovery_email`
├── 🔧 `list_recovery_emails`
├── 🔧 `list_recovery_emails`
├── 🔧 `remove_recovery_email`
├── 🔧 `remove_recovery_email`
├── 🔧 `resend_verification_email`
├── 🔧 `resend_verification_email`
├── 🔧 `send_verification_email`
├── 🔧 `send_verification_email`
├── 🔧 `verify_recovery_email`
├── 🔧 `verify_recovery_email`

## 📄 security_question_service.rs

└── 🔹 `SecurityQuestionService`
    ├── 🔸 `create_question`
    └── 🔸 `get_question_by_id`
├── 🔧 `add_user_answer`
├── 🔧 `delete_all_user_answers`
├── 🔧 `delete_question`
├── 🔧 `delete_user_answer`
├── 🔧 `list_questions`
├── 🔧 `list_user_answers`
├── 🔧 `update_question`
├── 🔧 `update_user_answer`
├── 🔧 `user_has_min_security_questions`
├── 🔧 `verify_multiple_answers`
├── 🔧 `verify_user_answer`

## 📄 token_service.rs

└── 🔹 `TokenService`
    ├── 🔸 `generate_token`
    └── 🔸 `generate_token`
└── 🔹 `TokenService`
├── 🔧 `blacklist_token`
├── 🔧 `blacklist_token`
├── 🔧 `clean_expired_tokens`
├── 🔧 `clean_expired_tokens`
├── 🔧 `is_token_blacklisted`
├── 🔧 `is_token_blacklisted`
├── 🔧 `rotate_token`
├── 🔧 `rotate_token`
├── 🔧 `validate_token`
├── 🔧 `validate_token`

## 📄 two_factor_service.rs

└── 🔹 `TwoFactorService`
    ├── 🔸 `generate_setup`
    └── 🔸 `generate_setup`
└── 🔹 `TwoFactorService`
├── 🔧 `disable_2fa`
├── 🔧 `disable_2fa`
├── 🔧 `enable_2fa`
├── 🔧 `enable_2fa`
├── 🔧 `generate_backup_codes`
├── 🔧 `generate_backup_codes`
├── 🔧 `regenerate_backup_codes`
├── 🔧 `regenerate_backup_codes`
├── 🔧 `verify_backup_code`
├── 🔧 `verify_backup_code`
├── 🔧 `verify_totp`
├── 🔧 `verify_totp`

## 📄 user_service.rs

└── 🔹 `UserService`
    ├── 🔸 `create_user`
    └── 🔸 `create_user`
└── 🔹 `UserService`
├── 🔧 `change_password`
├── 🔧 `change_password`
├── 🔧 `delete_user`
├── 🔧 `delete_user`
├── 🔧 `get_user_by_email`
├── 🔧 `get_user_by_email`
├── 🔧 `get_user_by_email_or_username`
├── 🔧 `get_user_by_email_or_username`
├── 🔧 `get_user_by_id`
├── 🔧 `get_user_by_id`
├── 🔧 `list_users`
├── 🔧 `list_users`
├── 🔧 `update_password`
├── 🔧 `update_password`
├── 🔧 `update_user`
├── 🔧 `update_user`
├── 🔧 `verify_password`
├── 🔧 `verify_password`

## 📄 jwt.rs

└── 🔹 `JwtUtils` - Utilitários para JWT
    └── 🔸 `verify` - Verifica um token JWT e retorna as claims
├── 🔧 `extract_user_id` - Extrai o ID do usuário do token JWT na requisição
├── 🔧 `extract_user_id` - Extrai o ID do usuário do token JWT na requisição
├── 🔧 `is_admin` - Verifica se o usuário é administrador
├── 🔧 `is_admin` - Verifica se o usuário é administrador

## 📄 mod.rs


## 📄 password.rs

├── 🔧 `as_str`
├── 🔧 `as_str`
├── 🔧 `check_password_strength`
├── 🔧 `check_password_strength`
├── 🔧 `generate_random_password`
├── 🔧 `generate_random_password`
├── 🔧 `meets_requirements`
└── 🔧 `meets_requirements`

## 📄 password_argon2.rs

├── 🔧 `hash_password` - Gera um hash seguro de senha usando Argon2id (mais seguro que bcrypt)
├── 🔧 `hash_password` - Gera um hash seguro de senha usando Argon2id (mais seguro que bcrypt)
├── 🔧 `is_argon2_hash` - Verifica se um hash foi gerado com Argon2
├── 🔧 `is_argon2_hash` - Verifica se um hash foi gerado com Argon2
├── 🔧 `verify_password` - Verifica se uma senha corresponde ao hash armazenado
└── 🔧 `verify_password` - Verifica se uma senha corresponde ao hash armazenado

## 📄 tracing.rs

├── 🔧 `init_tracing` - Configura o sistema de logging estruturado com tracing
├── 🔧 `init_tracing` - Configura o sistema de logging estruturado com tracing
├── 🔧 `log_startup_info` - Registra informações sobre o ambiente de execução
└── 🔧 `log_startup_info` - Registra informações sobre o ambiente de execução

## 📄 validator.rs

├── 🔧 `validate_dto`
└── 🔧 `validate_dto`

