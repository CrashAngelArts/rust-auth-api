# Árvore de Funções do Código Rust

## mod.rs

└── `Config`
    ├──  🔸 `from_env() -> Result<Self, env::VarError> `
    └──  🔸 `from_env() -> Result<Self, env::VarError> `
└── `ServerConfig`
└── `DatabaseConfig`
└── `JwtConfig`
└── `EmailConfig`
└── `SecurityConfig`
└── `CorsConfig`
└── `OAuthConfig`
└── `Config`
└── `ServerConfig`
└── `DatabaseConfig`
└── `JwtConfig`
└── `EmailConfig`
└── `SecurityConfig`
└── `CorsConfig`
└── `OAuthConfig`
├──  🔧 `load_config() -> Result<Config, env::VarError> `
├──  🔧 `load_config() -> Result<Config, env::VarError> `

## auth_controller.rs

├──  🔧 `forgot_password(
    pool: web::Data<DbPool>,
    forgot_dto: web::Json<ForgotPasswordDto>,
    email_service: web::Data<EmailService>,
    config: web::Data<Config>, // Adicionar Config para verificar se email está habilitado
) -> Result<impl Responder, ApiError> `
├──  🔧 `forgot_password(
    pool: web::Data<DbPool>,
    forgot_dto: web::Json<ForgotPasswordDto>,
    email_service: web::Data<EmailService>,
    config: web::Data<Config>, // Adicionar Config para verificar se email está habilitado
) -> Result<impl Responder, ApiError> `
├──  🔧 `login(
    pool: web::Data<DbPool>,
    login_dto: web::Json<LoginDto>,
    config: web::Data<Config>, // Usar Config importado
    email_service: web::Data<EmailService>, // Adicionar EmailService
    req: HttpRequest,
) -> Result<impl Responder, ApiError> `
├──  🔧 `login(
    pool: web::Data<DbPool>,
    login_dto: web::Json<LoginDto>,
    config: web::Data<Config>, // Usar Config importado
    email_service: web::Data<EmailService>, // Adicionar EmailService
    req: HttpRequest,
) -> Result<impl Responder, ApiError> `
├──  🔧 `me(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>, // Extrai claims do middleware JwtAuth
) -> Result<impl Responder, ApiError> `
├──  🔧 `me(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>, // Extrai claims do middleware JwtAuth
) -> Result<impl Responder, ApiError> `
├──  🔧 `refresh_token(
    pool: web::Data<DbPool>,
    refresh_dto: web::Json<RefreshTokenDto>,
    config: web::Data<Config>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `refresh_token(
    pool: web::Data<DbPool>,
    refresh_dto: web::Json<RefreshTokenDto>,
    config: web::Data<Config>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `register(
    pool: web::Data<DbPool>,
    register_dto: web::Json<RegisterDto>,
    config: web::Data<Config>, // Usar Config importado
    email_service: web::Data<EmailService>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `register(
    pool: web::Data<DbPool>,
    register_dto: web::Json<RegisterDto>,
    config: web::Data<Config>, // Usar Config importado
    email_service: web::Data<EmailService>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `reset_password(
    pool: web::Data<DbPool>,
    reset_dto: web::Json<ResetPasswordDto>, // DTO já está atualizado
    config: web::Data<Config>, // Usar Config importado
) -> Result<impl Responder, ApiError> `
├──  🔧 `reset_password(
    pool: web::Data<DbPool>,
    reset_dto: web::Json<ResetPasswordDto>, // DTO já está atualizado
    config: web::Data<Config>, // Usar Config importado
) -> Result<impl Responder, ApiError> `
├──  🔧 `unlock_account(
    pool: web::Data<DbPool>,
    unlock_dto: web::Json<UnlockAccountDto>,
) -> Result<impl Responder, ApiError> `
└──  🔧 `unlock_account(
    pool: web::Data<DbPool>,
    unlock_dto: web::Json<UnlockAccountDto>,
) -> Result<impl Responder, ApiError> `

## device_controller.rs

├──  🔧 `clean_expired_sessions(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `clean_expired_sessions(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `get_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `get_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `list_devices(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> `
├──  🔧 `list_devices(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
) -> Result<impl Responder, ApiError> `
├──  🔧 `revoke_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
    req: HttpRequest,
) -> Result<impl Responder, ApiError> `
├──  🔧 `revoke_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
    req: HttpRequest,
) -> Result<impl Responder, ApiError> `
├──  🔧 `update_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
    update_dto: web::Json<UpdateDeviceDto>,
) -> Result<impl Responder, ApiError> `
└──  🔧 `update_device(
    pool: web::Data<DbPool>,
    auth_user: AuthenticatedUser,
    device_id: web::Path<String>,
    update_dto: web::Json<UpdateDeviceDto>,
) -> Result<impl Responder, ApiError> `

## email_verification_controller.rs

├──  🔧 `clean_expired_codes(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `clean_expired_codes(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `resend_verification_code(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>,
    email_service: web::Data<crate::services::email_service::EmailService>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `resend_verification_code(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>,
    email_service: web::Data<crate::services::email_service::EmailService>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `verify_email_code(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>,
    data: web::Json<VerifyEmailCodeDto>,
) -> Result<impl Responder, ApiError> `
└──  🔧 `verify_email_code(
    pool: web::Data<DbPool>,
    claims: web::ReqData<TokenClaims>,
    data: web::Json<VerifyEmailCodeDto>,
) -> Result<impl Responder, ApiError> `

## health_controller.rs

└── `HealthResponse`
└── `HealthResponse`
├──  🔧 `health_check(
    pool: web::Data<DbPool>,
    config: web::Data<crate::config::Config>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `health_check(
    pool: web::Data<DbPool>,
    config: web::Data<crate::config::Config>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `version() -> Result<impl Responder, ApiError> `
├──  🔧 `version() -> Result<impl Responder, ApiError> `

## keystroke_controller.rs

├──  🔧 `get_keystroke_status(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> ` - Obtém o status da verificação de ritmo de digitação
├──  🔧 `get_keystroke_status(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> ` - Obtém o status da verificação de ritmo de digitação
├──  🔧 `register_keystroke_pattern(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<RegisterKeystrokePatternDto>,
) -> Result<impl Responder, ApiError> ` - Registra um novo padrão de digitação
├──  🔧 `register_keystroke_pattern(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<RegisterKeystrokePatternDto>,
) -> Result<impl Responder, ApiError> ` - Registra um novo padrão de digitação
├──  🔧 `toggle_keystroke_verification(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    enabled: web::Query<bool>,
) -> Result<impl Responder, ApiError> ` - Habilita ou desabilita a verificação de ritmo de digitação
├──  🔧 `toggle_keystroke_verification(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    enabled: web::Query<bool>,
) -> Result<impl Responder, ApiError> ` - Habilita ou desabilita a verificação de ritmo de digitação
├──  🔧 `verify_keystroke_pattern(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<VerifyKeystrokePatternDto>,
    req: HttpRequest,
    security_service: web::Data<KeystrokeSecurityService>,
) -> Result<impl Responder, ApiError> ` - Verifica um padrão de digitação durante o login
└──  🔧 `verify_keystroke_pattern(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<VerifyKeystrokePatternDto>,
    req: HttpRequest,
    security_service: web::Data<KeystrokeSecurityService>,
) -> Result<impl Responder, ApiError> ` - Verifica um padrão de digitação durante o login

## mod.rs


## oauth_controller.rs

├──  🔧 `list_oauth_connections(
    _req: HttpRequest,
    user_id: web::Path<String>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder `
├──  🔧 `list_oauth_connections(
    _req: HttpRequest,
    user_id: web::Path<String>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder `
├──  🔧 `oauth_callback(
    req: HttpRequest,
    query: web::Query<OAuthCallbackRequest>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder `
├──  🔧 `oauth_callback(
    req: HttpRequest,
    query: web::Query<OAuthCallbackRequest>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder `
├──  🔧 `oauth_login(
    _req: HttpRequest,
    data: web::Json<OAuthLoginRequest>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder `
├──  🔧 `oauth_login(
    _req: HttpRequest,
    data: web::Json<OAuthLoginRequest>,
    config: web::Data<Arc<Config>>,
    db_pool: web::Data<DbPool>,
) -> impl Responder `
├──  🔧 `remove_oauth_connection(
    _req: HttpRequest,
    path: web::Path<(String, String)`
└──  🔧 `remove_oauth_connection(
    _req: HttpRequest,
    path: web::Path<(String, String)`

## rbac_controller.rs

├──  🔧 `assign_permission_to_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `assign_permission_to_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `assign_role_to_user_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `assign_role_to_user_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `check_user_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `check_user_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `configure_rbac_routes(cfg: &mut web::ServiceConfig)`
├──  🔧 `configure_rbac_routes(cfg: &mut web::ServiceConfig)`
├──  🔧 `create_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    dto: web::Json<CreatePermissionDto>
) -> ActixResult<impl Responder> `
├──  🔧 `create_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    dto: web::Json<CreatePermissionDto>
) -> ActixResult<impl Responder> `
├──  🔧 `create_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    dto: web::Json<CreateRoleDto>
) -> ActixResult<impl Responder> `
├──  🔧 `create_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    dto: web::Json<CreateRoleDto>
) -> ActixResult<impl Responder> `
├──  🔧 `delete_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `delete_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `delete_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `delete_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_permission_by_id_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String> // Renomear para clareza se desejar
) -> ActixResult<impl Responder> `
├──  🔧 `get_permission_by_id_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String> // Renomear para clareza se desejar
) -> ActixResult<impl Responder> `
├──  🔧 `get_permission_by_name_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_permission_by_name_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_role_by_id_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_role_by_id_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_role_by_name_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_role_by_name_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_role_permissions_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_role_permissions_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_user_roles_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `get_user_roles_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>
) -> ActixResult<impl Responder> `
├──  🔧 `list_permissions_handler(
    rbac_service: web::Data<RbacService> // Receber RbacService
) -> ActixResult<impl Responder> `
├──  🔧 `list_permissions_handler(
    rbac_service: web::Data<RbacService> // Receber RbacService
) -> ActixResult<impl Responder> `
├──  🔧 `list_roles_handler(
    rbac_service: web::Data<RbacService> // Receber RbacService
) -> ActixResult<impl Responder> `
├──  🔧 `list_roles_handler(
    rbac_service: web::Data<RbacService> // Receber RbacService
) -> ActixResult<impl Responder> `
├──  🔧 `revoke_permission_from_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `revoke_permission_from_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `revoke_role_from_user_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `revoke_role_from_user_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<(String, String)`
├──  🔧 `update_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>,
    dto: web::Json<UpdatePermissionDto>
) -> ActixResult<impl Responder> `
├──  🔧 `update_permission_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>,
    dto: web::Json<UpdatePermissionDto>
) -> ActixResult<impl Responder> `
├──  🔧 `update_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>,
    dto: web::Json<UpdateRoleDto>
) -> ActixResult<impl Responder> `
└──  🔧 `update_role_handler(
    rbac_service: web::Data<RbacService>, // Receber RbacService
    path: web::Path<String>,
    dto: web::Json<UpdateRoleDto>
) -> ActixResult<impl Responder> `

## recovery_email_controller.rs

├──  🔧 `add_recovery_email(
    pool: web::Data<DbPool>,
    email_service: web::Data<EmailService>,
    dto: web::Json<AddRecoveryEmailDto>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `add_recovery_email(
    pool: web::Data<DbPool>,
    email_service: web::Data<EmailService>,
    dto: web::Json<AddRecoveryEmailDto>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_recovery_emails(
    pool: web::Data<DbPool>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_recovery_emails(
    pool: web::Data<DbPool>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `remove_recovery_email(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `remove_recovery_email(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `resend_verification_email(
    pool: web::Data<DbPool>,
    email_service: web::Data<EmailService>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `resend_verification_email(
    pool: web::Data<DbPool>,
    email_service: web::Data<EmailService>,
    path: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `verify_recovery_email(
    pool: web::Data<DbPool>,
    dto: web::Json<VerifyRecoveryEmailDto>,
) -> Result<HttpResponse, ApiError> `
└──  🔧 `verify_recovery_email(
    pool: web::Data<DbPool>,
    dto: web::Json<VerifyRecoveryEmailDto>,
) -> Result<HttpResponse, ApiError> `

## security_question_controller.rs

└── `ListQuestionsQuery`
└── `ListResponse`
└── `UpdateSecurityAnswerDto`
└── `ListQuestionsQuery`
└── `ListResponse`
└── `UpdateSecurityAnswerDto`
├──  🔧 `add_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    dto: web::Json<CreateUserSecurityAnswerDto>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `add_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    dto: web::Json<CreateUserSecurityAnswerDto>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `config(cfg: &mut web::ServiceConfig)`
├──  🔧 `config(cfg: &mut web::ServiceConfig)`
├──  🔧 `create_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    dto: web::Json<CreateSecurityQuestionDto>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `create_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    dto: web::Json<CreateSecurityQuestionDto>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `delete_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `delete_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `delete_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `delete_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `get_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `get_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_active_questions(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    query: web::Query<ListQuestionsQuery>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_active_questions(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    query: web::Query<ListQuestionsQuery>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_questions(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    query: web::Query<ListQuestionsQuery>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_questions(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    query: web::Query<ListQuestionsQuery>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_user_answers(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `list_user_answers(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `update_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
    dto: web::Json<UpdateSecurityQuestionDto>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `update_question(
    pool: web::Data<DbPool>,
    _auth: BearerAuth,
    path: web::Path<String>,
    dto: web::Json<UpdateSecurityQuestionDto>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `update_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    path: web::Path<String>,
    dto: web::Json<UpdateSecurityAnswerDto>,
) -> Result<HttpResponse, ApiError> `
├──  🔧 `update_security_answer(
    pool: web::Data<DbPool>,
    auth: BearerAuth,
    path: web::Path<String>,
    dto: web::Json<UpdateSecurityAnswerDto>,
) -> Result<HttpResponse, ApiError> `

## token_controller.rs

├──  🔧 `clean_expired_tokens(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `clean_expired_tokens(
    pool: web::Data<DbPool>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `revoke_all_tokens(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `revoke_all_tokens(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `revoke_token(
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    data: web::Json<RefreshTokenDto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `revoke_token(
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    data: web::Json<RefreshTokenDto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `rotate_token(
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    data: web::Json<RefreshTokenDto>,
) -> Result<impl Responder, ApiError> `
└──  🔧 `rotate_token(
    pool: web::Data<DbPool>,
    config: web::Data<Config>,
    data: web::Json<RefreshTokenDto>,
) -> Result<impl Responder, ApiError> `

## two_factor_controller.rs

├──  🔧 `disable_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Disable2FADto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `disable_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Disable2FADto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `enable_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Enable2FADto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `enable_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Enable2FADto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `get_2fa_status(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `get_2fa_status(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `regenerate_backup_codes(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Verify2FADto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `regenerate_backup_codes(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
    data: web::Json<Verify2FADto>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `setup_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `
└──  🔧 `setup_2fa(
    pool: web::Data<DbPool>,
    user_id: web::Path<String>,
) -> Result<impl Responder, ApiError> `

## user_controller.rs

└── `ListUsersQuery`
└── `ListUsersQuery`
├──  🔧 `change_password(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    change_dto: web::Json<ChangePasswordDto>,
    claims: web::ReqData<TokenClaims>,
    config: web::Data<crate::config::Config>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `change_password(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    change_dto: web::Json<ChangePasswordDto>,
    claims: web::ReqData<TokenClaims>,
    config: web::Data<crate::config::Config>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `delete_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `delete_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `get_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `get_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `list_users(
    pool: web::Data<DbPool>,
    query: web::Query<ListUsersQuery>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `list_users(
    pool: web::Data<DbPool>,
    query: web::Query<ListUsersQuery>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `update_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    update_dto: web::Json<UpdateUserDto>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> `
├──  🔧 `update_user(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    update_dto: web::Json<UpdateUserDto>,
    claims: web::ReqData<TokenClaims>,
) -> Result<impl Responder, ApiError> `

## webauthn_controller.rs

├──  🔧 `list_webauthn(user_id: web::Path<String>) -> impl Responder `
├──  🔧 `list_webauthn(user_id: web::Path<String>) -> impl Responder `
├──  🔧 `register_webauthn(web::Json(cred)`
└──  🔧 `register_webauthn(web::Json(cred)`

## webhook_controller.rs

├──  🔧 `list_webhooks() -> impl Responder `
├──  🔧 `list_webhooks() -> impl Responder `
├──  🔧 `register_webhook(web::Json(cfg)`
├──  🔧 `register_webhook(web::Json(cfg)`
├──  🔧 `remove_webhook(id: web::Path<String>) -> impl Responder `
└──  🔧 `remove_webhook(id: web::Path<String>) -> impl Responder `

## migrations.rs


## mod.rs

├──  🔧 `get_connection(pool: &DbPool) -> Result<DbConnection, ApiError> `
├──  🔧 `get_connection(pool: &DbPool) -> Result<DbConnection, ApiError> `
├──  🔧 `init_db(database_url: &str) -> Result<DbPool, ApiError> `
├──  🔧 `init_db(database_url: &str) -> Result<DbPool, ApiError> `
├──  🔧 `seed_rbac_data(conn: &mut Connection) -> Result<(), RusqliteError> ` - Função para semear dados RBAC essenciais (permissões e papel admin)
└──  🔧 `seed_rbac_data(conn: &mut Connection) -> Result<(), RusqliteError> ` - Função para semear dados RBAC essenciais (permissões e papel admin)

## pool.rs

└── `DbConnection`
    ├──  🔸 `deref(&self) -> &Self::Target `
    ├──  🔸 `deref(&self) -> &Self::Target `
    ├──  🔸 `deref_mut(&mut self) -> &mut Self::Target `
    ├──  🔸 `deref_mut(&mut self) -> &mut Self::Target `
    ├──  🔸 `get(pool: &web::Data<DbPool>) -> Result<Self, r2d2::Error> `
    └──  🔸 `get(pool: &web::Data<DbPool>) -> Result<Self, r2d2::Error> `
└── `DbConnection`

## mod.rs

└── `ErrorResponse`
└── `ErrorResponse`
├──  🔧 `error_response(&self) -> HttpResponse `
├──  🔧 `error_response(&self) -> HttpResponse `
├──  🔧 `fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result `
├──  🔧 `fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result `
├──  🔧 `from(error: actix_web::error::BlockingError) -> ApiError `
├──  🔧 `from(error: lettre::transport::smtp::Error) -> ApiError `
├──  🔧 `from(error: rusqlite::Error) -> ApiError `
├──  🔧 `from(error: r2d2::Error) -> ApiError `
├──  🔧 `from(error: bcrypt::BcryptError) -> ApiError `
├──  🔧 `from(error: jsonwebtoken::errors::Error) -> ApiError `
├──  🔧 `from(error: std::env::VarError) -> ApiError `
├──  🔧 `from(error: lettre::error::Error) -> ApiError `
├──  🔧 `from(error: std::io::Error) -> ApiError `
├──  🔧 `from(error: uuid::Error) -> ApiError `
├──  🔧 `from(errors: ValidationErrors) -> ApiError `
├──  🔧 `from(error: actix_web::error::BlockingError) -> ApiError `
├──  🔧 `from(error: lettre::transport::smtp::Error) -> ApiError `
├──  🔧 `from(error: rusqlite::Error) -> ApiError `
├──  🔧 `from(error: r2d2::Error) -> ApiError `
├──  🔧 `from(error: bcrypt::BcryptError) -> ApiError `
├──  🔧 `from(error: jsonwebtoken::errors::Error) -> ApiError `
├──  🔧 `from(error: std::env::VarError) -> ApiError `
├──  🔧 `from(error: lettre::error::Error) -> ApiError `
├──  🔧 `from(error: std::io::Error) -> ApiError `
├──  🔧 `from(error: uuid::Error) -> ApiError `
├──  🔧 `from(errors: ValidationErrors) -> ApiError `
├──  🔧 `log_error(error: &ApiError)`
├──  🔧 `log_error(error: &ApiError)`
├──  🔧 `status_code(&self) -> StatusCode `
├──  🔧 `status_code(&self) -> StatusCode `

## lib.rs


## main.rs

├──  🔧 `main() -> std::io::Result<()> `
└──  🔧 `main() -> std::io::Result<()> `

## auth.rs

└── `AuthenticatedUser`
└── `JwtAuth`
    ├──  🔸 `clone(&self) -> Self `
    ├──  🔸 `clone(&self) -> Self `
    ├──  🔸 `new(jwt_secret: String) -> Self `
    └──  🔸 `new(jwt_secret: String) -> Self `
└── `JwtAuthMiddleware`
└── `AdminAuth`
    ├──  🔸 `clone(&self) -> Self `
    ├──  🔸 `clone(&self) -> Self `
    ├──  🔸 `new() -> Self `
    └──  🔸 `new() -> Self `
└── `AdminAuthMiddleware`
└── `AuthenticatedUser`
└── `JwtAuth`
└── `JwtAuthMiddleware`
└── `AdminAuth`
└── `AdminAuthMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future `
├──  🔧 `from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `

## cors.rs

├──  🔧 `configure_cors(config: &Config) -> Cors `
└──  🔧 `configure_cors(config: &Config) -> Cors `

## csrf.rs

└── `CsrfProtect`
    ├──  🔸 `from_config(config: &Config) -> Self ` - Cria uma nova instância do Transform CSRF a partir da configuração da aplicação.
    └──  🔸 `from_config(config: &Config) -> Self ` - Cria uma nova instância do Transform CSRF a partir da configuração da aplicação.
└── `CsrfProtectMiddleware`
└── `CsrfProtect`
└── `CsrfProtectMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `constant_time_compare(a: &[u8], b: &[u8]) -> bool ` - Implementação segura de comparação de tempo constante para evitar ataques de timing
├──  🔧 `constant_time_compare(a: &[u8], b: &[u8]) -> bool ` - Implementação segura de comparação de tempo constante para evitar ataques de timing
├──  🔧 `error_response(&self) -> HttpResponse `
├──  🔧 `error_response(&self) -> HttpResponse `
├──  🔧 `generate_csrf_token() -> String `
├──  🔧 `generate_csrf_token() -> String `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `status_code(&self) -> StatusCode `
├──  🔧 `status_code(&self) -> StatusCode `

## email_verification.rs

└── `EmailVerificationCheck`
    ├──  🔸 `new() -> Self `
    ├──  🔸 `new() -> Self `
    ├──  🔸 `new_transform(&self, service: S) -> Self::Future `
    └──  🔸 `new_transform(&self, service: S) -> Self::Future `
└── `EmailVerificationCheckMiddleware`
└── `EmailVerificationCheck`
└── `EmailVerificationCheckMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `

## error.rs

└── `ErrorHandler`
    ├──  🔸 `new() -> Self `
    ├──  🔸 `new() -> Self `
    ├──  🔸 `new_transform(&self, service: S) -> Self::Future `
    └──  🔸 `new_transform(&self, service: S) -> Self::Future `
└── `ErrorHandlerMiddleware`
└── `ErrorHandler`
└── `ErrorHandlerMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `

## keystroke_rate_limiter.rs

└── `KeystrokeAttempts`
└── `KeystrokeRateLimiter`
    ├──  🔸 `default() -> Self `
    ├──  🔸 `default() -> Self `
    ├──  🔸 `new(max_attempts: usize, window_duration: Duration, block_duration: Duration) -> Self `
    └──  🔸 `new(max_attempts: usize, window_duration: Duration, block_duration: Duration) -> Self `
└── `KeystrokeRateLimiterMiddleware`
└── `KeystrokeAttempts`
└── `KeystrokeRateLimiter`
└── `KeystrokeRateLimiterMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `clean_keystroke_rate_limit_entries(attempts_map: Arc<Mutex<HashMap<String, KeystrokeAttempts>>>)`
├──  🔧 `clean_keystroke_rate_limit_entries(attempts_map: Arc<Mutex<HashMap<String, KeystrokeAttempts>>>)`
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> `
├──  🔧 `poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> `

## logger.rs

└── `RequestLogger`
    ├──  🔸 `new() -> Self `
    ├──  🔸 `new() -> Self `
    ├──  🔸 `new_transform(&self, service: S) -> Self::Future `
    └──  🔸 `new_transform(&self, service: S) -> Self::Future `
└── `RequestLoggerMiddleware`
└── `RequestLogger`
└── `RequestLoggerMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `

## mod.rs


## permission.rs

└── `PermissionAuth`
    ├──  🔸 `new(permission: &str) -> Self `
    └──  🔸 `new(permission: &str) -> Self `
└── `PermissionAuthMiddleware`
└── `PermissionAuth`
└── `PermissionAuthMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `

## rate_limiter.rs

└── `TokenBucketInfo`
└── `RateLimiter`
    ├──  🔸 `new(capacity: u32, refill_rate: f64) -> Self ` - Cria um novo Rate Limiter com o algoritmo Token Bucket.
    └──  🔸 `new(capacity: u32, refill_rate: f64) -> Self ` - Cria um novo Rate Limiter com o algoritmo Token Bucket.
└── `RateLimiterMiddleware`
└── `TokenBucketInfo`
└── `RateLimiter`
└── `RateLimiterMiddleware`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `

## security.rs

└── `SecurityHeaders`
    ├──  🔸 `new() -> Self `
    └──  🔸 `new() -> Self `
└── `SecurityHeadersMiddleware`
└── `CsrfProtectionMiddleware`
    ├──  🔸 `new(secret: &str) -> Self `
    └──  🔸 `new(secret: &str) -> Self `
└── `CsrfProtectionService`
└── `SecurityHeaders`
└── `SecurityHeadersMiddleware`
└── `CsrfProtectionMiddleware`
└── `CsrfProtectionService`
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `call(&self, req: ServiceRequest) -> Self::Future `
├──  🔧 `clone(&self) -> Self `
├──  🔧 `clone(&self) -> Self `
├──  🔧 `configure_security(jwt_secret: &str) -> (SecurityHeaders, CsrfProtectionMiddleware) `
├──  🔧 `configure_security(jwt_secret: &str) -> (SecurityHeaders, CsrfProtectionMiddleware) `
├──  🔧 `generate_csrf_token(secret: &str) -> (String, String) `
├──  🔧 `generate_csrf_token(secret: &str) -> (String, String) `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `new_transform(&self, service: S) -> Self::Future `
├──  🔧 `with_header(mut self, name: &str, value: &str) -> Self `
├──  🔧 `with_header(mut self, name: &str, value: &str) -> Self `

## auth.rs

└── `LoginDto`
└── `RegisterDto`
└── `ForgotPasswordDto`
└── `ResetPasswordDto`
└── `TokenClaims`
└── `AuthResponse`
└── `PasswordResetToken`
    ├──  🔸 `is_expired(&self) -> bool `
    ├──  🔸 `is_expired(&self) -> bool `
    ├──  🔸 `new(user_id: String) -> Self `
    └──  🔸 `new(user_id: String) -> Self `
└── `RefreshToken`
    ├──  🔸 `new(user_id: String, duration_days: i64) -> Self `
    └──  🔸 `new(user_id: String, duration_days: i64) -> Self `
└── `RefreshTokenDto`
└── `Session`
    ├──  🔸 `is_expired(&self) -> bool `
    ├──  🔸 `is_expired(&self) -> bool `
    ├──  🔸 `new(
        user_id: String,
        ip_address: String,
        user_agent: String,
        duration_hours: i64,
    ) -> Self `
    └──  🔸 `new(
        user_id: String,
        ip_address: String,
        user_agent: String,
        duration_hours: i64,
    ) -> Self `
└── `AuthLog`
    ├──  🔸 `new(
        user_id: Option<String>,
        event_type: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    ) -> Self `
    └──  🔸 `new(
        user_id: Option<String>,
        event_type: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    ) -> Self `
└── `UnlockAccountDto`
└── `LoginDto`
└── `RegisterDto`
└── `ForgotPasswordDto`
└── `ResetPasswordDto`
└── `TokenClaims`
└── `AuthResponse`
└── `PasswordResetToken`
└── `RefreshToken`
└── `RefreshTokenDto`
└── `Session`
└── `AuthLog`
└── `UnlockAccountDto`
├──  🔧 `is_expired(&self) -> bool `
├──  🔧 `is_expired(&self) -> bool `
├──  🔧 `validate_reset_method(dto: &ResetPasswordDto) -> Result<(), ValidationError> `
├──  🔧 `validate_reset_method(dto: &ResetPasswordDto) -> Result<(), ValidationError> `

## device.rs

└── `Device`
└── `DeviceInfo`
└── `UpdateDeviceDto`
└── `DeviceListResponse`
└── `Device`
└── `DeviceInfo`
└── `UpdateDeviceDto`
└── `DeviceListResponse`

## email_verification.rs

└── `EmailVerificationCode`
    ├──  🔸 `new(user_id: String, ip_address: Option<String>, user_agent: Option<String>, expiration_minutes: i64) -> Self `
    └──  🔸 `new(user_id: String, ip_address: Option<String>, user_agent: Option<String>, expiration_minutes: i64) -> Self `
└── `VerifyEmailCodeDto`
└── `EmailVerificationResponse`
└── `EmailVerificationCode`
└── `VerifyEmailCodeDto`
└── `EmailVerificationResponse`
├──  🔧 `generate_code() -> String `
├──  🔧 `generate_code() -> String `
├──  🔧 `is_expired(&self) -> bool `
├──  🔧 `is_expired(&self) -> bool `

## keystroke_dynamics.rs

└── `KeystrokeDynamics`
└── `RegisterKeystrokePatternDto`
└── `VerifyKeystrokePatternDto`
└── `KeystrokeVerificationResponse`
└── `KeystrokeStatusResponse`
└── `KeystrokeDynamics`
└── `RegisterKeystrokePatternDto`
└── `VerifyKeystrokePatternDto`
└── `KeystrokeVerificationResponse`
└── `KeystrokeStatusResponse`

## mod.rs


## oauth.rs

└── `OAuthLoginRequest`
└── `OAuthCallbackRequest`
└── `OAuthUrlResponse`
└── `OAuthUserProfile`
└── `OAuthConnection`
    ├──  🔸 `new(user_id: &str, profile: &OAuthUserProfile) -> Self `
    └──  🔸 `new(user_id: &str, profile: &OAuthUserProfile) -> Self `
└── `OAuthConnectionResponse`
└── `OAuthErrorResponse`
└── `OAuthLoginRequest`
└── `OAuthCallbackRequest`
└── `OAuthUrlResponse`
└── `OAuthUserProfile`
└── `OAuthConnection`
└── `OAuthConnectionResponse`
└── `OAuthErrorResponse`
├──  🔧 `fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result `
├──  🔧 `fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result `
├──  🔧 `from(s: &str) -> Self `
├──  🔧 `from(conn: &OAuthConnection) -> Self `
├──  🔧 `from(s: &str) -> Self `
├──  🔧 `from(conn: &OAuthConnection) -> Self `

## permission.rs

└── `Permission`
    ├──  🔸 `new(name: String, description: Option<String>) -> Self ` - Cria uma nova instância de Permissão.
    └──  🔸 `new(name: String, description: Option<String>) -> Self ` - Cria uma nova instância de Permissão.
└── `CreatePermissionDto`
└── `UpdatePermissionDto`
└── `Permission`
└── `CreatePermissionDto`
└── `UpdatePermissionDto`

## recovery_email.rs

└── `RecoveryEmail`
    ├──  🔸 `generate_verification_token(&mut self) -> String `
    ├──  🔸 `generate_verification_token(&mut self) -> String `
    ├──  🔸 `new(user_id: String, email: String) -> Self `
    └──  🔸 `new(user_id: String, email: String) -> Self `
└── `AddRecoveryEmailDto`
└── `VerifyRecoveryEmailDto`
└── `RecoveryEmailResponse`
└── `RecoveryEmail`
└── `AddRecoveryEmailDto`
└── `VerifyRecoveryEmailDto`
└── `RecoveryEmailResponse`
├──  🔧 `from(email: RecoveryEmail) -> Self `
├──  🔧 `from(email: RecoveryEmail) -> Self `
├──  🔧 `verify(&mut self)`
├──  🔧 `verify(&mut self)`

## response.rs

└── `ApiResponse`
    ├──  🔸 `message(message: &str) -> Self `
    └──  🔸 `message(message: &str) -> Self `
└── `PaginatedResponse`
    ├──  🔸 `new(data: Vec<T>, total: u64, page: u64, page_size: u64) -> Self `
    ├──  🔸 `new(data: Vec<T>, total: u64, page: u64, page_size: u64) -> Self `
    ├──  🔸 `with_message(data: Vec<T>, total: u64, page: u64, page_size: u64, message: &str) -> Self `
    └──  🔸 `with_message(data: Vec<T>, total: u64, page: u64, page_size: u64, message: &str) -> Self `
└── `ApiResponse`
└── `PaginatedResponse`
├──  🔧 `error(message: &str) -> Self `
├──  🔧 `error(message: &str) -> Self `
├──  🔧 `fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result `
├──  🔧 `fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result `
├──  🔧 `success(data: T) -> Self `
├──  🔧 `success(data: T) -> Self `
├──  🔧 `success_with_message(data: T, message: &str) -> Self `
├──  🔧 `success_with_message(data: T, message: &str) -> Self `

## role.rs

└── `Role`
    ├──  🔸 `new(name: String, description: Option<String>) -> Self ` - Cria uma nova instância de Role.
    └──  🔸 `new(name: String, description: Option<String>) -> Self ` - Cria uma nova instância de Role.
└── `CreateRoleDto`
└── `UpdateRoleDto`
└── `RolePermissionDto`
└── `UserRoleDto`
└── `Role`
└── `CreateRoleDto`
└── `UpdateRoleDto`
└── `RolePermissionDto`
└── `UserRoleDto`

## security_question.rs

└── `SecurityQuestion`
    ├──  🔸 `new(text: String) -> Self `
    └──  🔸 `new(text: String) -> Self `
└── `UserSecurityAnswer`
    ├──  🔸 `new(user_id: String, question_id: String, answer_hash: String) -> Self `
    └──  🔸 `new(user_id: String, question_id: String, answer_hash: String) -> Self `
└── `CreateSecurityQuestionDto`
└── `UpdateSecurityQuestionDto`
└── `CreateUserSecurityAnswerDto`
└── `SecurityQuestionResponse`
└── `UserQuestionResponse`
└── `SecurityQuestion`
└── `UserSecurityAnswer`
└── `CreateSecurityQuestionDto`
└── `UpdateSecurityQuestionDto`
└── `CreateUserSecurityAnswerDto`
└── `SecurityQuestionResponse`
└── `UserQuestionResponse`
├──  🔧 `from(question: SecurityQuestion) -> Self `
├──  🔧 `from(question: SecurityQuestion) -> Self `

## token.rs

└── `BlacklistedToken`
    ├──  🔸 `new(token_id: String, expiry: DateTime<Utc>) -> Self `
    └──  🔸 `new(token_id: String, expiry: DateTime<Utc>) -> Self `
└── `TokenClaims`
└── `TokenResponse`
└── `RefreshTokenDto`
└── `BlacklistedToken`
└── `TokenClaims`
└── `TokenResponse`
└── `RefreshTokenDto`

## two_factor.rs

└── `Enable2FADto`
└── `Verify2FADto`
└── `Disable2FADto`
└── `UseBackupCodeDto`
└── `TwoFactorSetupResponse`
└── `TwoFactorEnabledResponse`
└── `TwoFactorStatusResponse`
└── `Enable2FADto`
└── `Verify2FADto`
└── `Disable2FADto`
└── `UseBackupCodeDto`
└── `TwoFactorSetupResponse`
└── `TwoFactorEnabledResponse`
└── `TwoFactorStatusResponse`

## user.rs

└── `User`
    ├──  🔸 `new(
        email: String,
        username: String,
        password_hash: String,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> Self `
    └──  🔸 `new(
        email: String,
        username: String,
        password_hash: String,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> Self `
└── `CreateUserDto`
└── `UpdateUserDto`
└── `ChangePasswordDto`
└── `UserResponse`
└── `User`
└── `CreateUserDto`
└── `UpdateUserDto`
└── `ChangePasswordDto`
└── `UserResponse`
├──  🔧 `from(user: User) -> Self `
├──  🔧 `from(user: User) -> Self `
├──  🔧 `full_name(&self) -> String `
├──  🔧 `full_name(&self) -> String `
├──  🔧 `is_locked(&self) -> bool `
├──  🔧 `is_locked(&self) -> bool `

## webauthn.rs

└── `WebauthnCredential`
└── `WebauthnCredential`

## webhook.rs

└── `WebhookConfig`
└── `WebhookConfig`

## mod.rs


## rbac_repository.rs

└── `SqliteRbacRepository`
    ├──  🔸 `create_permission(pool: &DbPool, dto: CreatePermissionDto) -> Result<Permission, ApiError> ` - Cria uma nova permissão no banco de dados.
    └──  🔸 `create_permission(pool: &DbPool, dto: CreatePermissionDto) -> Result<Permission, ApiError> ` - Cria uma nova permissão no banco de dados.
└── `Permission` - Mapeia uma linha do banco de dados para a
└── `Role` - Mapeia uma linha do banco de dados para a
└── `SqliteRbacRepository`
└── `Permission` - Mapeia uma linha do banco de dados para a
└── `Role` - Mapeia uma linha do banco de dados para a
├──  🔧 `assign_permission_to_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<usize, ApiError> ` - Associa uma permissão a um papel.
├──  🔧 `assign_permission_to_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<usize, ApiError> ` - Associa uma permissão a um papel.
├──  🔧 `assign_role_to_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<usize, ApiError> ` - Associa um papel a um usuário.
├──  🔧 `assign_role_to_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<usize, ApiError> ` - Associa um papel a um usuário.
├──  🔧 `check_user_permission(pool: &DbPool, user_id: &str, permission_name: &str) -> Result<bool, ApiError> ` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├──  🔧 `check_user_permission(pool: &DbPool, user_id: &str, permission_name: &str) -> Result<bool, ApiError> ` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├──  🔧 `create_role(pool: &DbPool, dto: CreateRoleDto) -> Result<Role, ApiError> ` - Cria um novo papel no banco de dados.
├──  🔧 `create_role(pool: &DbPool, dto: CreateRoleDto) -> Result<Role, ApiError> ` - Cria um novo papel no banco de dados.
├──  🔧 `delete_permission(pool: &DbPool, permission_id: &str) -> Result<usize, ApiError> ` - Deleta uma permissão pelo seu ID no banco de dados.
├──  🔧 `delete_permission(pool: &DbPool, permission_id: &str) -> Result<usize, ApiError> ` - Deleta uma permissão pelo seu ID no banco de dados.
├──  🔧 `delete_role(pool: &DbPool, role_id: &str) -> Result<usize, ApiError> ` - Deleta um papel pelo seu ID no banco de dados.
├──  🔧 `delete_role(pool: &DbPool, role_id: &str) -> Result<usize, ApiError> ` - Deleta um papel pelo seu ID no banco de dados.
├──  🔧 `get_permission_by_id(pool: &DbPool, permission_id: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu ID no banco de dados.
├──  🔧 `get_permission_by_id(pool: &DbPool, permission_id: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu ID no banco de dados.
├──  🔧 `get_permission_by_name(pool: &DbPool, name: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu nome único no banco de dados.
├──  🔧 `get_permission_by_name(pool: &DbPool, name: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu nome único no banco de dados.
├──  🔧 `get_role_by_id(pool: &DbPool, role_id: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu ID no banco de dados.
├──  🔧 `get_role_by_id(pool: &DbPool, role_id: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu ID no banco de dados.
├──  🔧 `get_role_by_name(pool: &DbPool, name: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu nome único no banco de dados.
├──  🔧 `get_role_by_name(pool: &DbPool, name: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu nome único no banco de dados.
├──  🔧 `get_role_permissions(pool: &DbPool, role_id: &str) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões associadas a um papel específico.
├──  🔧 `get_role_permissions(pool: &DbPool, role_id: &str) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões associadas a um papel específico.
├──  🔧 `get_user_roles(pool: &DbPool, user_id: &str) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis associados a um usuário específico.
├──  🔧 `get_user_roles(pool: &DbPool, user_id: &str) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis associados a um usuário específico.
├──  🔧 `list_permissions(pool: &DbPool) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões do banco de dados.
├──  🔧 `list_permissions(pool: &DbPool) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões do banco de dados.
├──  🔧 `list_roles(pool: &DbPool) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis do banco de dados.
├──  🔧 `list_roles(pool: &DbPool) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis do banco de dados.
├──  🔧 `map_row_to_permission(row: &rusqlite::Row) -> Result<Permission, rusqlite::Error> ` - Mapeia uma linha do banco de dados para a struct Permission.
├──  🔧 `map_row_to_permission(row: &rusqlite::Row) -> Result<Permission, rusqlite::Error> ` - Mapeia uma linha do banco de dados para a struct Permission.
├──  🔧 `map_row_to_role(row: &rusqlite::Row) -> Result<Role, rusqlite::Error> ` - Mapeia uma linha do banco de dados para a struct Role.
├──  🔧 `map_row_to_role(row: &rusqlite::Row) -> Result<Role, rusqlite::Error> ` - Mapeia uma linha do banco de dados para a struct Role.
├──  🔧 `revoke_permission_from_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<usize, ApiError> ` - Remove a associação entre uma permissão e um papel.
├──  🔧 `revoke_permission_from_role(pool: &DbPool, role_id: &str, permission_id: &str) -> Result<usize, ApiError> ` - Remove a associação entre uma permissão e um papel.
├──  🔧 `revoke_role_from_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<usize, ApiError> ` - Remove a associação entre um usuário e um papel.
├──  🔧 `revoke_role_from_user(pool: &DbPool, user_id: &str, role_id: &str) -> Result<usize, ApiError> ` - Remove a associação entre um usuário e um papel.
├──  🔧 `update_permission(
        pool: &DbPool,
        permission_id: &str,
        new_name: &str,
        new_description: &Option<String>,
    ) -> Result<(), ApiError> ` - Atualiza uma permissão existente no banco de dados.
├──  🔧 `update_permission(
        pool: &DbPool,
        permission_id: &str,
        new_name: &str,
        new_description: &Option<String>,
    ) -> Result<(), ApiError> ` - Atualiza uma permissão existente no banco de dados.
├──  🔧 `update_role(
        pool: &DbPool,
        role_id: &str,
        new_name: &str,
        new_description: &Option<String>,
    ) -> Result<(), ApiError> ` - Atualiza um papel existente no banco de dados.
├──  🔧 `update_role(
        pool: &DbPool,
        role_id: &str,
        new_name: &str,
        new_description: &Option<String>,
    ) -> Result<(), ApiError> ` - Atualiza um papel existente no banco de dados.

## security_question_repository.rs

└── `SqliteSecurityQuestionRepository`
    ├──  🔸 `create_question(pool: &DbPool, text: String) -> Result<SecurityQuestion, ApiError> `
    └──  🔸 `create_question(pool: &DbPool, text: String) -> Result<SecurityQuestion, ApiError> `
└── `SqliteSecurityQuestionRepository`
├──  🔧 `add_user_answer(
        pool: &DbPool, 
        user_id: &str, 
        question_id: &str, 
        answer_hash: &str
    ) -> Result<UserSecurityAnswer, ApiError> `
├──  🔧 `add_user_answer(
        pool: &DbPool, 
        user_id: &str, 
        question_id: &str, 
        answer_hash: &str
    ) -> Result<UserSecurityAnswer, ApiError> `
├──  🔧 `delete_question(pool: &DbPool, id: &str) -> Result<(), ApiError> `
├──  🔧 `delete_question(pool: &DbPool, id: &str) -> Result<(), ApiError> `
├──  🔧 `delete_user_answer(pool: &DbPool, id: &str) -> Result<(), ApiError> `
├──  🔧 `delete_user_answer(pool: &DbPool, id: &str) -> Result<(), ApiError> `
├──  🔧 `delete_user_answers(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `delete_user_answers(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `get_question_by_id(pool: &DbPool, id: &str) -> Result<SecurityQuestion, ApiError> `
├──  🔧 `get_question_by_id(pool: &DbPool, id: &str) -> Result<SecurityQuestion, ApiError> `
├──  🔧 `get_user_answer_by_id(pool: &DbPool, id: &str) -> Result<UserSecurityAnswer, ApiError> `
├──  🔧 `get_user_answer_by_id(pool: &DbPool, id: &str) -> Result<UserSecurityAnswer, ApiError> `
├──  🔧 `list_questions(
        pool: &DbPool, 
        page: u64, 
        page_size: u64, 
        only_active: bool
    ) -> Result<(Vec<SecurityQuestion>, u64), ApiError> `
├──  🔧 `list_questions(
        pool: &DbPool, 
        page: u64, 
        page_size: u64, 
        only_active: bool
    ) -> Result<(Vec<SecurityQuestion>, u64), ApiError> `
├──  🔧 `list_user_answers(pool: &DbPool, user_id: &str) -> Result<Vec<(UserSecurityAnswer, String)>, ApiError> `
├──  🔧 `list_user_answers(pool: &DbPool, user_id: &str) -> Result<Vec<(UserSecurityAnswer, String)>, ApiError> `
├──  🔧 `update_question(
        pool: &DbPool, 
        id: &str, 
        text: Option<String>, 
        is_active: Option<bool>
    ) -> Result<SecurityQuestion, ApiError> `
├──  🔧 `update_question(
        pool: &DbPool, 
        id: &str, 
        text: Option<String>, 
        is_active: Option<bool>
    ) -> Result<SecurityQuestion, ApiError> `
├──  🔧 `update_user_answer(
        pool: &DbPool, 
        id: &str, 
        answer_hash: &str
    ) -> Result<UserSecurityAnswer, ApiError> `
├──  🔧 `update_user_answer(
        pool: &DbPool, 
        id: &str, 
        answer_hash: &str
    ) -> Result<UserSecurityAnswer, ApiError> `
├──  🔧 `verify_answer(
        pool: &DbPool, 
        user_id: &str, 
        question_id: &str, 
        answer_hash: &str
    ) -> Result<bool, ApiError> `
├──  🔧 `verify_answer(
        pool: &DbPool, 
        user_id: &str, 
        question_id: &str, 
        answer_hash: &str
    ) -> Result<bool, ApiError> `

## mod.rs

├──  🔧 `configure_routes(cfg: &mut web::ServiceConfig, config: &Config)`
└──  🔧 `configure_routes(cfg: &mut web::ServiceConfig, config: &Config)`

## auth_management.rs

├──  🔧 `create_session(
    pool: &DbPool,
    user_id: &str,
    _refresh_token_id: &str, // Usar o ID do refresh token associado
    user_agent: Option<String>,
    ip_address: Option<String>,
) -> Result<Session, ApiError> `
├──  🔧 `find_and_validate_refresh_token(pool: &DbPool, token_value: &str) -> Result<RefreshToken, ApiError> ` - Encontra e valida um refresh token
├──  🔧 `forgot_password(
    pool: &DbPool,
    forgot_dto: ForgotPasswordDto,
    email_service: &EmailService,
    config: &Config, // Added config
) -> Result<(), ApiError> ` - Solicita a recuperação de senha
├──  🔧 `generate_and_set_recovery_code(
    pool: &DbPool,
    user_id: &str,
) -> Result<String, ApiError> ` - Gera um código de recuperação único para um usuário e atualiza o banco.
├──  🔧 `generate_recovery_code_internal(length: usize) -> String ` - Função auxiliar interna para gerar a string do código de recuperação.
├──  🔧 `hash_token(token: &str) -> String ` - Gera o hash SHA-256 de um token
├──  🔧 `reset_password(
    pool: &DbPool,
    reset_dto: ResetPasswordDto,
    salt_rounds: u32,
) -> Result<(), ApiError> ` - Redefine a senha usando token de email ou código de recuperação
├──  🔧 `revoke_all_user_refresh_tokens(pool: &DbPool, user_id: &str) -> Result<(), ApiError> ` - Revoga todos os refresh tokens de um usuário
├──  🔧 `revoke_refresh_token(pool: &DbPool, token_id: &str) -> Result<(), ApiError> ` - Revoga um refresh token específico
├──  🔧 `save_refresh_token(pool: &DbPool, token: &RefreshToken) -> Result<(), ApiError> ` - Salva um refresh token no banco
└──  🔧 `unlock_account(pool: &DbPool, unlock_dto: UnlockAccountDto) -> Result<(), ApiError> ` - Desbloqueia a conta usando o token

## auth_service.rs

└── `AuthService`
    ├──  🔸 `register(
        pool: &DbPool,
        register_dto: RegisterDto,
        salt_rounds: u32,
    ) -> Result<User, ApiError> `
    └──  🔸 `register(
        pool: &DbPool,
        register_dto: RegisterDto,
        salt_rounds: u32,
    ) -> Result<User, ApiError> `
└── `AuthService`
├──  🔧 `create_session(
        pool: &DbPool,
        user_id: &str,
        _refresh_token: &str,
        user_agent: &str,
        ip_address: &str,
    ) -> Result<Session, ApiError> `
├──  🔧 `create_session(
        pool: &DbPool,
        user_id: &str,
        _refresh_token: &str,
        user_agent: &str,
        ip_address: &str,
    ) -> Result<Session, ApiError> `
├──  🔧 `find_and_validate_refresh_token(pool: &DbPool, token_value: &str) -> Result<RefreshToken, ApiError> `
├──  🔧 `find_and_validate_refresh_token(pool: &DbPool, token_value: &str) -> Result<RefreshToken, ApiError> `
├──  🔧 `forgot_password(
        pool: &DbPool,
        forgot_dto: ForgotPasswordDto,
        email_service: &EmailService,
    ) -> Result<(), ApiError> `
├──  🔧 `forgot_password(
        pool: &DbPool,
        forgot_dto: ForgotPasswordDto,
        email_service: &EmailService,
    ) -> Result<(), ApiError> `
├──  🔧 `generate_and_set_recovery_code(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<String, ApiError> ` - Generates a unique recovery code for a user and updates the database.
├──  🔧 `generate_and_set_recovery_code(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<String, ApiError> ` - Generates a unique recovery code for a user and updates the database.
├──  🔧 `generate_auth_tokens(pool: &DbPool, user: &User) -> Result<AuthResponse, ApiError> `
├──  🔧 `generate_auth_tokens(pool: &DbPool, user: &User) -> Result<AuthResponse, ApiError> `
├──  🔧 `generate_jwt(user: &User, jwt_secret: &str, jwt_expiration: &str) -> Result<String, ApiError> `
├──  🔧 `generate_jwt(user: &User, jwt_secret: &str, jwt_expiration: &str) -> Result<String, ApiError> `
├──  🔧 `generate_recovery_code_internal(length: usize) -> String `
├──  🔧 `generate_recovery_code_internal(length: usize) -> String `
├──  🔧 `hash_token(token: &str) -> String `
├──  🔧 `hash_token(token: &str) -> String `
├──  🔧 `log_auth_event(
        pool: &DbPool,
        user_id: Option<String>,
        event_type: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    ) -> Result<(), ApiError> `
├──  🔧 `log_auth_event(
        pool: &DbPool,
        user_id: Option<String>,
        event_type: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
        details: Option<String>,
    ) -> Result<(), ApiError> `
├──  🔧 `login(
        pool: &DbPool,
        login_dto: LoginDto,
        config: &Config,
        ip_address: Option<String>,
        user_agent: Option<String>,
        email_service: &EmailService,
    ) -> Result<AuthResponse, ApiError> `
├──  🔧 `login(
        pool: &DbPool,
        login_dto: LoginDto,
        config: &Config,
        ip_address: Option<String>,
        user_agent: Option<String>,
        email_service: &EmailService,
    ) -> Result<AuthResponse, ApiError> `
├──  🔧 `parse_expiration(expiration: &str) -> Result<i64, ApiError> `
├──  🔧 `parse_expiration(expiration: &str) -> Result<i64, ApiError> `
├──  🔧 `refresh_token(
        pool: &DbPool,
        refresh_dto: RefreshTokenDto,
        config: &Config,
    ) -> Result<AuthResponse, ApiError> `
├──  🔧 `refresh_token(
        pool: &DbPool,
        refresh_dto: RefreshTokenDto,
        config: &Config,
    ) -> Result<AuthResponse, ApiError> `
├──  🔧 `reset_password(
        pool: &DbPool,
        reset_dto: ResetPasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> `
├──  🔧 `reset_password(
        pool: &DbPool,
        reset_dto: ResetPasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> `
├──  🔧 `revoke_all_user_refresh_tokens(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `revoke_all_user_refresh_tokens(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `revoke_refresh_token(pool: &DbPool, token_id: &str) -> Result<(), ApiError> `
├──  🔧 `revoke_refresh_token(pool: &DbPool, token_id: &str) -> Result<(), ApiError> `
├──  🔧 `save_refresh_token(pool: &DbPool, token: &RefreshToken) -> Result<(), ApiError> `
├──  🔧 `save_refresh_token(pool: &DbPool, token: &RefreshToken) -> Result<(), ApiError> `
├──  🔧 `unlock_account(pool: &DbPool, unlock_dto: UnlockAccountDto) -> Result<(), ApiError> `
├──  🔧 `unlock_account(pool: &DbPool, unlock_dto: UnlockAccountDto) -> Result<(), ApiError> `
├──  🔧 `validate_token( // Tornar async
        token: &str, 
        jwt_secret: &str,
        pool: Option<&DbPool>, // Adicionar pool como opcional para verificar blacklist 
        cache: &Cache<String, TokenClaims> // Adicionar parâmetro do cache
    ) -> Result<TokenClaims, ApiError> `
├──  🔧 `validate_token( // Tornar async
        token: &str, 
        jwt_secret: &str,
        pool: Option<&DbPool>, // Adicionar pool como opcional para verificar blacklist 
        cache: &Cache<String, TokenClaims> // Adicionar parâmetro do cache
    ) -> Result<TokenClaims, ApiError> `
├──  🔧 `verify_recovery_code(
        pool: &DbPool,
        recovery_code: &str,
    ) -> Result<User, ApiError> ` - Verifies a recovery code and returns the associated user if valid.
├──  🔧 `verify_recovery_code(
        pool: &DbPool,
        recovery_code: &str,
    ) -> Result<User, ApiError> ` - Verifies a recovery code and returns the associated user if valid.

## device_service.rs

└── `DeviceService`
    ├──  🔸 `list_user_devices(pool: &DbPool, user_id: &str) -> Result<DeviceListResponse, ApiError> `
    └──  🔸 `list_user_devices(pool: &DbPool, user_id: &str) -> Result<DeviceListResponse, ApiError> `
└── `DeviceService`
├──  🔧 `clean_expired_sessions(pool: &DbPool) -> Result<usize, ApiError> `
├──  🔧 `clean_expired_sessions(pool: &DbPool) -> Result<usize, ApiError> `
├──  🔧 `create_session_with_device_info(
        pool: &DbPool,
        user_id: &str,
        ip_address: &Option<String>,
        user_agent: &Option<String>,
        duration_hours: i64,
    ) -> Result<Session, ApiError> `
├──  🔧 `create_session_with_device_info(
        pool: &DbPool,
        user_id: &str,
        ip_address: &Option<String>,
        user_agent: &Option<String>,
        duration_hours: i64,
    ) -> Result<Session, ApiError> `
├──  🔧 `detect_device_type(user_agent: &Option<String>) -> Option<String> `
├──  🔧 `detect_device_type(user_agent: &Option<String>) -> Option<String> `
├──  🔧 `generate_device_name(device_type: &Option<String>, location: &Option<String>) -> String `
├──  🔧 `generate_device_name(device_type: &Option<String>, location: &Option<String>) -> String `
├──  🔧 `get_device_details(pool: &DbPool, device_id: &str, user_id: &str) -> Result<DeviceInfo, ApiError> `
├──  🔧 `get_device_details(pool: &DbPool, device_id: &str, user_id: &str) -> Result<DeviceInfo, ApiError> `
├──  🔧 `revoke_device(pool: &DbPool, device_id: &str, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `revoke_device(pool: &DbPool, device_id: &str, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `set_current_device(pool: &DbPool, device_id: &str, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `set_current_device(pool: &DbPool, device_id: &str, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `update_device(pool: &DbPool, device_id: &str, user_id: &str, device_name: &str) -> Result<DeviceInfo, ApiError> `
├──  🔧 `update_device(pool: &DbPool, device_id: &str, user_id: &str, device_name: &str) -> Result<DeviceInfo, ApiError> `
├──  🔧 `update_last_active(pool: &DbPool, device_id: &str) -> Result<(), ApiError> `
├──  🔧 `update_last_active(pool: &DbPool, device_id: &str) -> Result<(), ApiError> `

## email_service.rs

└── `EmailService`
    ├──  🔸 `get_base_url(&self) -> &str `
    ├──  🔸 `get_base_url(&self) -> &str `
    ├──  🔸 `is_enabled(&self) -> bool `
    ├──  🔸 `is_enabled(&self) -> bool `
    ├──  🔸 `new(
        smtp_server: String,
        smtp_port: u16,
        username: String,
        password: String,
        from: String,
        from_name: String,
        base_url: String,
        enabled: bool,
    ) -> Self `
    └──  🔸 `new(
        smtp_server: String,
        smtp_port: u16,
        username: String,
        password: String,
        from: String,
        from_name: String,
        base_url: String,
        enabled: bool,
    ) -> Self `
└── `EmailService`
├──  🔧 `send_account_unlock_email(&self, user: &User, token: &str) -> Result<(), ApiError> `
├──  🔧 `send_account_unlock_email(&self, user: &User, token: &str) -> Result<(), ApiError> `
├──  🔧 `send_email(
        &self,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `send_email(
        &self,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `send_password_reset_email(&self, user: &User, token: &str) -> Result<(), ApiError> `
├──  🔧 `send_password_reset_email(&self, user: &User, token: &str) -> Result<(), ApiError> `
├──  🔧 `send_welcome_email(&self, user: &User) -> Result<(), ApiError> `
├──  🔧 `send_welcome_email(&self, user: &User) -> Result<(), ApiError> `

## email_verification_service.rs

└── `EmailVerificationService`
    ├──  🔸 `generate_and_send_code(
        pool: &DbPool,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
        email_service: &EmailService,
        expiration_minutes: i64,
    ) -> Result<(), ApiError> `
    └──  🔸 `generate_and_send_code(
        pool: &DbPool,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
        email_service: &EmailService,
        expiration_minutes: i64,
    ) -> Result<(), ApiError> `
└── `EmailVerificationService`
├──  🔧 `clean_expired_codes(pool: &DbPool) -> Result<usize, ApiError> `
├──  🔧 `clean_expired_codes(pool: &DbPool) -> Result<usize, ApiError> `
├──  🔧 `has_pending_code(pool: &DbPool, user_id: &str) -> Result<bool, ApiError> `
├──  🔧 `has_pending_code(pool: &DbPool, user_id: &str) -> Result<bool, ApiError> `
├──  🔧 `send_verification_email(
        email_service: &EmailService,
        user: &User,
        code: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `send_verification_email(
        email_service: &EmailService,
        user: &User,
        code: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `verify_code(
        pool: &DbPool,
        user_id: &str,
        code: &str,
    ) -> Result<EmailVerificationResponse, ApiError> `
├──  🔧 `verify_code(
        pool: &DbPool,
        user_id: &str,
        code: &str,
    ) -> Result<EmailVerificationResponse, ApiError> `

## keystroke_security_service.rs

└── `KeystrokeVerificationAttempt`
└── `UserVerificationHistory`
└── `KeystrokeSecurityService`
    ├──  🔸 `new(
        max_failed_attempts: usize,
        suspicious_threshold: f64,
        anomaly_threshold: f64,
        history_window_secs: u64,
    ) -> Self `
    └──  🔸 `new(
        max_failed_attempts: usize,
        suspicious_threshold: f64,
        anomaly_threshold: f64,
        history_window_secs: u64,
    ) -> Self `
└── `KeystrokeVerificationAttempt`
└── `UserVerificationHistory`
└── `KeystrokeSecurityService`
├──  🔧 `calculate_anomaly_score(&self, history: &mut UserVerificationHistory)`
├──  🔧 `calculate_anomaly_score(&self, history: &mut UserVerificationHistory)`
├──  🔧 `check_consecutive_failures(
        &self,
        user_id: &str,
        history: &UserVerificationHistory,
    ) -> Result<(), ApiError> `
├──  🔧 `check_consecutive_failures(
        &self,
        user_id: &str,
        history: &UserVerificationHistory,
    ) -> Result<(), ApiError> `
├──  🔧 `check_for_suspicious_patterns(
        &self,
        user_id: &str,
        history: &mut UserVerificationHistory,
    ) -> Result<(), ApiError> `
├──  🔧 `check_for_suspicious_patterns(
        &self,
        user_id: &str,
        history: &mut UserVerificationHistory,
    ) -> Result<(), ApiError> `
├──  🔧 `clean_old_history(&self)`
├──  🔧 `clean_old_history(&self)`
├──  🔧 `default() -> Self `
├──  🔧 `default() -> Self `
├──  🔧 `get_user_anomaly_score(&self, user_id: &str) -> f64 `
├──  🔧 `get_user_anomaly_score(&self, user_id: &str) -> f64 `
├──  🔧 `is_user_suspicious(&self, user_id: &str) -> bool `
├──  🔧 `is_user_suspicious(&self, user_id: &str) -> bool `
├──  🔧 `record_verification_attempt(
        &self,
        user_id: &str,
        success: bool,
        similarity: f64,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), ApiError> `
├──  🔧 `record_verification_attempt(
        &self,
        user_id: &str,
        success: bool,
        similarity: f64,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(), ApiError> `

## keystroke_service.rs

└── `KeystrokeService`
    ├──  🔸 `register_pattern(
        pool: &DbPool,
        user_id: &str,
        typing_pattern: Vec<u32>,
        similarity_threshold: u8,
    ) -> Result<(), ApiError> ` - Registra um novo padrão de digitação para o usuário
    └──  🔸 `register_pattern(
        pool: &DbPool,
        user_id: &str,
        typing_pattern: Vec<u32>,
        similarity_threshold: u8,
    ) -> Result<(), ApiError> ` - Registra um novo padrão de digitação para o usuário
└── `KeystrokeService`
├──  🔧 `calculate_pattern_similarity(stored_pattern: &[u32], current_pattern: &[u32]) -> f32 ` - Calcula a similaridade entre dois padrões de digitação
├──  🔧 `calculate_pattern_similarity(stored_pattern: &[u32], current_pattern: &[u32]) -> f32 ` - Calcula a similaridade entre dois padrões de digitação
├──  🔧 `get_keystroke_status(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<KeystrokeStatusResponse, ApiError> ` - Obtém o status da verificação de ritmo de digitação
├──  🔧 `get_keystroke_status(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<KeystrokeStatusResponse, ApiError> ` - Obtém o status da verificação de ritmo de digitação
├──  🔧 `normalize_pattern(pattern: &[u32]) -> Vec<f32> ` - Normaliza um padrão de digitação para valores entre 0.0 e 1.0
├──  🔧 `normalize_pattern(pattern: &[u32]) -> Vec<f32> ` - Normaliza um padrão de digitação para valores entre 0.0 e 1.0
├──  🔧 `toggle_keystroke_verification(
        pool: &DbPool,
        user_id: &str,
        enabled: bool,
    ) -> Result<(), ApiError> ` - Habilita ou desabilita a verificação de ritmo de digitação
├──  🔧 `toggle_keystroke_verification(
        pool: &DbPool,
        user_id: &str,
        enabled: bool,
    ) -> Result<(), ApiError> ` - Habilita ou desabilita a verificação de ritmo de digitação
├──  🔧 `verify_keystroke_pattern(
        pool: &DbPool,
        user_id: &str,
        current_pattern: Vec<u32>,
    ) -> Result<KeystrokeVerificationResponse, ApiError> ` - Verifica o padrão de digitação durante o login
├──  🔧 `verify_keystroke_pattern(
        pool: &DbPool,
        user_id: &str,
        current_pattern: Vec<u32>,
    ) -> Result<KeystrokeVerificationResponse, ApiError> ` - Verifica o padrão de digitação durante o login

## mod.rs


## oauth_service.rs

└── `OAuthService`
    ├──  🔸 `get_authorization_url(&self, provider: OAuthProvider, _state: &str) -> Result<String, ApiError> ` - Cria URL de autorização para o provedor OAuth especificado
    ├──  🔸 `get_authorization_url(&self, provider: OAuthProvider, _state: &str) -> Result<String, ApiError> ` - Cria URL de autorização para o provedor OAuth especificado
    ├──  🔸 `new(config: Arc<Config>, db_pool: DbPool) -> Self `
    └──  🔸 `new(config: Arc<Config>, db_pool: DbPool) -> Self `
└── `OAuthService`
├──  🔧 `create_oauth_client(&self, provider: OAuthProvider) -> Result<BasicClient, ApiError> ` - Cria um cliente OAuth para o provedor especificado
├──  🔧 `create_oauth_client(&self, provider: OAuthProvider) -> Result<BasicClient, ApiError> ` - Cria um cliente OAuth para o provedor especificado
├──  🔧 `create_oauth_connection(&self, user_id: &str, profile: &OAuthUserProfile) -> Result<OAuthConnection, ApiError> ` - Cria uma nova conexão OAuth
├──  🔧 `create_oauth_connection(&self, user_id: &str, profile: &OAuthUserProfile) -> Result<OAuthConnection, ApiError> ` - Cria uma nova conexão OAuth
├──  🔧 `find_oauth_connection(&self, provider: &OAuthProvider, provider_user_id: &str) -> Result<Option<OAuthConnection>, ApiError> ` - Encontra uma conexão OAuth existente
├──  🔧 `find_oauth_connection(&self, provider: &OAuthProvider, provider_user_id: &str) -> Result<Option<OAuthConnection>, ApiError> ` - Encontra uma conexão OAuth existente
├──  🔧 `get_apple_profile(&self, _access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário da Apple
├──  🔧 `get_apple_profile(&self, _access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário da Apple
├──  🔧 `get_facebook_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do Facebook
├──  🔧 `get_facebook_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do Facebook
├──  🔧 `get_github_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do GitHub
├──  🔧 `get_github_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do GitHub
├──  🔧 `get_google_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do Google
├──  🔧 `get_google_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do Google
├──  🔧 `get_microsoft_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do Microsoft
├──  🔧 `get_microsoft_profile(&self, access_token: &str) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do Microsoft
├──  🔧 `get_user_profile(
        &self,
        provider: OAuthProvider,
        access_token: &str,
    ) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do provedor OAuth
├──  🔧 `get_user_profile(
        &self,
        provider: OAuthProvider,
        access_token: &str,
    ) -> Result<OAuthUserProfile, ApiError> ` - Obtém o perfil do usuário do provedor OAuth
├──  🔧 `list_user_oauth_connections(&self, user_id: &str) -> Result<Vec<OAuthConnection>, ApiError> ` - Lista todas as conexões OAuth de um usuário
├──  🔧 `list_user_oauth_connections(&self, user_id: &str) -> Result<Vec<OAuthConnection>, ApiError> ` - Lista todas as conexões OAuth de um usuário
├──  🔧 `process_callback(
        &self,
        provider: OAuthProvider,
        code: &str,
        _state: &str,
    ) -> Result<OAuthUserProfile, ApiError> ` - Processa o callback OAuth e retorna o perfil do usuário
├──  🔧 `process_callback(
        &self,
        provider: OAuthProvider,
        code: &str,
        _state: &str,
    ) -> Result<OAuthUserProfile, ApiError> ` - Processa o callback OAuth e retorna o perfil do usuário
├──  🔧 `process_oauth_login(&self, profile: OAuthUserProfile) -> Result<User, ApiError> ` - Cria ou atualiza um usuário com base no perfil OAuth
├──  🔧 `process_oauth_login(&self, profile: OAuthUserProfile) -> Result<User, ApiError> ` - Cria ou atualiza um usuário com base no perfil OAuth
├──  🔧 `remove_oauth_connection(&self, user_id: &str, connection_id: &str) -> Result<(), ApiError> ` - Remove uma conexão OAuth
├──  🔧 `remove_oauth_connection(&self, user_id: &str, connection_id: &str) -> Result<(), ApiError> ` - Remove uma conexão OAuth

## rbac_service.rs

└── `RbacService`
    ├──  🔸 `create_permission(&self, dto: CreatePermissionDto) -> Result<Permission, ApiError> ` - Cria uma nova permissão.
    ├──  🔸 `create_permission(&self, dto: CreatePermissionDto) -> Result<Permission, ApiError> ` - Cria uma nova permissão.
    ├──  🔸 `new(pool: DbPool) -> Self ` - Cria uma nova instância do RbacService.
    └──  🔸 `new(pool: DbPool) -> Self ` - Cria uma nova instância do RbacService.
└── `RbacService`
├──  🔧 `assign_permission_to_role(&self, role_id: &str, permission_id: &str) -> Result<(), ApiError> ` - Associa uma permissão a um papel.
├──  🔧 `assign_permission_to_role(&self, role_id: &str, permission_id: &str) -> Result<(), ApiError> ` - Associa uma permissão a um papel.
├──  🔧 `assign_role_to_user(&self, user_id: &str, role_id: &str) -> Result<(), ApiError> ` - Associa um papel a um usuário.
├──  🔧 `assign_role_to_user(&self, user_id: &str, role_id: &str) -> Result<(), ApiError> ` - Associa um papel a um usuário.
├──  🔧 `check_user_permission(&self, user_id: &str, permission_name: &str) -> Result<bool, ApiError> ` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├──  🔧 `check_user_permission(&self, user_id: &str, permission_name: &str) -> Result<bool, ApiError> ` - Verifica se um usuário possui uma permissão específica (através dos papéis associados).
├──  🔧 `create_role(&self, dto: CreateRoleDto) -> Result<Role, ApiError> ` - Cria um novo papel.
├──  🔧 `create_role(&self, dto: CreateRoleDto) -> Result<Role, ApiError> ` - Cria um novo papel.
├──  🔧 `delete_permission(&self, permission_id: &str) -> Result<(), ApiError> ` - Deleta uma permissão.
├──  🔧 `delete_permission(&self, permission_id: &str) -> Result<(), ApiError> ` - Deleta uma permissão.
├──  🔧 `delete_role(&self, role_id: &str) -> Result<(), ApiError> ` - Deleta um papel.
├──  🔧 `delete_role(&self, role_id: &str) -> Result<(), ApiError> ` - Deleta um papel.
├──  🔧 `get_permission_by_id(&self, permission_id: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu ID.
├──  🔧 `get_permission_by_id(&self, permission_id: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu ID.
├──  🔧 `get_permission_by_name(&self, name: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu nome.
├──  🔧 `get_permission_by_name(&self, name: &str) -> Result<Permission, ApiError> ` - Busca uma permissão pelo seu nome.
├──  🔧 `get_role_by_id(&self, role_id: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu ID.
├──  🔧 `get_role_by_id(&self, role_id: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu ID.
├──  🔧 `get_role_by_name(&self, name: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu nome.
├──  🔧 `get_role_by_name(&self, name: &str) -> Result<Role, ApiError> ` - Busca um papel pelo seu nome.
├──  🔧 `get_role_permissions(&self, role_id: &str) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões associadas a um papel específico.
├──  🔧 `get_role_permissions(&self, role_id: &str) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões associadas a um papel específico.
├──  🔧 `get_user_roles(&self, user_id: &str) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis associados a um usuário específico.
├──  🔧 `get_user_roles(&self, user_id: &str) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis associados a um usuário específico.
├──  🔧 `list_permissions(&self) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões.
├──  🔧 `list_permissions(&self) -> Result<Vec<Permission>, ApiError> ` - Lista todas as permissões.
├──  🔧 `list_roles(&self) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis.
├──  🔧 `list_roles(&self) -> Result<Vec<Role>, ApiError> ` - Lista todos os papéis.
├──  🔧 `revoke_permission_from_role(&self, role_id: &str, permission_id: &str) -> Result<(), ApiError> ` - Remove a associação entre uma permissão e um papel.
├──  🔧 `revoke_permission_from_role(&self, role_id: &str, permission_id: &str) -> Result<(), ApiError> ` - Remove a associação entre uma permissão e um papel.
├──  🔧 `revoke_role_from_user(&self, user_id: &str, role_id: &str) -> Result<(), ApiError> ` - Remove a associação entre um usuário e um papel.
├──  🔧 `revoke_role_from_user(&self, user_id: &str, role_id: &str) -> Result<(), ApiError> ` - Remove a associação entre um usuário e um papel.
├──  🔧 `update_permission(&self, permission_id: &str, dto: UpdatePermissionDto) -> Result<Permission, ApiError> ` - Atualiza uma permissão existente.
├──  🔧 `update_permission(&self, permission_id: &str, dto: UpdatePermissionDto) -> Result<Permission, ApiError> ` - Atualiza uma permissão existente.
├──  🔧 `update_role(&self, role_id: &str, dto: UpdateRoleDto) -> Result<(), ApiError> ` - Atualiza um papel existente.
├──  🔧 `update_role(&self, role_id: &str, dto: UpdateRoleDto) -> Result<(), ApiError> ` - Atualiza um papel existente.

## recovery_email_service.rs

└── `RecoveryEmailService`
    ├──  🔸 `add_recovery_email(
        pool: &DbPool,
        user_id: &str,
        dto: AddRecoveryEmailDto,
        email_service: &EmailService,
    ) -> Result<RecoveryEmail, ApiError> `
    └──  🔸 `add_recovery_email(
        pool: &DbPool,
        user_id: &str,
        dto: AddRecoveryEmailDto,
        email_service: &EmailService,
    ) -> Result<RecoveryEmail, ApiError> `
└── `RecoveryEmailService`
├──  🔧 `get_user_id_by_recovery_email(
        pool: &DbPool,
        email: &str,
    ) -> Result<String, ApiError> `
├──  🔧 `get_user_id_by_recovery_email(
        pool: &DbPool,
        email: &str,
    ) -> Result<String, ApiError> `
├──  🔧 `list_recovery_emails(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<RecoveryEmailResponse>, ApiError> `
├──  🔧 `list_recovery_emails(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<RecoveryEmailResponse>, ApiError> `
├──  🔧 `remove_recovery_email(
        pool: &DbPool,
        user_id: &str,
        email_id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `remove_recovery_email(
        pool: &DbPool,
        user_id: &str,
        email_id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `resend_verification_email(
        pool: &DbPool,
        user_id: &str,
        email_id: &str,
        email_service: &EmailService,
    ) -> Result<(), ApiError> `
├──  🔧 `resend_verification_email(
        pool: &DbPool,
        user_id: &str,
        email_id: &str,
        email_service: &EmailService,
    ) -> Result<(), ApiError> `
├──  🔧 `send_verification_email(
        email_service: &EmailService,
        recovery_email: &RecoveryEmail,
        token: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `send_verification_email(
        email_service: &EmailService,
        recovery_email: &RecoveryEmail,
        token: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `verify_recovery_email(
        pool: &DbPool,
        token: &str,
    ) -> Result<RecoveryEmail, ApiError> `
├──  🔧 `verify_recovery_email(
        pool: &DbPool,
        token: &str,
    ) -> Result<RecoveryEmail, ApiError> `

## refresh_token_service.rs

└── `RefreshTokenService`
    └──  🔸 `generate_auth_tokens(
        pool: &DbPool,
        user: &User,
        config: &Config,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<AuthResponse, ApiError> `
├──  🔧 `find_and_validate_refresh_token(
        pool: &DbPool,
        token_value: &str,
    ) -> Result<RefreshToken, ApiError> `
├──  🔧 `hash_token(token: &str) -> String `
├──  🔧 `parse_expiration(expiration: &str) -> Result<i64, ApiError> `
├──  🔧 `refresh_token(
        pool: &DbPool,
        refresh_dto: RefreshTokenDto,
        config: &Config,
    ) -> Result<AuthResponse, ApiError> `
├──  🔧 `revoke_all_user_refresh_tokens(pool: &DbPool, user_id: &str) -> Result<usize, ApiError> `
├──  🔧 `revoke_family(
        pool: &DbPool,
        user_id: &str,
        except_id: Option<&str>,
    ) -> Result<(), ApiError> `
├──  🔧 `revoke_refresh_token(pool: &DbPool, token_id: &str) -> Result<(), ApiError> `
├──  🔧 `save_refresh_token(pool: &DbPool, token: &RefreshToken) -> Result<(), ApiError> `

## security_question_service.rs

└── `SecurityQuestionService`
    ├──  🔸 `create_question(
        pool: &DbPool,
        dto: CreateSecurityQuestionDto,
    ) -> Result<SecurityQuestionResponse, ApiError> `
    ├──  🔸 `create_question(
        pool: &DbPool,
        dto: CreateSecurityQuestionDto,
    ) -> Result<SecurityQuestionResponse, ApiError> `
    ├──  🔸 `get_question_by_id(
        pool: &DbPool,
        id: &str,
    ) -> Result<SecurityQuestionResponse, ApiError> `
    └──  🔸 `get_question_by_id(
        pool: &DbPool,
        id: &str,
    ) -> Result<SecurityQuestionResponse, ApiError> `
└── `SecurityQuestionService`
├──  🔧 `add_user_answer(
        pool: &DbPool,
        user_id: &str,
        dto: CreateUserSecurityAnswerDto,
        salt_rounds: u32,
    ) -> Result<UserQuestionResponse, ApiError> `
├──  🔧 `add_user_answer(
        pool: &DbPool,
        user_id: &str,
        dto: CreateUserSecurityAnswerDto,
        salt_rounds: u32,
    ) -> Result<UserQuestionResponse, ApiError> `
├──  🔧 `delete_all_user_answers(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `delete_all_user_answers(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `delete_question(
        pool: &DbPool,
        id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `delete_question(
        pool: &DbPool,
        id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `delete_user_answer(
        pool: &DbPool,
        user_id: &str,
        answer_id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `delete_user_answer(
        pool: &DbPool,
        user_id: &str,
        answer_id: &str,
    ) -> Result<(), ApiError> `
├──  🔧 `list_questions(
        pool: &DbPool,
        page: u64,
        page_size: u64,
        only_active: bool,
    ) -> Result<(Vec<SecurityQuestionResponse>, u64), ApiError> `
├──  🔧 `list_questions(
        pool: &DbPool,
        page: u64,
        page_size: u64,
        only_active: bool,
    ) -> Result<(Vec<SecurityQuestionResponse>, u64), ApiError> `
├──  🔧 `list_user_answers(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<UserQuestionResponse>, ApiError> `
├──  🔧 `list_user_answers(
        pool: &DbPool,
        user_id: &str,
    ) -> Result<Vec<UserQuestionResponse>, ApiError> `
├──  🔧 `update_question(
        pool: &DbPool,
        id: &str,
        dto: UpdateSecurityQuestionDto,
    ) -> Result<SecurityQuestionResponse, ApiError> `
├──  🔧 `update_question(
        pool: &DbPool,
        id: &str,
        dto: UpdateSecurityQuestionDto,
    ) -> Result<SecurityQuestionResponse, ApiError> `
├──  🔧 `update_user_answer(
        pool: &DbPool,
        user_id: &str,
        answer_id: &str,
        new_answer: &str,
        salt_rounds: u32,
    ) -> Result<UserQuestionResponse, ApiError> `
├──  🔧 `update_user_answer(
        pool: &DbPool,
        user_id: &str,
        answer_id: &str,
        new_answer: &str,
        salt_rounds: u32,
    ) -> Result<UserQuestionResponse, ApiError> `
├──  🔧 `user_has_min_security_questions(
        pool: &DbPool,
        user_id: &str,
        min_count: usize,
    ) -> Result<bool, ApiError> `
├──  🔧 `user_has_min_security_questions(
        pool: &DbPool,
        user_id: &str,
        min_count: usize,
    ) -> Result<bool, ApiError> `
├──  🔧 `verify_multiple_answers(
        pool: &DbPool,
        user_id: &str,
        answers: &[(String, String)`
├──  🔧 `verify_multiple_answers(
        pool: &DbPool,
        user_id: &str,
        answers: &[(String, String)`
├──  🔧 `verify_user_answer(
        pool: &DbPool,
        user_id: &str,
        question_id: &str,
        answer: &str,
    ) -> Result<bool, ApiError> `
├──  🔧 `verify_user_answer(
        pool: &DbPool,
        user_id: &str,
        question_id: &str,
        answer: &str,
    ) -> Result<bool, ApiError> `

## token_service.rs

└── `TokenService`
    ├──  🔸 `generate_token(
        user_id: &str, 
        token_family: &str, 
        is_2fa_verified: bool,
        expiry_minutes: i64,
        secret: &str
    ) -> Result<(String, String), ApiError> `
    └──  🔸 `generate_token(
        user_id: &str, 
        token_family: &str, 
        is_2fa_verified: bool,
        expiry_minutes: i64,
        secret: &str
    ) -> Result<(String, String), ApiError> `
└── `TokenService`
├──  🔧 `blacklist_token(
        pool: &DbPool, 
        token_id: &str, 
        expiry: DateTime<Utc>
    ) -> Result<(), ApiError> `
├──  🔧 `blacklist_token(
        pool: &DbPool, 
        token_id: &str, 
        expiry: DateTime<Utc>
    ) -> Result<(), ApiError> `
├──  🔧 `clean_expired_tokens(pool: &DbPool) -> Result<usize, ApiError> `
├──  🔧 `clean_expired_tokens(pool: &DbPool) -> Result<usize, ApiError> `
├──  🔧 `is_token_blacklisted(pool: &DbPool, token_id: &str) -> Result<bool, ApiError> `
├──  🔧 `is_token_blacklisted(pool: &DbPool, token_id: &str) -> Result<bool, ApiError> `
├──  🔧 `rotate_token(
        pool: &DbPool,
        old_token: &str,
        secret: &str,
        expiry_minutes: i64,
        invalidate_family: bool
    ) -> Result<(String, String, String), ApiError> `
├──  🔧 `rotate_token(
        pool: &DbPool,
        old_token: &str,
        secret: &str,
        expiry_minutes: i64,
        invalidate_family: bool
    ) -> Result<(String, String, String), ApiError> `
├──  🔧 `validate_token(
        token: &str, 
        secret: &str,
        pool: &DbPool,
        require_2fa: bool
    ) -> Result<TokenClaims, ApiError> `
├──  🔧 `validate_token(
        token: &str, 
        secret: &str,
        pool: &DbPool,
        require_2fa: bool
    ) -> Result<TokenClaims, ApiError> `

## two_factor_service.rs

└── `TwoFactorService`
    ├──  🔸 `generate_setup(user: &User) -> Result<TwoFactorSetupResponse, ApiError> `
    └──  🔸 `generate_setup(user: &User) -> Result<TwoFactorSetupResponse, ApiError> `
└── `TwoFactorService`
├──  🔧 `disable_2fa(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `disable_2fa(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `enable_2fa(pool: &DbPool, user_id: &str, totp_code: &str, totp_secret: &str) -> Result<TwoFactorEnabledResponse, ApiError> `
├──  🔧 `enable_2fa(pool: &DbPool, user_id: &str, totp_code: &str, totp_secret: &str) -> Result<TwoFactorEnabledResponse, ApiError> `
├──  🔧 `generate_backup_codes() -> Vec<String> `
├──  🔧 `generate_backup_codes() -> Vec<String> `
├──  🔧 `regenerate_backup_codes(pool: &DbPool, user_id: &str) -> Result<Vec<String>, ApiError> `
├──  🔧 `regenerate_backup_codes(pool: &DbPool, user_id: &str) -> Result<Vec<String>, ApiError> `
├──  🔧 `verify_backup_code(pool: &DbPool, user_id: &str, backup_code: &str) -> Result<bool, ApiError> `
├──  🔧 `verify_backup_code(pool: &DbPool, user_id: &str, backup_code: &str) -> Result<bool, ApiError> `
├──  🔧 `verify_totp(secret: &str, code: &str) -> Result<bool, ApiError> `
├──  🔧 `verify_totp(secret: &str, code: &str) -> Result<bool, ApiError> `

## user_service.rs

└── `UserService`
    ├──  🔸 `create_user(
        pool: &DbPool,
        user_dto: CreateUserDto,
        salt_rounds: u32,
    ) -> Result<User, ApiError> `
    └──  🔸 `create_user(
        pool: &DbPool,
        user_dto: CreateUserDto,
        salt_rounds: u32,
    ) -> Result<User, ApiError> `
└── `UserService`
├──  🔧 `change_password(
        pool: &DbPool,
        user_id: &str,
        change_dto: ChangePasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> `
├──  🔧 `change_password(
        pool: &DbPool,
        user_id: &str,
        change_dto: ChangePasswordDto,
        salt_rounds: u32,
    ) -> Result<(), ApiError> `
├──  🔧 `clear_recovery_code(pool: Arc<DbPool>, user_id: &str) -> Result<(), ApiError> ` - Limpa (remove) o código de recuperação do usuário.
├──  🔧 `clear_recovery_code(pool: Arc<DbPool>, user_id: &str) -> Result<(), ApiError> ` - Limpa (remove) o código de recuperação do usuário.
├──  🔧 `delete_user(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `delete_user(pool: &DbPool, user_id: &str) -> Result<(), ApiError> `
├──  🔧 `generate_and_set_recovery_code(pool: Arc<DbPool>, user_id: &str) -> Result<String, ApiError> ` - Gera um novo código de recuperação persistente, faz o hash e o salva no banco.
├──  🔧 `generate_and_set_recovery_code(pool: Arc<DbPool>, user_id: &str) -> Result<String, ApiError> ` - Gera um novo código de recuperação persistente, faz o hash e o salva no banco.
├──  🔧 `get_user_by_email(pool: &DbPool, email: &str) -> Result<User, ApiError> `
├──  🔧 `get_user_by_email(pool: &DbPool, email: &str) -> Result<User, ApiError> `
├──  🔧 `get_user_by_email_or_username(pool: &DbPool, username_or_email: &str) -> Result<User, ApiError> `
├──  🔧 `get_user_by_email_or_username(pool: &DbPool, username_or_email: &str) -> Result<User, ApiError> `
├──  🔧 `get_user_by_id(pool: &DbPool, user_id: &str) -> Result<User, ApiError> `
├──  🔧 `get_user_by_id(pool: &DbPool, user_id: &str) -> Result<User, ApiError> `
├──  🔧 `list_users(pool: &DbPool, page: u64, page_size: u64) -> Result<(Vec<UserResponse>, u64), ApiError> `
├──  🔧 `list_users(pool: &DbPool, page: u64, page_size: u64) -> Result<(Vec<UserResponse>, u64), ApiError> `
├──  🔧 `map_row_to_user(row: &Row<'_>) -> SqlResult<User> `
├──  🔧 `map_row_to_user(row: &Row<'_>) -> SqlResult<User> `
├──  🔧 `update_password(
        pool: &DbPool,
        user_id: &str,
        new_password: &str,
        salt_rounds: u32,
    ) -> Result<(), ApiError> `
├──  🔧 `update_password(
        pool: &DbPool,
        user_id: &str,
        new_password: &str,
        salt_rounds: u32,
    ) -> Result<(), ApiError> `
├──  🔧 `update_user(pool: &DbPool, user_id: &str, update_dto: UpdateUserDto) -> Result<User, ApiError> `
├──  🔧 `update_user(pool: &DbPool, user_id: &str, update_dto: UpdateUserDto) -> Result<User, ApiError> `
├──  🔧 `verify_password(password: &str, password_hash: &str) -> Result<bool, ApiError> `
├──  🔧 `verify_password(password: &str, password_hash: &str) -> Result<bool, ApiError> `
├──  🔧 `verify_recovery_code(pool: Arc<DbPool>, user_id: &str, provided_code: &str) -> Result<bool, ApiError> ` - Verifica se o código de recuperação fornecido corresponde ao hash armazenado.
├──  🔧 `verify_recovery_code(pool: Arc<DbPool>, user_id: &str, provided_code: &str) -> Result<bool, ApiError> ` - Verifica se o código de recuperação fornecido corresponde ao hash armazenado.

## webauthn_service.rs

└── `WebauthnService`
    ├──  🔸 `list_credentials(user_id: &str) -> Vec<WebauthnCredential> `
    ├──  🔸 `list_credentials(user_id: &str) -> Vec<WebauthnCredential> `
    ├──  🔸 `register_credential(cred: WebauthnCredential)`
    └──  🔸 `register_credential(cred: WebauthnCredential)`
└── `WebauthnService`

## webhook_service.rs

└── `WebhookService`
    ├──  🔸 `register_webhook(cfg: WebhookConfig)`
    ├──  🔸 `register_webhook(cfg: WebhookConfig)`
    ├──  🔸 `remove_webhook(id: &str)`
    ├──  🔸 `remove_webhook(id: &str)`
    ├──  🔸 `trigger_event(event_type: &str, payload: &str)`
    └──  🔸 `trigger_event(event_type: &str, payload: &str)`
└── `WebhookService`
├──  🔧 `list_webhooks() -> Vec<WebhookConfig> `
├──  🔧 `list_webhooks() -> Vec<WebhookConfig> `
├──  🔧 `load_webhooks_from_file() -> Vec<WebhookConfig> `
├──  🔧 `load_webhooks_from_file() -> Vec<WebhookConfig> `
├──  🔧 `save_webhooks_to_file(hooks: &Vec<WebhookConfig>)`
├──  🔧 `save_webhooks_to_file(hooks: &Vec<WebhookConfig>)`

## jwt.rs

└── `JwtUtils` - Utilitários para JWT
    ├──  🔸 `verify(jwt_secret: &str, token: &str) -> Result<TokenClaims, ApiError> ` - Verifica um token JWT e retorna as claims
    └──  🔸 `verify(jwt_secret: &str, token: &str) -> Result<TokenClaims, ApiError> ` - Verifica um token JWT e retorna as claims
└── `JwtUtils` - Utilitários para JWT
├──  🔧 `extract_user_id(req: &HttpRequest) -> Result<String, ApiError> ` - Extrai o ID do usuário do token JWT na requisição
├──  🔧 `extract_user_id(req: &HttpRequest) -> Result<String, ApiError> ` - Extrai o ID do usuário do token JWT na requisição
├──  🔧 `is_admin(req: &HttpRequest) -> Result<bool, ApiError> ` - Verifica se o usuário é administrador
├──  🔧 `is_admin(req: &HttpRequest) -> Result<bool, ApiError> ` - Verifica se o usuário é administrador

## mod.rs


## password.rs

├──  🔧 `as_str(&self) -> &'static str `
├──  🔧 `as_str(&self) -> &'static str `
├──  🔧 `check_password_strength(password: &str) -> Result<(), Vec<String>> `
├──  🔧 `check_password_strength(password: &str) -> Result<(), Vec<String>> `
├──  🔧 `generate_random_password(length: usize) -> String `
├──  🔧 `generate_random_password(length: usize) -> String `
├──  🔧 `meets_requirements(&self) -> bool `
└──  🔧 `meets_requirements(&self) -> bool `

## password_argon2.rs

├──  🔧 `hash_password(password: &str) -> Result<String, String> ` - Gera um hash seguro de senha usando Argon2id (mais seguro que bcrypt)
├──  🔧 `hash_password(password: &str) -> Result<String, String> ` - Gera um hash seguro de senha usando Argon2id (mais seguro que bcrypt)
├──  🔧 `is_argon2_hash(hash: &str) -> bool ` - Verifica se um hash foi gerado com Argon2
├──  🔧 `is_argon2_hash(hash: &str) -> bool ` - Verifica se um hash foi gerado com Argon2
├──  🔧 `verify_password(password: &str, hash: &str) -> Result<bool, String> ` - Verifica se uma senha corresponde ao hash armazenado
└──  🔧 `verify_password(password: &str, hash: &str) -> Result<bool, String> ` - Verifica se uma senha corresponde ao hash armazenado

## tracing.rs

├──  🔧 `init_tracing() -> Result<(), String> ` - Configura o sistema de logging estruturado com tracing
├──  🔧 `init_tracing() -> Result<(), String> ` - Configura o sistema de logging estruturado com tracing
├──  🔧 `log_startup_info()` - Registra informações sobre o ambiente de execução
└──  🔧 `log_startup_info()` - Registra informações sobre o ambiente de execução

## validator.rs

├──  🔧 `validate_dto(&self) -> Result<(), ApiError> `
└──  🔧 `validate_dto(&self) -> Result<(), ApiError> `

