use crate::errors::ApiError;
use crate::models::user::User;
use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use tracing::info; // Usar tracing em vez de log

#[derive(Clone)]
pub struct EmailService {
    smtp_server: String,
    smtp_port: u16,
    username: String,
    password: String,
    from: String,
    from_name: String,
    base_url: String,
    enabled: bool,
}

impl EmailService {
    // Retorna se o serviço de email está habilitado
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    // Retorna a URL base
    pub fn get_base_url(&self) -> &str {
        &self.base_url
    }
    
    pub fn new(
        smtp_server: String,
        smtp_port: u16,
        username: String,
        password: String,
        from: String,
        from_name: String,
        base_url: String,
        enabled: bool,
    ) -> Self {
        Self {
            smtp_server,
            smtp_port,
            username,
            password,
            from,
            from_name,
            base_url,
            enabled,
        }
    }

    // Envia um email para recuperação de senha
    // Envia um email para recuperação de senha
    pub async fn send_password_reset_email(&self, user: &User, token: &str) -> Result<(), ApiError> {
        // Verifica se o serviço de email está habilitado
        if !self.enabled {
            info!("🔕 Serviço de email desabilitado. Email de recuperação de senha não enviado para: {}", user.email);
            return Ok(());
        }

        let reset_link = format!("{}/reset-password?token={}", self.base_url, token);

        let html_body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Recuperação de Senha</title>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }}
                    .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    .header {{ background-color: #4a86e8; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }}
                    .content {{ padding: 20px; }}
                    .button {{ display: inline-block; background-color: #4a86e8; color: white !important; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ font-size: 12px; color: #777; text-align: center; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h2>Recuperação de Senha</h2></div>
                    <div class="content">
                        <p>Olá, <strong>{name}</strong>!</p>
                        <p>Recebemos uma solicitação para redefinir sua senha. Se você não fez essa solicitação, por favor ignore este email.</p>
                        <p>Para redefinir sua senha, clique no botão abaixo:</p>
                        <p style="text-align: center;"><a href="{reset_link}" class="button">Redefinir Senha</a></p>
                        <p>Ou copie e cole o link abaixo no seu navegador:</p>
                        <p>{reset_link}</p>
                        <p>Este link expirará em 1 hora.</p>
                        <p>Atenciosamente,<br>Equipe de Suporte</p>
                    </div>
                    <div class="footer"><p>Este é um email automático, por favor não responda.</p></div>
                </div>
            </body>
            </html>
            "#,
            name = user.full_name(),
            reset_link = reset_link
        );

        let text_body = format!(
            r#"
            Recuperação de Senha

            Olá, {}!

            Recebemos uma solicitação para redefinir sua senha. Se você não fez essa solicitação, por favor ignore este email.

            Para redefinir sua senha, acesse o link abaixo:

            {}

            Este link expirará em 1 hora.

            Atenciosamente,
            Equipe de Suporte

            Este é um email automático, por favor não responda.
            "#,
            user.full_name(),
            reset_link
        );

        self.send_email(
            &user.email,
            "Recuperação de Senha",
            &text_body,
            &html_body,
        ).await // Adicionar await
    }

    // Envia um email de boas-vindas
    // Envia um email de boas-vindas
    pub async fn send_welcome_email(&self, user: &User) -> Result<(), ApiError> {
        // Verifica se o serviço de email está habilitado
        if !self.enabled {
            info!("🔕 Serviço de email desabilitado. Email de boas-vindas não enviado para: {}", user.email);
            return Ok(());
        }

        let login_link = format!("{}/login", self.base_url);

        let html_body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Bem-vindo(a)!</title>
                 <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }}
                    .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    .header {{ background-color: #4a86e8; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }}
                    .content {{ padding: 20px; }}
                    .button {{ display: inline-block; background-color: #4a86e8; color: white !important; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ font-size: 12px; color: #777; text-align: center; margin-top: 20px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h2>Bem-vindo(a) ao nosso serviço!</h2></div>
                    <div class="content">
                        <p>Olá, <strong>{name}</strong>!</p>
                        <p>Obrigado por se cadastrar em nosso serviço. Estamos muito felizes em tê-lo(a) conosco!</p>
                        <p>Seu cadastro foi realizado com sucesso e você já pode acessar sua conta:</p>
                        <p style="text-align: center;"><a href="{login_link}" class="button">Acessar minha conta</a></p>
                        <p>Se você tiver alguma dúvida ou precisar de ajuda, não hesite em nos contatar.</p>
                        <p>Atenciosamente,<br>Equipe de Suporte</p>
                    </div>
                    <div class="footer"><p>Este é um email automático, por favor não responda.</p></div>
                </div>
            </body>
            </html>
            "#,
            name = user.full_name(),
            login_link = login_link
        );

        let text_body = format!(
            r#"
            Bem-vindo(a) ao nosso serviço!

            Olá, {}!

            Obrigado por se cadastrar em nosso serviço. Estamos muito felizes em tê-lo(a) conosco!

            Seu cadastro foi realizado com sucesso e você já pode acessar sua conta:

            {}

            Se você tiver alguma dúvida ou precisar de ajuda, não hesite em nos contatar.

            Atenciosamente,
            Equipe de Suporte

            Este é um email automático, por favor não responda.
            "#,
            user.full_name(),
            login_link
        );

        self.send_email(
            &user.email,
            "Bem-vindo(a) ao nosso serviço!",
            &text_body,
            &html_body,
        ).await // Adicionar await
    }

    // Envia um email para desbloqueio de conta
    // Envia um email para desbloqueio de conta
    pub async fn send_account_unlock_email(&self, user: &User, token: &str) -> Result<(), ApiError> {
        // Verifica se o serviço de email está habilitado
        if !self.enabled {
            info!("🔕 Serviço de email desabilitado. Email de desbloqueio não enviado para: {}", user.email);
            return Ok(());
        }

        // Link para a página/endpoint de desbloqueio (precisa ser criado no frontend/API)
        let unlock_link = format!("{}/unlock-account?token={}", self.base_url, token);

        let html_body = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Conta Bloqueada Temporariamente</title>
                 <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }}
                    .container {{ padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    .header {{ background-color: #f4b400; color: white; padding: 10px; text-align: center; border-radius: 5px 5px 0 0; }} /* Cor diferente para alerta */
                    .content {{ padding: 20px; }}
                    .button {{ display: inline-block; background-color: #f4b400; color: white !important; text-decoration: none; padding: 10px 20px; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ font-size: 12px; color: #777; text-align: center; margin-top: 20px; }}
                    .token-code {{ background-color: #f0f0f0; padding: 5px 10px; border-radius: 3px; font-family: monospace; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header"><h2>Conta Bloqueada Temporariamente</h2></div>
                    <div class="content">
                        <p>Olá, <strong>{name}</strong>!</p>
                        <p>Detectamos múltiplas tentativas de login malsucedidas em sua conta. Por segurança, sua conta foi temporariamente bloqueada.</p>
                        <p>Para desbloquear sua conta imediatamente, use o código abaixo ou clique no botão:</p>
                        <p>Seu código de desbloqueio: <strong class="token-code">{token}</strong></p>
                        <p style="text-align: center;"><a href="{unlock_link}" class="button">Desbloquear Minha Conta</a></p>
                        <p>Ou copie e cole o link abaixo no seu navegador:</p>
                        <p>{unlock_link}</p>
                        <p>Este código/link expirará em breve. Se você não solicitou isso ou acredita que foi um erro, entre em contato com o suporte.</p>
                        <p>Atenciosamente,<br>Equipe de Segurança</p>
                    </div>
                    <div class="footer"><p>Este é um email automático, por favor não responda.</p></div>
                </div>
            </body>
            </html>
            "#,
            name = user.full_name(),
            token = token,
            unlock_link = unlock_link
        );

        let text_body = format!(
            r#"
            Conta Bloqueada Temporariamente

            Olá, {}!

            Detectamos múltiplas tentativas de login malsucedidas em sua conta. Por segurança, sua conta foi temporariamente bloqueada.

            Para desbloquear sua conta imediatamente, use o código abaixo ou acesse o link:

            Código de Desbloqueio: {}

            Link de Desbloqueio: {}

            Este código/link expirará em breve. Se você não solicitou isso ou acredita que foi um erro, entre em contato com o suporte.

            Atenciosamente,
            Equipe de Segurança

            Este é um email automático, por favor não responda.
            "#,
            user.full_name(),
            token,
            unlock_link
        );

        self.send_email(
            &user.email,
            "Sua conta foi temporariamente bloqueada",
            &text_body,
            &html_body,
        ).await // Adicionar await
    }


    // Método genérico para envio de emails
    // Método genérico para envio de emails
    pub async fn send_email(
        &self,
        to: &str,
        subject: &str,
        text_body: &str,
        html_body: &str,
    ) -> Result<(), ApiError> {
        // Verifica se o serviço de email está habilitado
        if !self.enabled {
            info!("🔕 Serviço de email desabilitado. Email não enviado para: {}", to);
            return Ok(());
        }

        // Cria a mensagem
        let to_address = to.parse().map_err(|e| ApiError::EmailError(format!("Endereço 'To' inválido: {}", e)))?;
        let from_address = format!("{} <{}>", self.from_name, self.from).parse().map_err(|e| ApiError::EmailError(format!("Endereço 'From' inválido: {}", e)))?;
        let email_subject = subject.to_string();
        let email_text_body = text_body.to_string();
        let email_html_body = html_body.to_string();

        let email = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject(email_subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(email_text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(email_html_body),
                    ),
            )?;

        // Cria o transportador SMTP
        let smtp_server = self.smtp_server.clone();
        let smtp_port = self.smtp_port;
        let username = self.username.clone();
        let password = self.password.clone();
        let to_log = to.to_string(); // Clonar 'to' para o log

        // Executar a operação de envio bloqueante em uma thread separada
        let send_result = actix_web::web::block(move || -> Result<lettre::transport::smtp::response::Response, ApiError> { // Corrigir o caminho do tipo Response
            let creds = Credentials::new(username, password);

            // Constrói o mailer, convertendo erros para ApiError
            let mailer = SmtpTransport::relay(&smtp_server)
                .map_err(|e| ApiError::EmailError(format!("Falha ao criar relay SMTP: {}", e)))? // Este ? agora funciona pois a closure retorna Result<_, ApiError>
                .credentials(creds)
                .port(smtp_port)
                .build();

            // Envia o email, convertendo o erro SMTP específico para ApiError
            mailer.send(&email)
                  .map_err(|e| ApiError::EmailError(format!("Erro ao enviar email: {}", e)))
        }).await; // Await o resultado do web::block

        // Trata o resultado do web::block e da operação interna
        match send_result {
            Ok(Ok(_response)) => { // Sucesso interno e externo
                info!("📧 Email enviado com sucesso para: {}", to_log);
                Ok(())
            }
            Ok(Err(api_error)) => { // Erro na operação interna (já é ApiError)
                 Err(api_error)
            }
            Err(blocking_error) => { // Erro no web::block
                 Err(ApiError::from(blocking_error))
            }
        }
    }
}
