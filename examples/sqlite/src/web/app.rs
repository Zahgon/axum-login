use actix_login::{
    actix_session::{
        config::{PersistentSession, TtlExtensionPolicy},
        SessionMiddleware,
    },
    require::{RedirectHandler, Require},
    AuthManagerLayerBuilder,
};
use actix_web::{
    cookie::{time::Duration, Key, SameSite},
    error::{InternalError, UrlencodedError},
    http::StatusCode,
    web, App as ActixApp, HttpServer,
};
use actix_web_flash_messages::FlashMessagesFramework;
use sqlx::SqlitePool;

use crate::{
    users::Backend,
    web::{
        auth, protected,
        sessions::{SessionMessageStore, SqliteStore},
    },
};

pub struct App {
    db: SqlitePool,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let db = SqlitePool::connect(":memory:").await?;
        sqlx::migrate!().run(&db).await?;

        Ok(Self { db })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        // Session store.
        //
        // This uses `actix-session` to establish middleware that will provide
        // the session as a request extension.
        let session_store = SqliteStore::new(self.db.clone());
        session_store.migrate().await?;

        let deletion_task = tokio::task::spawn(
            session_store
                .clone()
                .continuously_delete_expired(std::time::Duration::from_secs(60)),
        );

        // Generate a cryptographic key to sign the session cookie.
        let key = Key::generate();

        let backend = Backend::new(self.db);

        let server = HttpServer::new(move || {
            let session_middleware = SessionMiddleware::builder(session_store.clone(), key.clone())
                .cookie_secure(false)
                // `tower-sessions` defaulted to `Strict`; `actix-session`
                // defaults to `Lax`, so pin it to keep the original policy.
                .cookie_same_site(SameSite::Strict)
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(Duration::days(1))
                        .session_ttl_extension_policy(TtlExtensionPolicy::OnEveryRequest),
                )
                .build();

            // Auth service.
            //
            // This combines the session middleware with our backend to
            // establish the auth service which will provide the auth session as
            // a request extension.
            let auth_layer =
                AuthManagerLayerBuilder::new(backend.clone(), session_middleware).build();

            // Flash messages are kept in the session, so they ride along on
            // the session cookie rather than needing one of their own.
            let message_framework =
                FlashMessagesFramework::builder(SessionMessageStore::default()).build();

            let require_login = Require::<Backend>::builder()
                .unauthenticated(RedirectHandler::new().login_url("/login"))
                .build();

            // The auth layer is registered last so that it is the outermost
            // middleware: sessions must be established before anything else
            // runs.
            ActixApp::new()
                .app_data(form_config())
                .wrap(message_framework)
                .wrap(auth_layer)
                .configure(auth::configure)
                .service(protected::resource().wrap(require_login))
        })
        .bind(("0.0.0.0", 3000))?
        .run();

        // Actix Web installs its own `SIGINT`/`SIGTERM` handlers and shuts the
        // server down gracefully, so we only need to stop the deletion task
        // once the server has returned.
        server.await?;

        deletion_task.abort();
        match deletion_task.await {
            Ok(result) => result?,
            Err(err) if err.is_cancelled() => {}
            Err(err) => return Err(err.into()),
        }

        Ok(())
    }
}

/// Configuration for the `Form` extractor, keeping axum's rejection statuses.
///
/// Axum answered a form body it could not deserialize with 422 Unprocessable
/// Entity; actix-web answers 400 Bad Request. Map the body-level rejections
/// back so the wire contract is unchanged. The content-type, length and size
/// rejections already agree on both sides and keep their actix-web statuses.
fn form_config() -> web::FormConfig {
    web::FormConfig::default().error_handler(|err, _| {
        let status = match err {
            UrlencodedError::Overflow { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            UrlencodedError::UnknownLength => StatusCode::LENGTH_REQUIRED,
            UrlencodedError::ContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        };

        InternalError::new(err, status).into()
    })
}
