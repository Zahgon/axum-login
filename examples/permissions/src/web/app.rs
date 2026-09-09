use actix_login::{
    actix_session::{
        config::{PersistentSession, TtlExtensionPolicy},
        SessionMiddleware,
    },
    require::{PermissionsPredicate, RedirectHandler, Require, SimpleResponseHandler},
    AuthManagerLayerBuilder, MemoryStore,
};
use actix_web::{
    cookie::{time::Duration, Key, SameSite},
    error::{InternalError, UrlencodedError},
    http::StatusCode,
    web, App as ActixApp, HttpServer,
};
use sqlx::SqlitePool;

use crate::{
    users::Backend,
    web::{auth, protected, restricted},
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
        // Generate a cryptographic key to sign the session cookie.
        let key = Key::generate();

        let backend = Backend::new(self.db);

        // Session store.
        //
        // Built outside the factory below so that every worker thread
        // shares the same sessions.
        let session_store = MemoryStore::default();

        HttpServer::new(move || {
            // Session middleware.
            //
            // This uses `actix-session` to establish middleware that will
            // provide the session as a request extension.
            let session_middleware = SessionMiddleware::builder(session_store.clone(), key.clone())
                .cookie_secure(false)
                // `tower-sessions` defaulted to `Strict`; `actix-session`
                // defaults to `Lax`, so pin it to keep the original policy.
                .cookie_same_site(SameSite::Strict)
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(Duration::days(1))
                        .session_ttl_extension_policy(TtlExtensionPolicy::OnStateChanges),
                )
                .build();

            // Auth service.
            //
            // This combines the session middleware with our backend to
            // establish the auth service which will provide the auth session as
            // a request extension.
            let auth_layer =
                AuthManagerLayerBuilder::new(backend.clone(), session_middleware).build();

            let unauthorized_handler =
                SimpleResponseHandler::text(StatusCode::FORBIDDEN, "Forbidden");

            let restricted_require = Require::<Backend>::builder()
                .decision(PermissionsPredicate::new().with_permissions(["restricted.read"]))
                .unauthenticated(RedirectHandler::new().login_url("/login"))
                .unauthorized(unauthorized_handler.clone())
                .build();

            let protected_require = Require::<Backend>::builder()
                .decision(PermissionsPredicate::new().with_permissions(["protected.read"]))
                .unauthenticated(RedirectHandler::new().login_url("/login"))
                .unauthorized(unauthorized_handler)
                .build();

            ActixApp::new()
                .app_data(form_config())
                .wrap(auth_layer)
                .configure(auth::configure)
                .service(restricted::resource().wrap(restricted_require))
                .service(protected::resource().wrap(protected_require))
        })
        .bind(("0.0.0.0", 3000))?
        .run()
        .await?;

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
