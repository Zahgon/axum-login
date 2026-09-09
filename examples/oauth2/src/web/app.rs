use std::env;

use actix_login::{
    actix_session::{
        config::{PersistentSession, TtlExtensionPolicy},
        SessionMiddleware,
    },
    require::{RedirectHandler, Require},
    AuthManagerLayerBuilder, MemoryStore,
};
use actix_web::{
    cookie::{time::Duration, Key, SameSite},
    error::{InternalError, UrlencodedError},
    http::StatusCode,
    web, App as ActixApp, HttpServer,
};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, TokenUrl};
use sqlx::SqlitePool;

use crate::{
    users::{Backend, BasicClientSet},
    web::{auth, oauth, protected},
};

pub struct App {
    db: SqlitePool,
    client: BasicClientSet,
}

impl App {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        dotenvy::dotenv()?;

        let client_id = env::var("CLIENT_ID")
            .map(ClientId::new)
            .expect("CLIENT_ID should be provided.");
        let client_secret = env::var("CLIENT_SECRET")
            .map(ClientSecret::new)
            .expect("CLIENT_SECRET should be provided");

        let auth_url = AuthUrl::new("https://github.com/login/oauth/authorize".to_string())?;
        let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())?;
        let client = BasicClient::new(client_id)
            .set_client_secret(client_secret)
            .set_auth_uri(auth_url)
            .set_token_uri(token_url);

        let db = SqlitePool::connect(":memory:").await?;
        sqlx::migrate!().run(&db).await?;

        Ok(Self { db, client })
    }

    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error>> {
        // Generate a cryptographic key to sign the session cookie.
        let key = Key::generate();

        let backend = Backend::new(self.db, self.client);

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
                // Ensure we send the cookie from the OAuth redirect.
                .cookie_same_site(SameSite::Lax)
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

            let require_login = Require::<Backend>::builder()
                .unauthenticated(RedirectHandler::new().login_url("/login"))
                .build();

            ActixApp::new()
                .app_data(form_config())
                .wrap(auth_layer)
                .configure(auth::configure)
                .configure(oauth::configure)
                .service(protected::resource().wrap(require_login))
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
