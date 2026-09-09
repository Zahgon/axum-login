//! Authentication requirement middleware for Actix Web.
//!
//! This module provides the [`Require`] type, which acts as a configurable
//! middleware for enforcing authentication and access control in Actix Web
//! applications. It uses a customizable decision predicate with configurable
//! unauthenticated and unauthorized handlers to control access to routes based
//! on authentication.
//! ## Overview
//!
//! ```rust,no_run
//! # use std::collections::HashMap;
//! #
//! # use actix_login::{AuthUser, AuthnBackend, UserId};
//! #
//! # #[derive(Debug, Clone)]
//! # struct User {
//! #     id: i64,
//! #     pw_hash: Vec<u8>,
//! # }
//! #
//! # impl AuthUser for User {
//! #     type Id = i64;
//! #
//! #     fn id(&self) -> Self::Id {
//! #         self.id
//! #     }
//! #
//! #     fn session_auth_hash(&self) -> &[u8] {
//! #         &self.pw_hash
//! #     }
//! # }
//! #
//! # #[derive(Clone, Default)]
//! # struct Backend {
//! #     users: HashMap<i64, User>,
//! # }
//! #
//! # #[derive(Clone)]
//! # struct Credentials {
//! #     user_id: i64,
//! # }
//! #
//! # impl AuthnBackend for Backend {
//! #     type User = User;
//! #     type Credentials = Credentials;
//! #     type Error = std::convert::Infallible;
//! #
//! #     async fn authenticate(
//! #         &self,
//! #         Credentials { user_id }: Self::Credentials,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(&user_id).cloned())
//! #     }
//! #
//! #     async fn get_user(
//! #         &self,
//! #         user_id: &UserId<Self>,
//! #     ) -> Result<Option<Self::User>, Self::Error> {
//! #         Ok(self.users.get(user_id).cloned())
//! #     }
//! # }
//! use actix_login::{
//!     require::{RedirectHandler, Require},
//!     AuthManagerLayerBuilder,
//! };
//! use actix_session::{storage::CookieSessionStore, SessionMiddleware};
//! use actix_web::{cookie::Key, web, App, HttpResponse, HttpServer};
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // Signing key for the session cookie.
//!     let key = Key::generate();
//!
//!     HttpServer::new(move || {
//!         // Session middleware.
//!         let session_middleware =
//!             SessionMiddleware::new(CookieSessionStore::default(), key.clone());
//!
//!         // Auth service.
//!         let backend = Backend::default();
//!         let auth_layer = AuthManagerLayerBuilder::new(backend, session_middleware).build();
//!
//!         // Permission control middleware.
//!         let require = Require::<Backend>::builder()
//!             .unauthenticated(RedirectHandler::new().login_url("/login"))
//!             .build();
//!
//!         App::new()
//!             .wrap(auth_layer)
//!             .service(
//!                 web::resource("/protected")
//!                     .wrap(require)
//!                     .route(web::get().to(HttpResponse::Ok)),
//!             )
//!             .service(
//!                 web::resource("/login")
//!                     .route(web::get().to(HttpResponse::Ok))
//!                     .route(web::post().to(HttpResponse::Ok)),
//!             )
//!     })
//!     .bind(("0.0.0.0", 3000))?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ## Common patterns
//!
//! Require a permission and redirect unauthenticated users to `/login`:
//!
//! ```rust,no_run
//! use actix_login::{
//!     require::{PermissionsPredicate, RedirectHandler, Require},
//!     AuthUser, AuthnBackend, AuthzBackend, UserId,
//! };
//!
//! #[derive(Clone, Debug)]
//! struct User;
//!
//! impl AuthUser for User {
//!     type Id = i64;
//!
//!     fn id(&self) -> Self::Id {
//!         0
//!     }
//!
//!     fn session_auth_hash(&self) -> &[u8] {
//!         &[]
//!     }
//! }
//!
//! #[derive(Clone, Debug, Eq, PartialEq, Hash)]
//! struct Permission(&'static str);
//!
//! #[derive(Clone)]
//! struct Backend;
//!
//! impl AuthnBackend for Backend {
//!     type User = User;
//!     type Credentials = ();
//!     type Error = std::convert::Infallible;
//!
//!     async fn authenticate(
//!         &self,
//!         _: Self::Credentials,
//!     ) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//!
//!     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//! }
//!
//! impl AuthzBackend for Backend {
//!     type Permission = Permission;
//! }
//!
//! let predicate =
//!     PermissionsPredicate::<Backend>::new().with_permissions([Permission("admin.read")]);
//!
//! let require = Require::<Backend>::builder()
//!     .decision(predicate)
//!     .unauthenticated(RedirectHandler::new().login_url("/login"))
//!     .build();
//! ```
//!
//! Use shared state in a decision predicate:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use actix_login::{
//!     require::{Decision, Require},
//!     AuthSession, AuthUser, AuthnBackend, UserId,
//! };
//!
//! #[derive(Clone, Debug)]
//! struct User;
//!
//! impl AuthUser for User {
//!     type Id = i64;
//!
//!     fn id(&self) -> Self::Id {
//!         0
//!     }
//!
//!     fn session_auth_hash(&self) -> &[u8] {
//!         &[]
//!     }
//! }
//!
//! #[derive(Clone)]
//! struct Backend;
//!
//! impl AuthnBackend for Backend {
//!     type User = User;
//!     type Credentials = ();
//!     type Error = std::convert::Infallible;
//!
//!     async fn authenticate(
//!         &self,
//!         _: Self::Credentials,
//!     ) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//!
//!     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
//!         Ok(Some(User))
//!     }
//! }
//!
//! #[derive(Clone)]
//! struct AppState {
//!     allow: bool,
//! }
//!
//! let state = AppState { allow: true };
//! let require = Require::<Backend, AppState>::builder_with_state(state)
//!     .decision(
//!         |auth_session: AuthSession<Backend>, state: Arc<AppState>| async move {
//!             if auth_session.user().await.is_none() {
//!                 return Decision::Unauthenticated;
//!             }
//!
//!             if state.allow {
//!                 Decision::Allow
//!             } else {
//!                 Decision::Unauthorized
//!             }
//!         },
//!     )
//!     .build();
//! ```
mod builder;
mod handler;
mod predicate;
mod service;

use std::{
    future::{ready, Future, Ready},
    pin::Pin,
    rc::Rc,
    sync::Arc,
};

use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
};

pub use self::{
    builder::RequireBuilder,
    handler::{
        DefaultUnauthenticated, DefaultUnauthorized, RedirectHandler, ResponseHandler,
        SimpleResponseHandler,
    },
    predicate::{
        Decision, DecisionPredicate, DefaultAccess, PermissionMatch, PermissionsPredicate,
    },
    service::RequireService,
};
use crate::AuthnBackend;

/// A Future in a Box.
///
/// Actix Web handles a request on the worker thread that accepted it, so the
/// futures this crate produces are not required to be `Send`.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A type alias for the default [`Require`] configuration.
pub type RequireLayer<B, ST = ()> = Require<B, ST>;

/// A type alias for the default [`RequireBuilder`] configuration.
pub type RequireBuilderLayer<B, ST = ()> = RequireBuilder<B, ST>;

/// A configurable authentication and access control middleware.
///
/// The [`Require`] struct serves as the core component of the authentication
/// middleware. It determines whether a request is allowed and applies
/// unauthorized or unauthenticated logic when access is denied.
///
/// This type is typically constructed using the [`Require::builder`] or
/// [`Require::builder_with_state`] methods and applied with
/// [`App::wrap`](actix_web::App::wrap),
/// [`Scope::wrap`](actix_web::Scope::wrap), or
/// [`Resource::wrap`](actix_web::Resource::wrap).
///
/// Decision predicates and handlers are stored behind `Arc` to keep the public
/// type stable and reduce generic noise.
///
/// # Type Parameters
/// - `B`: The authentication backend implementing [`AuthnBackend`].
/// - `ST`: Shared state used by predicates or handlers.
///
/// For most use cases, prefer [`RequireLayer`] and [`RequireBuilderLayer`] to
/// avoid explicit generic parameters.
#[must_use]
pub struct Require<B, ST = ()>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    pub(crate) inner: Arc<RequireState<B, ST>>,
}

pub(crate) struct RequireState<B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    /// The predicate that determines if access should be granted.
    pub(crate) decision: Arc<dyn DecisionPredicate<B, ST>>,
    /// The response for authenticated but unauthorized requests.
    pub(crate) unauthorized: Arc<dyn ResponseHandler>,
    /// The response for unauthenticated requests.
    pub(crate) unauthenticated: Arc<dyn ResponseHandler>,
    /// Arbitrary user state available to the predicate.
    pub(crate) state: Arc<ST>,
}

impl<B, ST> Require<B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    /// Creates a new [`Require`] instance with the specified decision,
    /// unauthorized, unauthenticated, and state.
    pub fn new<Pr, Un, Uh>(decision: Pr, unauthorized: Un, unauthenticated: Uh, state: ST) -> Self
    where
        Pr: DecisionPredicate<B, ST> + 'static,
        Un: ResponseHandler + 'static,
        Uh: ResponseHandler + 'static,
    {
        let inner = RequireState {
            decision: Arc::new(decision),
            unauthorized: Arc::new(unauthorized),
            unauthenticated: Arc::new(unauthenticated),
            state: Arc::new(state),
        };
        Self {
            inner: Arc::new(inner),
        }
    }
}

impl<B, ST> std::fmt::Debug for Require<B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Require")
            .field("decision", &"DecisionPredicate")
            .field("unauthorized", &"ResponseHandler")
            .field("unauthenticated", &"ResponseHandler")
            .field("state", &"Arc<ST>")
            .finish()
    }
}

impl<B, ST> Clone for Require<B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<B> Require<B, ()>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    /// Returns a builder for constructing a [`Require`] middleware with an
    /// empty state.
    #[inline]
    pub fn builder() -> RequireBuilder<B, ()> {
        RequireBuilder::new()
    }
}

impl<B, ST> Require<B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    /// Returns a builder for constructing a [`Require`] middleware with custom
    /// shared state.
    #[inline]
    pub fn builder_with_state(state: ST) -> RequireBuilder<B, ST> {
        RequireBuilder::new_with_state(state)
    }
}

impl<S, Body, B, ST> Transform<S, ServiceRequest> for Require<B, ST>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = actix_web::Error>
        + 'static,
    Body: MessageBody + 'static,
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    type Response = ServiceResponse<EitherBody<Body>>;
    type Error = actix_web::Error;
    type Transform = RequireService<S, B, ST>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    #[doc(hidden)]
    /// Wraps the given service with the [`Require`] authentication middleware.
    fn new_transform(&self, inner: S) -> Self::Future {
        ready(Ok(RequireService {
            inner: Rc::new(inner),
            layer: self.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc};

    use actix_session::{storage::CookieSessionStore, SessionMiddleware};
    use actix_web::{
        body::MessageBody,
        cookie::{Cookie, Key},
        dev::ServiceResponse,
        http::{header, StatusCode},
        test, web, App, HttpResponse,
    };

    use crate::{
        require::{
            builder::RequireBuilder,
            handler::{RedirectHandler, SimpleResponseHandler},
            predicate::PermissionsPredicate,
            Decision, PermissionMatch, Require,
        },
        AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend,
    };

    /// Builds the auth middleware used by these tests.
    ///
    /// Session state is kept in a signed cookie, which keeps the tests free of
    /// external services while exercising the full session round trip.
    fn auth_layer() -> AuthManagerLayerBuilder<TestBackend, CookieSessionStore> {
        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), Key::generate())
                .cookie_secure(false)
                .build();

        AuthManagerLayerBuilder::new(TestBackend, session_middleware)
    }

    #[derive(Clone)]
    struct TestState {
        req_perm: Vec<TestPermission>,
    }

    async fn verify_permissions(
        auth_session: AuthSession<TestBackend>,
        state: Arc<TestState>,
    ) -> Decision {
        let req_perms = &state.req_perm;
        let Some(user) = auth_session.user().await else {
            return Decision::Unauthenticated;
        };
        let Ok(u_perms) = auth_session.backend().get_user_permissions(&user).await else {
            return Decision::Unauthorized;
        };

        if req_perms.iter().any(|perm| u_perms.contains(perm)) {
            Decision::Allow
        } else {
            Decision::Unauthorized
        }
    }

    #[derive(Debug, Clone)]
    struct User;

    impl AuthUser for User {
        type Id = i64;

        fn id(&self) -> Self::Id {
            0
        }

        fn session_auth_hash(&self) -> &[u8] {
            &[]
        }
    }

    #[derive(Debug, Clone)]
    struct Credentials;

    #[derive(thiserror::Error, Debug)]
    struct Error;

    impl std::fmt::Display for Error {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestBackend;

    impl AuthnBackend for TestBackend {
        type User = User;
        type Credentials = Credentials;
        type Error = Error;

        async fn authenticate(
            &self,
            _: Self::Credentials,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }

        async fn get_user(
            &self,
            _: &<<TestBackend as AuthnBackend>::User as AuthUser>::Id,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct TestPermission {
        pub name: String,
    }

    impl From<&str> for TestPermission {
        fn from(name: &str) -> Self {
            TestPermission {
                name: name.to_string(),
            }
        }
    }

    impl AuthzBackend for TestBackend {
        type Permission = TestPermission;

        async fn get_user_permissions(
            &self,
            _user: &Self::User,
        ) -> Result<HashSet<Self::Permission>, Self::Error> {
            let perms: HashSet<Self::Permission> =
                HashSet::from_iter(["test.read".into(), "test.write".into()]);
            Ok(perms)
        }
    }

    /// The handler used for the login route in these tests; logging in
    /// establishes the session the protected routes then require.
    async fn login(auth_session: AuthSession<TestBackend>) -> HttpResponse {
        auth_session.login(&User).await.unwrap();
        HttpResponse::Ok().finish()
    }

    fn get_session_cookie<B>(res: &ServiceResponse<B>) -> Option<Cookie<'static>> {
        res.response()
            .cookies()
            .find(|cookie| cookie.name() == "id")
            .map(|cookie| cookie.into_owned())
    }

    fn location<B>(res: &ServiceResponse<B>) -> Option<&str> {
        res.headers()
            .get(header::LOCATION)
            .and_then(|h| h.to_str().ok())
    }

    // Classic Tests (no state)
    #[actix_web::test]
    async fn test_login_required() {
        let require_login = RequireBuilder::<TestBackend>::new().build();
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require_login)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[cfg(feature = "macros-middleware")]
    mod parity {
        use super::*;
        use crate::{login_required, permission_required};

        /// Runs the same request against a builder-configured app and a
        /// macro-configured app, returning both responses.
        macro_rules! compare {
            ($builder_layer:expr, $macro_layer:expr, $uri:expr, login = $login:expr) => {{
                let app_builder = test::init_service(
                    App::new()
                        .wrap(auth_layer().build())
                        .service(web::resource("/login").route(web::get().to(login)))
                        .service(
                            web::resource("/")
                                .wrap($builder_layer)
                                .route(web::get().to(HttpResponse::Ok)),
                        ),
                )
                .await;

                let app_macro = test::init_service(
                    App::new()
                        .wrap(auth_layer().build())
                        .service(web::resource("/login").route(web::get().to(login)))
                        .service(
                            web::resource("/")
                                .wrap($macro_layer)
                                .route(web::get().to(HttpResponse::Ok)),
                        ),
                )
                .await;

                let cookies = if $login {
                    let res = test::call_service(
                        &app_builder,
                        test::TestRequest::with_uri("/login").to_request(),
                    )
                    .await;
                    let builder_cookie = get_session_cookie(&res)
                        .expect("Response should have a valid session cookie");

                    let res = test::call_service(
                        &app_macro,
                        test::TestRequest::with_uri("/login").to_request(),
                    )
                    .await;
                    let macro_cookie = get_session_cookie(&res)
                        .expect("Response should have a valid session cookie");

                    Some((builder_cookie, macro_cookie))
                } else {
                    None
                };

                let mut builder_req = test::TestRequest::with_uri($uri);
                let mut macro_req = test::TestRequest::with_uri($uri);
                if let Some((builder_cookie, macro_cookie)) = cookies {
                    builder_req = builder_req.cookie(builder_cookie);
                    macro_req = macro_req.cookie(macro_cookie);
                }

                let res_builder = test::call_service(&app_builder, builder_req.to_request()).await;
                let res_macro = test::call_service(&app_macro, macro_req.to_request()).await;

                (res_builder, res_macro)
            }};
        }

        #[actix_web::test]
        async fn test_login_required_parity_unauthenticated() {
            let (res_builder, res_macro) = compare!(
                RequireBuilder::<TestBackend>::new().build(),
                login_required!(TestBackend),
                "/",
                login = false
            );

            assert_eq!(res_builder.status(), res_macro.status());
        }

        #[actix_web::test]
        async fn test_login_required_parity_redirect() {
            let (res_builder, res_macro) = compare!(
                RequireBuilder::<TestBackend>::new()
                    .unauthenticated(RedirectHandler::new().login_url("/login"))
                    .build(),
                login_required!(TestBackend, login_url = "/login"),
                "/?foo=bar",
                login = false
            );

            assert_eq!(res_builder.status(), res_macro.status());
            assert_eq!(location(&res_builder), location(&res_macro));
        }

        #[actix_web::test]
        async fn test_permission_required_parity_unauthenticated() {
            let (res_builder, res_macro) = compare!(
                RequireBuilder::<TestBackend>::new()
                    .decision(PermissionsPredicate::new().with_permissions(vec!["test.read"]))
                    .build(),
                permission_required!(TestBackend, "test.read"),
                "/",
                login = false
            );

            assert_eq!(res_builder.status(), res_macro.status());
        }

        #[actix_web::test]
        async fn test_permission_required_parity_authenticated() {
            let (res_builder, res_macro) = compare!(
                RequireBuilder::<TestBackend>::new()
                    .decision(PermissionsPredicate::new().with_permissions(vec!["test.read"]))
                    .build(),
                permission_required!(TestBackend, "test.read"),
                "/",
                login = true
            );

            assert_eq!(res_builder.status(), res_macro.status());
        }

        #[actix_web::test]
        async fn test_permission_required_parity_redirect() {
            let (res_builder, res_macro) = compare!(
                RequireBuilder::<TestBackend>::new()
                    .decision(PermissionsPredicate::new().with_permissions(vec!["test.read"]))
                    .unauthenticated(RedirectHandler::new().login_url("/login"))
                    .build(),
                permission_required!(TestBackend, login_url = "/login", "test.read"),
                "/",
                login = false
            );

            assert_eq!(res_builder.status(), res_macro.status());
            assert_eq!(location(&res_builder), location(&res_macro));
        }
    }

    #[actix_web::test]
    async fn test_login_required_with_login_url() {
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(RedirectHandler::new().login_url("/login"))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next=%2F"));

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_login_required_with_login_url_and_redirect_field() {
        let fallback = RedirectHandler::new()
            .redirect_field("next_uri")
            .login_url("/signin");

        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(fallback)
            .build();
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/signin").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/signin?next_uri=%2F"));

        let req = test::TestRequest::with_uri("/signin").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_login_required_with_response_fallback() {
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(|_| async { HttpResponse::Gone().finish() })
            .unauthenticated(SimpleResponseHandler::text(StatusCode::GONE, "test"))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/signin").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), StatusCode::GONE);

        let req = test::TestRequest::with_uri("/signin").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_login_required_with_custom_fallback() {
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(|_| async { HttpResponse::Gone().finish() })
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/signin").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), StatusCode::GONE);

        let req = test::TestRequest::with_uri("/signin").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_permission_required() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .decision(PermissionsPredicate::new().with_permissions(permissions))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_permission_required_multiple_permissions() {
        let permissions: Vec<&str> = vec!["test.read", "test.write"];
        let require = RequireBuilder::<TestBackend>::new()
            .decision(PermissionsPredicate::new().with_permissions(permissions))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_permission_required_with_login_url() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(RedirectHandler::new().login_url("/login"))
            .decision(PermissionsPredicate::new().with_permissions(permissions))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next=%2F"));

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_permission_required_with_login_url_and_redirect_field() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(
                RedirectHandler::new()
                    .redirect_field("next_uri")
                    .login_url("/signin"),
            )
            .decision(PermissionsPredicate::new().with_permissions(permissions))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/signin").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/signin?next_uri=%2F"));

        let req = test::TestRequest::with_uri("/signin").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_permission_required_missing_permissions() {
        let permissions: Vec<&str> = vec!["test.read", "test.write", "admin.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .decision(PermissionsPredicate::new().with_permissions(permissions))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn test_permission_required_custom_unauthorized_handler() {
        let permissions: Vec<&str> = vec!["test.read", "test.write", "admin.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .decision(PermissionsPredicate::new().with_permissions(permissions))
            .unauthorized(SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"))
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let body = res.into_body().try_into_bytes().unwrap();
        assert_eq!(body, "nope");
    }

    #[actix_web::test]
    async fn test_login_required_custom_unauthenticated_body() {
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(SimpleResponseHandler::text(
                StatusCode::UNAUTHORIZED,
                "sign in",
            ))
            .build();

        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(require)
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let body = res.into_body().try_into_bytes().unwrap();
        assert_eq!(body, "sign in");
    }

    #[actix_web::test]
    async fn test_permission_required_any_mode() {
        let permissions: Vec<&str> = vec!["missing.read", "test.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .decision(
                PermissionsPredicate::new()
                    .with_permissions(permissions)
                    .with_mode(PermissionMatch::Any),
            )
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_permission_required_exact_mode_denies_extra_permissions() {
        let permissions: Vec<&str> = vec!["test.read"];
        let require = RequireBuilder::<TestBackend>::new()
            .decision(
                PermissionsPredicate::new()
                    .with_permissions(permissions)
                    .with_mode(PermissionMatch::Exact),
            )
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn test_redirect_uri_query() {
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(RedirectHandler::new().login_url("/login"))
            .build();

        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(require)
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/?foo=bar&foo=baz").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            location(&res),
            Some("/login?next=%2F%3Ffoo%3Dbar%26foo%3Dbaz")
        );
    }

    #[actix_web::test]
    async fn test_login_url_query() {
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(RedirectHandler::new().login_url("/login?foo=bar&foo=baz"))
            .build();
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(require)
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next=%2F&foo=bar&foo=baz"));

        let req = test::TestRequest::with_uri("/?a=b&a=c").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            location(&res),
            Some("/login?next=%2F%3Fa%3Db%26a%3Dc&foo=bar&foo=baz")
        );
    }

    #[actix_web::test]
    async fn test_login_url_explicit_redirect() {
        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(
                RedirectHandler::new()
                    .redirect_field("next_url")
                    .login_url("/login?next_url=%2Fdashboard"),
            )
            .build();
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(require)
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next_url=%2Fdashboard"));

        let require = RequireBuilder::<TestBackend>::new()
            .unauthenticated(RedirectHandler::new().login_url("/login?next=%2Fdashboard"))
            .build();
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(require)
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next=%2Fdashboard"));
    }

    #[actix_web::test]
    async fn test_scoped() {
        let require = Require::<TestBackend>::builder()
            .unauthenticated(RedirectHandler::new().login_url("/login"))
            .build();
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::scope("/nested").service(
                    web::resource("/foo")
                        .wrap(require)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/nested/foo").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next=%2Fnested%2Ffoo"));
    }

    #[actix_web::test]
    async fn test_login_required_perm_with_state() {
        let state = TestState {
            req_perm: vec!["test.read".into()],
        };

        let f = |auth_session: AuthSession<TestBackend>, state: Arc<TestState>| {
            verify_permissions(auth_session, state)
        };
        let require_login = Require::<TestBackend, TestState>::builder_with_state(state)
            .unauthenticated(RedirectHandler::new().login_url("/login"))
            .unauthorized(|_| async { HttpResponse::Unauthorized().finish() })
            .decision(f)
            .build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require_login)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);

        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_login_url_explicit_redirect_with_permissions() {
        let state = TestState {
            req_perm: vec!["test.read".into(), "test.write".into()],
        };
        let f = |auth_session: AuthSession<TestBackend>, state: Arc<TestState>| {
            verify_permissions(auth_session, state)
        };

        let re = RequireBuilder::<TestBackend, TestState>::new_with_state(state).unauthenticated(
            RedirectHandler::new()
                .redirect_field("next_url")
                .login_url("/login?next_url=%2Fdashboard"),
        );
        let pre = re.decision(f);
        let require_login = pre.build();

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/signin").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(require_login)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next_url=%2Fdashboard"));

        let req = test::TestRequest::with_uri("/signin").to_request();
        let res = test::call_service(&app, req).await;
        let session_cookie =
            get_session_cookie(&res).expect("Response should have a valid session cookie");

        let req = test::TestRequest::with_uri("/")
            .cookie(session_cookie)
            .to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn require_debug_includes_type() {
        let require = Require::<TestBackend>::builder().build();
        let formatted = format!("{:?}", require);

        assert!(formatted.contains("Require"));
    }
}
