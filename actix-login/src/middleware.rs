/// Login predicate middleware.
///
/// Requires that the user is authenticated.
#[macro_export]
macro_rules! login_required {
    ($backend_type:ty) => {{
        $crate::require::Require::<$backend_type>::builder().build()
    }};

    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        $crate::require::Require::<$backend_type>::builder()
            .unauthenticated(
                $crate::require::RedirectHandler::new()
                    .login_url($login_url)
                    .redirect_field($redirect_field),
            )
            .build()
    }};

    ($backend_type:ty, login_url = $login_url:expr) => {
        $crate::login_required!(
            $backend_type,
            login_url = $login_url,
            redirect_field = "next"
        )
    };
}

/// Permission predicate middleware.
///
/// Requires that the specified permissions, either user or group or both, are
/// all assigned to the user.
#[macro_export]
macro_rules! permission_required {
    ($backend_type:ty, login_url = $login_url:expr, redirect_field = $redirect_field:expr, $($perm:expr),+ $(,)?) => {{
        let predicate = $crate::require::PermissionsPredicate::<$backend_type>::new()
            .with_permissions([$($perm),+]);

        $crate::require::Require::<$backend_type>::builder()
            .decision(predicate)
            .unauthenticated(
                $crate::require::RedirectHandler::new()
                    .login_url($login_url)
                    .redirect_field($redirect_field),
            )
            .build()
    }};

    ($backend_type:ty, login_url = $login_url:expr, $($perm:expr),+ $(,)?) => {
        $crate::permission_required!(
            $backend_type,
            login_url = $login_url,
            redirect_field = "next",
            $($perm),+
        )
    };

    ($backend_type:ty, $($perm:expr),+ $(,)?) => {{
        let predicate = $crate::require::PermissionsPredicate::<$backend_type>::new()
            .with_permissions([$($perm),+]);

        $crate::require::Require::<$backend_type>::builder()
            .decision(predicate)
            .build()
    }};
}

/// Predicate middleware.
///
/// Can be specified with a login URL and next redirect field or an alternative
/// which implements [`Responder`](actix_web::Responder).
///
/// When the predicate passes, the request processes normally. On failure,
/// either a redirect to the specified login URL is issued or the alternative is
/// used as the response.
#[macro_export]
macro_rules! predicate_required {
    ($predicate:expr, $alternative:expr) => {{
        let alternative = move |_req: $crate::actix_web::HttpRequest| async move { $alternative };

        $crate::require::Require::builder()
            .decision(
                move |auth_session, _state: ::std::sync::Arc<()>| async move {
                    if $predicate(auth_session).await {
                        $crate::require::Decision::Allow
                    } else {
                        $crate::require::Decision::Unauthorized
                    }
                },
            )
            .unauthorized(alternative)
            .unauthenticated(alternative)
            .build()
    }};

    ($predicate:expr, login_url = $login_url:expr, redirect_field = $redirect_field:expr) => {{
        let redirect = $crate::require::RedirectHandler::new()
            .login_url($login_url)
            .redirect_field($redirect_field);

        $crate::require::Require::builder()
            .decision(
                move |auth_session, _state: ::std::sync::Arc<()>| async move {
                    if $predicate(auth_session).await {
                        $crate::require::Decision::Allow
                    } else {
                        $crate::require::Decision::Unauthenticated
                    }
                },
            )
            .unauthorized(redirect.clone())
            .unauthenticated(redirect)
            .build()
    }};
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use actix_session::{storage::CookieSessionStore, SessionMiddleware};
    use actix_web::{
        cookie::{Cookie, Key},
        dev::ServiceResponse,
        http::{header, StatusCode},
        test, web, App, HttpResponse,
    };

    use crate::{AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend};

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
    struct Backend;

    impl AuthnBackend for Backend {
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
            _: &<<Backend as AuthnBackend>::User as AuthUser>::Id,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(User))
        }
    }

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    pub struct Permission {
        pub name: String,
    }

    impl From<&str> for Permission {
        fn from(name: &str) -> Self {
            Permission {
                name: name.to_string(),
            }
        }
    }

    impl AuthzBackend for Backend {
        type Permission = Permission;

        async fn get_user_permissions(
            &self,
            _user: &Self::User,
        ) -> Result<HashSet<Self::Permission>, Self::Error> {
            let perms: HashSet<Self::Permission> =
                HashSet::from_iter(["test.read".into(), "test.write".into()]);
            Ok(perms)
        }
    }

    fn auth_layer() -> AuthManagerLayerBuilder<Backend, CookieSessionStore> {
        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), Key::generate())
                .cookie_secure(false)
                .build();

        AuthManagerLayerBuilder::new(Backend, session_middleware)
    }

    async fn login(auth_session: AuthSession<Backend>) -> HttpResponse {
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

    #[actix_web::test]
    async fn test_login_required() {
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(login_required!(Backend))
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
    async fn test_login_required_with_login_url() {
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(login_required!(Backend, login_url = "/login"))
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
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/signin").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(login_required!(
                            Backend,
                            login_url = "/signin",
                            redirect_field = "next_uri"
                        ))
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
    async fn test_permission_required() {
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(permission_required!(Backend, "test.read"))
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
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(permission_required!(Backend, "test.read", "test.write"))
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
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(permission_required!(
                            Backend,
                            login_url = "/login",
                            "test.read"
                        ))
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
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/signin").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(permission_required!(
                            Backend,
                            login_url = "/signin",
                            redirect_field = "next_uri",
                            "test.read"
                        ))
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
        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(permission_required!(
                            Backend,
                            "test.read",
                            "test.write",
                            "admin.read"
                        ))
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
    async fn test_redirect_uri_query() {
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(login_required!(Backend, login_url = "/login"))
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
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(login_required!(
                        Backend,
                        login_url = "/login?foo=bar&foo=baz"
                    ))
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
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(login_required!(
                        Backend,
                        login_url = "/login?next_url=%2Fdashboard",
                        redirect_field = "next_url"
                    ))
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next_url=%2Fdashboard"));

        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(login_required!(
                        Backend,
                        login_url = "/login?next=%2Fdashboard"
                    ))
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
        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::scope("/nested").service(
                    web::resource("/foo")
                        .wrap(login_required!(Backend, login_url = "/login"))
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
    async fn test_predicate_required_alternative() {
        async fn is_logged_in(auth_session: AuthSession<Backend>) -> bool {
            auth_session.user().await.is_some()
        }

        let app = test::init_service(
            App::new()
                .wrap(auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap(predicate_required!(
                            is_logged_in,
                            HttpResponse::Gone().finish()
                        ))
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::GONE);

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
    async fn test_predicate_required_login_url() {
        async fn is_logged_in(auth_session: AuthSession<Backend>) -> bool {
            auth_session.user().await.is_some()
        }

        let app = test::init_service(
            App::new().wrap(auth_layer().build()).service(
                web::resource("/")
                    .wrap(predicate_required!(
                        is_logged_in,
                        login_url = "/login",
                        redirect_field = "next"
                    ))
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(location(&res), Some("/login?next=%2F"));
    }
}
