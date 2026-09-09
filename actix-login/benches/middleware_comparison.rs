use std::collections::HashSet;

use actix_login::{
    login_required, permission_required,
    require::{PermissionsPredicate, RedirectHandler, Require},
    AuthManagerLayerBuilder, AuthSession, AuthUser, AuthnBackend, AuthzBackend,
};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::{Cookie, Key},
    dev::ServiceResponse,
    http::StatusCode,
    test, web, App, HttpResponse,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

    async fn authenticate(&self, _: Self::Credentials) -> Result<Option<Self::User>, Self::Error> {
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

fn setup_auth_layer() -> AuthManagerLayerBuilder<TestBackend, CookieSessionStore> {
    let session_middleware =
        SessionMiddleware::builder(CookieSessionStore::default(), Key::generate())
            .cookie_secure(false)
            .build();

    AuthManagerLayerBuilder::new(TestBackend, session_middleware)
}

async fn login(auth_session: AuthSession<TestBackend>) -> HttpResponse {
    auth_session.login(&User).await.unwrap();
    HttpResponse::Ok().finish()
}

fn session_cookie<B>(res: &ServiceResponse<B>) -> Cookie<'static> {
    res.response()
        .cookies()
        .find(|cookie| cookie.name() == "id")
        .map(|cookie| cookie.into_owned())
        .expect("Response should have a valid session cookie")
}

/// Builds an app with the given middleware applied to `/` plus a login route,
/// then runs an unauthenticated request against `/`.
macro_rules! bench_unauthenticated {
    ($middleware:expr, $expected:expr) => {{
        let app = test::init_service(
            App::new().wrap(setup_auth_layer().build()).service(
                web::resource("/")
                    .wrap($middleware)
                    .route(web::get().to(HttpResponse::Ok)),
            ),
        )
        .await;

        let req = test::TestRequest::with_uri("/").to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), $expected);
    }};
}

/// Builds an app with the given middleware applied to `/` plus a login route,
/// logs in, then runs an authenticated request against `/`.
macro_rules! bench_authenticated {
    ($middleware:expr) => {{
        let app = test::init_service(
            App::new()
                .wrap(setup_auth_layer().build())
                .service(web::resource("/login").route(web::get().to(login)))
                .service(
                    web::resource("/")
                        .wrap($middleware)
                        .route(web::get().to(HttpResponse::Ok)),
                ),
        )
        .await;

        // Login first
        let req = test::TestRequest::with_uri("/login").to_request();
        let res = test::call_service(&app, req).await;
        let cookie = session_cookie(&res);

        // Now test authenticated request
        let req = test::TestRequest::with_uri("/").cookie(cookie).to_request();
        let res = test::call_service(&app, req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }};
}

fn benchmark_unauthenticated(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("unauthenticated_request");

    // Benchmark macro-based middleware
    group.bench_function(BenchmarkId::new("macro", "login_required"), |b| {
        b.to_async(&runtime).iter(|| async {
            bench_unauthenticated!(login_required!(TestBackend), StatusCode::UNAUTHORIZED);
        });
    });

    // Benchmark builder-based middleware
    group.bench_function(BenchmarkId::new("builder", "login_required"), |b| {
        b.to_async(&runtime).iter(|| async {
            bench_unauthenticated!(
                Require::<TestBackend>::builder().build(),
                StatusCode::UNAUTHORIZED
            );
        });
    });

    group.finish();
}

fn benchmark_authenticated(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("authenticated_request");

    // Benchmark macro-based middleware
    group.bench_function(BenchmarkId::new("macro", "login_required"), |b| {
        b.to_async(&runtime).iter(|| async {
            bench_authenticated!(login_required!(TestBackend));
        });
    });

    // Benchmark builder-based middleware
    group.bench_function(BenchmarkId::new("builder", "login_required"), |b| {
        b.to_async(&runtime).iter(|| async {
            bench_authenticated!(Require::<TestBackend>::builder().build());
        });
    });

    group.finish();
}

fn benchmark_permission_check(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("permission_check");

    // Benchmark macro-based middleware
    group.bench_function(BenchmarkId::new("macro", "permission_required"), |b| {
        b.to_async(&runtime).iter(|| async {
            bench_authenticated!(permission_required!(TestBackend, "test.read"));
        });
    });

    // Benchmark builder-based middleware
    group.bench_function(BenchmarkId::new("builder", "permission_required"), |b| {
        b.to_async(&runtime).iter(|| async {
            let permissions: Vec<&str> = vec!["test.read"];
            bench_authenticated!(Require::<TestBackend>::builder()
                .decision(PermissionsPredicate::new().with_permissions(permissions))
                .build());
        });
    });

    group.finish();
}

fn benchmark_redirect_fallback(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("redirect_fallback");

    // Benchmark macro-based middleware with redirect
    group.bench_function(BenchmarkId::new("macro", "login_url_redirect"), |b| {
        b.to_async(&runtime).iter(|| async {
            bench_unauthenticated!(
                login_required!(TestBackend, login_url = "/login"),
                StatusCode::TEMPORARY_REDIRECT
            );
        });
    });

    // Benchmark builder-based middleware with redirect
    group.bench_function(BenchmarkId::new("builder", "login_url_redirect"), |b| {
        b.to_async(&runtime).iter(|| async {
            bench_unauthenticated!(
                Require::<TestBackend>::builder()
                    .unauthenticated(RedirectHandler::new().login_url("/login"))
                    .build(),
                StatusCode::TEMPORARY_REDIRECT
            );
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_unauthenticated,
    benchmark_authenticated,
    benchmark_permission_check,
    benchmark_redirect_fallback
);
criterion_main!(benches);
