use std::{fmt::Debug, rc::Rc, sync::Arc};

use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse},
    HttpMessage, HttpRequest, HttpResponse,
};

use crate::{
    require::{
        handler::{InternalErrorFallback, ResponseHandler},
        predicate::Decision,
        BoxFuture, Require,
    },
    AuthSession, AuthnBackend,
};

/// An Actix Web service that enforces authentication and authorization.
///
/// The service checks whether a request is authenticated. If it is, it
/// evaluates the predicate and either forwards to the inner service or applies
/// the unauthorized handler. If it is not, it applies the unauthenticated
/// handler.
#[must_use]
pub struct RequireService<S, B: AuthnBackend + Send + Sync + 'static, ST> {
    pub(crate) inner: Rc<S>,
    pub(crate) layer: Require<B, ST>,
}

impl<S, B, ST> Debug for RequireService<S, B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequireService")
            .field("layer", &self.layer)
            .finish_non_exhaustive()
    }
}

impl<S, B, ST> Clone for RequireService<S, B, ST>
where
    B: AuthnBackend + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        RequireService {
            inner: Rc::clone(&self.inner),
            layer: self.layer.clone(),
        }
    }
}

/// Turns a denied request into a response produced by the given handler.
async fn denied<Body>(
    req: ServiceRequest,
    handler: Arc<dyn ResponseHandler>,
) -> ServiceResponse<EitherBody<Body>> {
    let (req, _payload) = req.into_parts();
    let res = handle(req.clone(), handler).await;

    ServiceResponse::new(req, res).map_into_right_body()
}

async fn handle(req: HttpRequest, handler: Arc<dyn ResponseHandler>) -> HttpResponse {
    handler.handle(req).await
}

impl<S, Body, B, ST> Service<ServiceRequest> for RequireService<S, B, ST>
where
    S: Service<ServiceRequest, Response = ServiceResponse<Body>, Error = actix_web::Error>
        + 'static,
    Body: MessageBody + 'static,
    B: AuthnBackend + Send + Sync + 'static,
    ST: Send + Sync + 'static,
{
    type Response = ServiceResponse<EitherBody<Body>>;
    type Error = actix_web::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(inner);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_session = req.extensions().get::<AuthSession<B>>().cloned();

        let inner = Rc::clone(&self.inner);
        let layer = self.layer.clone();

        Box::pin(async move {
            let Some(auth_session) = auth_session else {
                // Missing required extensions: return internal server error.
                return Ok(denied(req, Arc::new(InternalErrorFallback)).await);
            };

            let decision = layer
                .inner
                .decision
                .decide(auth_session, Arc::clone(&layer.inner.state))
                .await;

            match decision {
                Decision::Allow => Ok(inner.call(req).await?.map_into_left_body()),
                Decision::Unauthorized => {
                    Ok(denied(req, Arc::clone(&layer.inner.unauthorized)).await)
                }
                Decision::Unauthenticated => {
                    Ok(denied(req, Arc::clone(&layer.inner.unauthenticated)).await)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use actix_session::SessionExt;
    use actix_web::{body::BoxBody, http::StatusCode, test::TestRequest};

    use super::*;
    use crate::{
        require::{Decision, Require, SimpleResponseHandler},
        AuthSession, AuthUser, AuthnBackend,
    };

    #[derive(Clone, Debug)]
    struct TestUser;

    impl AuthUser for TestUser {
        type Id = i64;

        fn id(&self) -> Self::Id {
            1
        }

        fn session_auth_hash(&self) -> &[u8] {
            &[]
        }
    }

    #[derive(Clone)]
    struct TestBackend;

    impl AuthnBackend for TestBackend {
        type User = TestUser;
        type Credentials = ();
        type Error = std::convert::Infallible;

        async fn authenticate(
            &self,
            _: Self::Credentials,
        ) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(TestUser))
        }

        async fn get_user(&self, _: &i64) -> Result<Option<Self::User>, Self::Error> {
            Ok(Some(TestUser))
        }
    }

    /// An inner service which counts how often it is polled for readiness and
    /// called.
    #[derive(Clone)]
    struct CountingService {
        poll_ready_calls: Arc<AtomicUsize>,
        call_count: Arc<AtomicUsize>,
    }

    impl CountingService {
        fn new() -> Self {
            Self {
                poll_ready_calls: Arc::new(AtomicUsize::new(0)),
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Service<ServiceRequest> for CountingService {
        type Response = ServiceResponse<BoxBody>;
        type Error = actix_web::Error;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.poll_ready_calls.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&self, req: ServiceRequest) -> Self::Future {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(req.into_response(HttpResponse::Ok().body("ok"))) })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CallError;

    impl std::fmt::Display for CallError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("call error")
        }
    }

    impl actix_web::ResponseError for CallError {}

    /// An inner service which always fails when called.
    #[derive(Clone)]
    struct ErrorService;

    impl Service<ServiceRequest> for ErrorService {
        type Response = ServiceResponse<BoxBody>;
        type Error = actix_web::Error;
        type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

        fn poll_ready(
            &self,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&self, _req: ServiceRequest) -> Self::Future {
            Box::pin(async move { Err(CallError.into()) })
        }
    }

    async fn auth_session() -> AuthSession<TestBackend> {
        let session = TestRequest::default().to_srv_request().get_session();
        AuthSession::from_session(session, TestBackend, "actix-login.data")
            .await
            .unwrap()
    }

    fn request_with_auth_session(auth_session: AuthSession<TestBackend>) -> ServiceRequest {
        let req = TestRequest::with_uri("/").to_srv_request();
        req.extensions_mut().insert(auth_session);
        req
    }

    fn require_allow() -> Require<TestBackend> {
        Require::new(
            |_, _| async { Decision::Allow },
            SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"),
            SimpleResponseHandler::text(StatusCode::UNAUTHORIZED, "nope"),
            (),
        )
    }

    fn require_unauthorized() -> Require<TestBackend> {
        Require::new(
            |_, _| async { Decision::Unauthorized },
            SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"),
            SimpleResponseHandler::text(StatusCode::UNAUTHORIZED, "nope"),
            (),
        )
    }

    fn require_unauthenticated() -> Require<TestBackend> {
        Require::new(
            |_, _| async { Decision::Unauthenticated },
            SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"),
            SimpleResponseHandler::text(StatusCode::UNAUTHORIZED, "nope"),
            (),
        )
    }

    #[actix_web::test]
    async fn allow_calls_inner() {
        let counting = CountingService::new();
        let service = RequireService {
            inner: Rc::new(counting.clone()),
            layer: require_allow(),
        };

        let req = request_with_auth_session(auth_session().await);
        let res = service.call(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(counting.call_count.load(Ordering::SeqCst), 1);
    }

    #[actix_web::test]
    async fn unauthorized_does_not_call_inner() {
        let counting = CountingService::new();
        let service = RequireService {
            inner: Rc::new(counting.clone()),
            layer: require_unauthorized(),
        };

        let req = request_with_auth_session(auth_session().await);
        let res = service.call(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(counting.call_count.load(Ordering::SeqCst), 0);
    }

    #[actix_web::test]
    async fn unauthenticated_does_not_call_inner() {
        let counting = CountingService::new();
        let service = RequireService {
            inner: Rc::new(counting.clone()),
            layer: require_unauthenticated(),
        };

        let req = request_with_auth_session(auth_session().await);
        let res = service.call(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(counting.call_count.load(Ordering::SeqCst), 0);
    }

    #[actix_web::test]
    async fn missing_auth_session_returns_internal_error() {
        let counting = CountingService::new();
        let service = RequireService {
            inner: Rc::new(counting.clone()),
            layer: require_allow(),
        };

        let req = TestRequest::with_uri("/").to_srv_request();
        let res = service.call(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(counting.call_count.load(Ordering::SeqCst), 0);
    }

    #[actix_web::test]
    async fn allow_propagates_inner_error() {
        let service = RequireService {
            inner: Rc::new(ErrorService),
            layer: require_allow(),
        };

        let req = request_with_auth_session(auth_session().await);
        let err = service.call(req).await.unwrap_err();

        assert_eq!(err.to_string(), "call error");
    }

    #[actix_web::test]
    async fn readiness_is_forwarded_to_inner() {
        let counting = CountingService::new();
        let service = RequireService {
            inner: Rc::new(counting.clone()),
            layer: require_allow(),
        };

        let _ = actix_web::dev::Service::poll_ready(
            &service,
            &mut std::task::Context::from_waker(std::task::Waker::noop()),
        )
        .map(|res| res.unwrap());

        assert_eq!(counting.poll_ready_calls.load(Ordering::SeqCst), 1);
    }

    #[actix_web::test]
    async fn decision_is_evaluated_once_per_request() {
        let calls = Arc::new(AtomicUsize::new(0));
        let decision_calls = Arc::clone(&calls);

        let require = Require::<TestBackend>::new(
            move |_, _| {
                let decision_calls = Arc::clone(&decision_calls);
                async move {
                    decision_calls.fetch_add(1, Ordering::SeqCst);
                    Decision::Allow
                }
            },
            SimpleResponseHandler::text(StatusCode::FORBIDDEN, "nope"),
            SimpleResponseHandler::text(StatusCode::UNAUTHORIZED, "nope"),
            (),
        );

        let service = RequireService {
            inner: Rc::new(CountingService::new()),
            layer: require,
        };

        let req = request_with_auth_session(auth_session().await);
        service.call(req).await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
