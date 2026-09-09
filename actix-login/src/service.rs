use std::{fmt::Debug, future::Future, pin::Pin, rc::Rc};

use actix_session::{storage::SessionStore, SessionExt, SessionMiddleware};
use actix_web::{
    body::MessageBody,
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorInternalServerError,
    HttpMessage,
};
use tracing::Instrument;

use crate::{AuthSession, AuthUser, AuthnBackend};

/// A middleware that provides [`AuthSession`] as a request extension.
pub struct AuthManager<S, Backend: AuthnBackend> {
    inner: Rc<S>,
    backend: Backend,
    data_key: &'static str,
}

impl<S, Backend: AuthnBackend> AuthManager<S, Backend> {
    /// Create a new [`AuthManager`] with the provided access controller.
    pub fn new(inner: S, backend: Backend, data_key: &'static str) -> Self {
        Self {
            inner: Rc::new(inner),
            backend,
            data_key,
        }
    }
}

impl<S, Backend: AuthnBackend> Debug for AuthManager<S, Backend> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthManager")
            .field("data_key", &self.data_key)
            .finish_non_exhaustive()
    }
}

impl<S, Backend: AuthnBackend> Clone for AuthManager<S, Backend> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            backend: self.backend.clone(),
            data_key: self.data_key,
        }
    }
}

impl<S, B, Backend> Service<ServiceRequest> for AuthManager<S, Backend>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
    Backend: AuthnBackend + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(inner);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let span = tracing::info_span!("call", user.id = tracing::field::Empty);

        let backend = self.backend.clone();
        let data_key = self.data_key;
        let inner = Rc::clone(&self.inner);

        // `SessionMiddleware` runs ahead of us, so the session is always
        // available on the request.
        let session = req.get_session();

        Box::pin(
            async move {
                let auth_session = match AuthSession::from_session(session, backend, data_key).await
                {
                    Ok(auth_session) => auth_session,
                    Err(err) => {
                        tracing::error!(
                            err = %err,
                            "could not create auth session from session"
                        );
                        return Err(ErrorInternalServerError(
                            "could not create auth session from session",
                        ));
                    }
                };

                if let Some(ref user) = auth_session.user().await {
                    tracing::Span::current().record("user.id", user.id().to_string());
                }

                req.extensions_mut().insert(auth_session);

                inner.call(req).await
            }
            .instrument(span),
        )
    }
}

/// A middleware factory for providing [`AuthSession`] as a request extension.
///
/// The layer bundles the [`SessionMiddleware`] it is built with, ensuring the
/// session is always established before the auth session is derived from it.
/// Apply it to an application with
/// [`App::wrap`](actix_web::App::wrap).
pub struct AuthManagerLayer<Backend: AuthnBackend, Sessions: SessionStore> {
    backend: Backend,
    // `SessionMiddleware` is only `Clone` when its store is, so we share it
    // behind an `Rc`. It is already worker-local, so this costs us nothing.
    session_middleware: Rc<SessionMiddleware<Sessions>>,
    data_key: &'static str,
}

impl<Backend: AuthnBackend, Sessions: SessionStore> AuthManagerLayer<Backend, Sessions> {
    /// Create a new [`AuthManagerLayer`] with the provided access controller.
    pub(crate) fn new(
        backend: Backend,
        data_key: &'static str,
        session_middleware: Rc<SessionMiddleware<Sessions>>,
    ) -> Self {
        Self {
            backend,
            session_middleware,
            data_key,
        }
    }
}

impl<Backend: AuthnBackend, Sessions: SessionStore> Debug for AuthManagerLayer<Backend, Sessions> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthManagerLayer")
            .field("data_key", &self.data_key)
            .finish_non_exhaustive()
    }
}

impl<Backend: AuthnBackend, Sessions: SessionStore> Clone for AuthManagerLayer<Backend, Sessions> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            session_middleware: Rc::clone(&self.session_middleware),
            data_key: self.data_key,
        }
    }
}

impl<S, B, Backend, Sessions> Transform<S, ServiceRequest> for AuthManagerLayer<Backend, Sessions>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    B: MessageBody + 'static,
    Backend: AuthnBackend + 'static,
    Sessions: SessionStore + 'static,
    SessionMiddleware<Sessions>: Transform<
        AuthManager<S, Backend>,
        ServiceRequest,
        Response = ServiceResponse<B>,
        Error = actix_web::Error,
        InitError = (),
    >,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Transform = <SessionMiddleware<Sessions> as Transform<
        AuthManager<S, Backend>,
        ServiceRequest,
    >>::Transform;
    type InitError = ();
    type Future =
        <SessionMiddleware<Sessions> as Transform<AuthManager<S, Backend>, ServiceRequest>>::Future;

    fn new_transform(&self, inner: S) -> Self::Future {
        let auth_manager = AuthManager::new(inner, self.backend.clone(), self.data_key);

        self.session_middleware.new_transform(auth_manager)
    }
}

/// Builder for the [`AuthManagerLayer`].
pub struct AuthManagerLayerBuilder<Backend: AuthnBackend, Sessions: SessionStore> {
    backend: Backend,
    session_middleware: Rc<SessionMiddleware<Sessions>>,
    data_key: Option<&'static str>,
}

impl<Backend: AuthnBackend, Sessions: SessionStore> Debug
    for AuthManagerLayerBuilder<Backend, Sessions>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthManagerLayerBuilder")
            .field("data_key", &self.data_key)
            .finish_non_exhaustive()
    }
}

impl<Backend: AuthnBackend, Sessions: SessionStore> Clone
    for AuthManagerLayerBuilder<Backend, Sessions>
{
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            session_middleware: Rc::clone(&self.session_middleware),
            data_key: self.data_key,
        }
    }
}

impl<Backend: AuthnBackend, Sessions: SessionStore> AuthManagerLayerBuilder<Backend, Sessions> {
    /// Create a new [`AuthManagerLayerBuilder`] with the provided access
    /// controller.
    pub fn new(backend: Backend, session_middleware: SessionMiddleware<Sessions>) -> Self {
        Self {
            backend,
            session_middleware: Rc::new(session_middleware),
            data_key: None,
        }
    }

    /// Configure the `data_key` optional property of the builder. If not
    /// configured it will default to "actix-login.data".
    pub fn with_data_key(
        mut self,
        data_key: &'static str,
    ) -> AuthManagerLayerBuilder<Backend, Sessions> {
        self.data_key = Some(data_key);
        self
    }

    /// Build the [`AuthManagerLayer`].
    pub fn build(self) -> AuthManagerLayer<Backend, Sessions> {
        AuthManagerLayer::new(
            self.backend,
            self.data_key.unwrap_or("actix-login.data"),
            self.session_middleware,
        )
    }
}
