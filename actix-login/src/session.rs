use std::{cell::RefCell, fmt::Debug, rc::Rc};

use actix_session::{Session, SessionGetError, SessionInsertError};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{
    backend::{AuthUser, UserId},
    AuthnBackend,
};

/// An error which can occur while reading from or writing to the session.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// A mapping to [`actix_session::SessionGetError`].
    #[error(transparent)]
    Get(#[from] SessionGetError),

    /// A mapping to [`actix_session::SessionInsertError`].
    #[error(transparent)]
    Insert(#[from] SessionInsertError),
}

/// An error type which maps session and backend errors.
#[derive(thiserror::Error)]
pub enum Error<Backend: AuthnBackend> {
    /// A mapping to [`SessionError`].
    #[error(transparent)]
    Session(SessionError),

    /// A mapping to `Backend::Error`.
    #[error(transparent)]
    Backend(Backend::Error),
}

impl<Backend: AuthnBackend> Debug for Error<Backend> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Session(err) => write!(f, "{err:?}")?,
            Error::Backend(err) => write!(f, "{err:?}")?,
        };

        Ok(())
    }
}

impl<Backend: AuthnBackend> From<SessionError> for Error<Backend> {
    fn from(value: SessionError) -> Self {
        Self::Session(value)
    }
}

impl<Backend: AuthnBackend> From<SessionGetError> for Error<Backend> {
    fn from(value: SessionGetError) -> Self {
        Self::Session(SessionError::Get(value))
    }
}

impl<Backend: AuthnBackend> From<SessionInsertError> for Error<Backend> {
    fn from(value: SessionInsertError) -> Self {
        Self::Session(SessionError::Insert(value))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Data<UserId> {
    user_id: Option<UserId>,
    auth_hash: Option<Vec<u8>>,
}

impl<UserId: Clone> Default for Data<UserId> {
    fn default() -> Self {
        Self {
            user_id: None,
            auth_hash: None,
        }
    }
}

struct Inner<Backend: AuthnBackend> {
    session: Session,
    user: Option<Backend::User>,
    data: Data<UserId<Backend>>,
    data_key: &'static str,
}

// `actix_session::Session` does not implement `Debug`, so we implement it
// manually here and elide the session itself.
impl<Backend: AuthnBackend> Debug for Inner<Backend> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("user", &self.user)
            .field("data", &self.data)
            .field("data_key", &self.data_key)
            .finish_non_exhaustive()
    }
}

/// A specialized session for identification, authentication, and authorization
/// of users associated with a backend.
///
/// The session is generic over some backend which implements [`AuthnBackend`].
/// The backend may also implement [`AuthzBackend`](crate::AuthzBackend),
/// in which case it will also supply authorization methods.
///
/// Methods for authenticating the session and logging a user in are provided.
///
/// Generally this session will be used in the context of some authentication
/// workflow, for example via a frontend login form. There a user would provide
/// their credentials, such as username and password, and via the backend
/// the session would authenticate those credentials.
///
/// Once the supplied credentials have been authenticated, a user will be
/// returned. In the case the credentials are invalid, no user will be returned.
/// When we do have a user, it's then possible to set the state of the session
/// so that the user is logged in.
///
/// Because the underlying [`actix_session::Session`] is bound to the worker
/// thread that handles the request, this type is neither `Send` nor `Sync`.
/// This matches the actor model Actix Web uses for request handling.
pub struct AuthSession<Backend: AuthnBackend> {
    backend: Backend,
    inner: Rc<RefCell<Inner<Backend>>>,
}

impl<Backend: AuthnBackend> Clone for AuthSession<Backend> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<Backend: AuthnBackend> Debug for AuthSession<Backend> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSession")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<Backend: AuthnBackend> AuthSession<Backend> {
    /// Returns the backend associated wih his auth session.
    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    /// Returns the user that's authenicated to this session otherwise `None`.
    pub async fn user(&self) -> Option<Backend::User> {
        self.inner.borrow().user.clone()
    }

    /// Verifies the provided credentials via the backend returning the
    /// authenticated user if valid and otherwise `None`.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id), ret, err)]
    pub async fn authenticate(
        &self,
        creds: Backend::Credentials,
    ) -> Result<Option<Backend::User>, Error<Backend>> {
        let result = self
            .backend
            .authenticate(creds)
            .await
            .map_err(Error::Backend);

        if let Ok(Some(ref user)) = result {
            tracing::Span::current().record("user.id", user.id().to_string());
        }

        result
    }

    /// Updates the session such that the user is logged in.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id = user.id().to_string()), ret, err)]
    pub async fn login(&self, user: &Backend::User) -> Result<(), Error<Backend>> {
        {
            let mut inner = self.inner.borrow_mut();
            inner.user = Some(user.clone());

            if inner.data.auth_hash.is_none() {
                inner.session.renew(); // Session-fixation mitigation.
            }

            inner.data.user_id = Some(user.id());
            inner.data.auth_hash = Some(user.session_auth_hash().to_owned());
        }

        self.update_session().await?;

        Ok(())
    }

    /// Updates the session such that the user is logged out.
    #[tracing::instrument(level = "debug", skip_all, fields(user.id), ret, err)]
    pub async fn logout(&self) -> Result<Option<Backend::User>, Error<Backend>> {
        let mut inner = self.inner.borrow_mut();
        let user = inner.user.take();

        if let Some(ref user) = user {
            tracing::Span::current().record("user.id", user.id().to_string());
        }

        inner.session.purge();

        Ok(user)
    }

    async fn update_session(&self) -> Result<(), SessionError> {
        let inner = self.inner.borrow();
        inner
            .session
            .insert(inner.data_key, inner.data.clone())
            .map_err(SessionError::Insert)
    }

    pub(crate) async fn from_session(
        session: Session,
        backend: Backend,
        data_key: &'static str,
    ) -> Result<Self, Error<Backend>> {
        let mut data: Data<_> = session
            .get(data_key)
            .map_err(SessionError::Get)?
            .unwrap_or_default();

        let mut user = if let Some(ref user_id) = data.user_id {
            backend.get_user(user_id).await.map_err(Error::Backend)?
        } else {
            None
        };

        if let Some(ref authed_user) = user {
            let session_auth_hash = authed_user.session_auth_hash();
            let session_verified = data
                .auth_hash
                .as_ref()
                .is_some_and(|auth_hash| auth_hash.ct_eq(session_auth_hash).into());
            if !session_verified {
                user = None;
                data = Data::default();
                session.purge();
            }
        }

        let inner = Rc::new(RefCell::new(Inner {
            user,
            session,
            data,
            data_key,
        }));

        Ok(Self { backend, inner })
    }
}

#[cfg(test)]
mod tests {
    use actix_session::{SessionExt, SessionStatus};
    use actix_web::test::TestRequest;
    use mockall::{predicate::*, *};

    use super::*;

    mock! {
        #[derive(Debug)]
        Backend {}

        impl Clone for Backend {
            fn clone(&self) -> Self;
        }

        impl AuthnBackend for Backend {
            type User = MockUser;
            type Credentials = MockCredentials;
            type Error = MockError;

            async fn authenticate(&self, creds: MockCredentials) -> Result<Option<MockUser>, MockError>;
            async fn get_user(&self, user_id: &i64) -> Result<Option<MockUser>, MockError>;

        }
    }

    #[derive(Debug, Clone)]
    struct MockUser {
        id: i64,
        auth_hash: Vec<u8>,
    }

    impl AuthUser for MockUser {
        type Id = i64;

        fn id(&self) -> Self::Id {
            self.id
        }

        fn session_auth_hash(&self) -> &[u8] {
            &self.auth_hash
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    struct MockCredentials;

    #[derive(Debug)]
    struct MockError;

    impl std::fmt::Display for MockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Mock error")
        }
    }

    impl std::error::Error for MockError {}

    /// Builds a bare session, as `SessionMiddleware` would provide to a
    /// request.
    fn session() -> Session {
        TestRequest::default().to_srv_request().get_session()
    }

    #[actix_web::test]
    async fn test_authenticate() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };
        let creds = MockCredentials;

        mock_backend
            .expect_authenticate()
            .with(eq(creds.clone()))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let inner = Inner {
            user: None,
            session: session(),
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Rc::new(RefCell::new(inner)),
        };

        let result = auth_session.authenticate(creds).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[actix_web::test]
    async fn test_authenticate_bad_credentials() {
        let mut mock_backend = MockBackend::default();
        let bad_creds = MockCredentials;

        mock_backend
            .expect_authenticate()
            .with(eq(bad_creds.clone()))
            .times(1)
            .returning(|_| Ok(None));

        let inner = Inner {
            user: None,
            session: session(),
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Rc::new(RefCell::new(inner)),
        };
        let result = auth_session.authenticate(bad_creds).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[actix_web::test]
    async fn test_login() {
        let mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };

        let session = session();
        let inner = Inner {
            user: None,
            session: session.clone(),
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Rc::new(RefCell::new(inner)),
        };

        // We were provided a fresh, unmodified session initially.
        assert_eq!(session.status(), SessionStatus::Unchanged);

        auth_session.login(&mock_user).await.unwrap();
        assert!(auth_session.user().await.is_some());
        assert_eq!(auth_session.user().await.unwrap().id(), 42);

        // Logging in cycles the session ID, so the session is marked renewed
        // and the auth data is persisted to it.
        assert_eq!(session.status(), SessionStatus::Renewed);
        assert!(session.contains_key("auth_data"));
    }

    #[actix_web::test]
    async fn test_logout() {
        let mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: Default::default(),
        };

        let session = session();
        let inner = Inner {
            user: Some(mock_user),
            session: session.clone(),
            data: Data::default(),
            data_key: "auth_data",
        };
        let auth_session = AuthSession {
            backend: mock_backend,
            inner: Rc::new(RefCell::new(inner)),
        };
        let logged_out_user = auth_session.logout().await.unwrap();
        assert!(logged_out_user.is_some());
        assert_eq!(logged_out_user.unwrap().id(), 42);
        assert!(auth_session.user().await.is_none());

        // The session is purged, both client and server side.
        assert_eq!(session.status(), SessionStatus::Purged);
    }

    #[actix_web::test]
    async fn test_from_session() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: vec![1, 2, 3, 4],
        };

        mock_backend
            .expect_get_user()
            .with(eq(mock_user.id))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let session = session();
        let data_key = "auth_data";

        // Simulate a user being logged in
        let data = Data {
            user_id: Some(42),
            auth_hash: Some(vec![1, 2, 3, 4]),
        };
        session.insert(data_key, &data).unwrap();

        let auth_session = AuthSession::from_session(session, mock_backend, data_key)
            .await
            .unwrap();

        assert!(auth_session.user().await.is_some());
        assert_eq!(auth_session.user().await.unwrap().id(), 42);
    }

    #[actix_web::test]
    async fn test_from_session_bad_auth_hash() {
        let mut mock_backend = MockBackend::default();
        let mock_user = MockUser {
            id: 42,
            auth_hash: vec![1, 2, 3, 4],
        };

        mock_backend
            .expect_get_user()
            .with(eq(mock_user.id))
            .times(1)
            .returning(move |_| Ok(Some(mock_user.clone())));

        let session = session();
        let data_key = "auth_data";

        // Try to use a malformed auth hash.
        let data = Data {
            user_id: Some(42),
            auth_hash: Some(vec![4, 3, 2, 1]),
        };
        session.insert(data_key, &data).unwrap();

        let auth_session = AuthSession::from_session(session, mock_backend, data_key)
            .await
            .unwrap();

        assert!(auth_session.user().await.is_none());
    }
}
