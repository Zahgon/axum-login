use std::{collections::HashMap, future::Future};

use actix_web::{
    http::{
        header::{self, HeaderName, HeaderValue},
        StatusCode,
    },
    HttpRequest, HttpResponse, Responder,
};
use tracing::error;

use crate::require::BoxFuture;

const DEFAULT_LOGIN_URL: &str = "/signin";
const DEFAULT_REDIRECT_FIELD: &str = "next";

/// Trait for [`super::Require`] middleware handlers.
///
/// Handlers are shared across requests, so they must be `Send + Sync`. The
/// futures they return are tied to the worker thread handling the request and
/// therefore need not be.
pub trait ResponseHandler: Send + Sync {
    /// Handle a request.
    fn handle(&self, request: HttpRequest) -> BoxFuture<'static, HttpResponse>;
}

impl<F, Fut, Res> ResponseHandler for F
where
    F: Fn(HttpRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Res> + 'static,
    Res: Responder + 'static,
{
    fn handle(&self, request: HttpRequest) -> BoxFuture<'static, HttpResponse> {
        let fut = (self)(request.clone());
        Box::pin(async move { fut.await.respond_to(&request).map_into_boxed_body() })
    }
}

/// The default handler for unauthenticated requests.
#[derive(Clone, Debug)]
pub struct DefaultUnauthenticated;

impl ResponseHandler for DefaultUnauthenticated {
    fn handle(&self, _request: HttpRequest) -> BoxFuture<'static, HttpResponse> {
        Box::pin(async move { HttpResponse::build(StatusCode::UNAUTHORIZED).body("Unauthorized") })
    }
}

/// The default handler for unauthorized requests.
#[derive(Clone, Debug)]
pub struct DefaultUnauthorized;

impl ResponseHandler for DefaultUnauthorized {
    fn handle(&self, _request: HttpRequest) -> BoxFuture<'static, HttpResponse> {
        Box::pin(async move { HttpResponse::build(StatusCode::FORBIDDEN).body("Forbidden") })
    }
}

#[derive(Clone)]
pub(super) struct InternalErrorFallback;

impl ResponseHandler for InternalErrorFallback {
    fn handle(&self, _request: HttpRequest) -> BoxFuture<'static, HttpResponse> {
        Box::pin(async move {
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).body("Internal server error")
        })
    }
}
/// A simple redirect-based handler that redirects to a login URL.
///
/// Used with [`RequireBuilder`](crate::require::builder::RequireBuilder).
///
/// # Example
///
/// ```rust,no_run
/// use actix_login::{
///     require::{RedirectHandler, Require},
///     AuthUser, AuthnBackend, UserId,
/// };
///
/// #[derive(Clone, Debug)]
/// struct User;
///
/// impl AuthUser for User {
///     type Id = i64;
///
///     fn id(&self) -> Self::Id {
///         0
///     }
///
///     fn session_auth_hash(&self) -> &[u8] {
///         &[]
///     }
/// }
///
/// #[derive(Clone)]
/// struct Backend;
///
/// impl AuthnBackend for Backend {
///     type User = User;
///     type Credentials = ();
///     type Error = std::convert::Infallible;
///
///     async fn authenticate(
///         &self,
///         _: Self::Credentials,
///     ) -> Result<Option<Self::User>, Self::Error> {
///         Ok(Some(User))
///     }
///
///     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
///         Ok(Some(User))
///     }
/// }
///
/// let require = Require::<Backend>::builder()
///     .unauthenticated(
///         RedirectHandler::new()
///             .login_url("/login")
///             .redirect_field("next"),
///     )
///     .build();
/// ```
#[derive(Clone, Debug, Default)]
pub struct RedirectHandler {
    /// Optional name of the query parameter used to store
    /// the redirect target (e.g., `"next"`).
    pub redirect_field: Option<String>,

    /// Optional login URL to redirect unauthenticated users to.
    pub login_url: Option<String>,
}

impl RedirectHandler {
    /// Creates a new [`RedirectHandler`] with no `login_url` or
    /// `redirect_field` set.
    ///
    /// This is equivalent to calling `RedirectHandler::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the redirect field name (e.g., `"next"`) to be appended to the
    /// login URL.
    pub fn redirect_field(mut self, field: impl Into<String>) -> Self {
        self.redirect_field = Some(field.into());
        self
    }

    /// Sets the login URL to which unauthenticated users will be redirected.
    pub fn login_url(mut self, url: impl Into<String>) -> Self {
        self.login_url = Some(url.into());
        self
    }
}

impl ResponseHandler for RedirectHandler {
    fn handle(&self, req: HttpRequest) -> BoxFuture<'static, HttpResponse> {
        let login_url = self
            .login_url
            .clone()
            .unwrap_or(DEFAULT_LOGIN_URL.to_string());
        let redirect_field = self
            .redirect_field
            .clone()
            .unwrap_or(DEFAULT_REDIRECT_FIELD.to_string());

        Box::pin(async move {
            // Actix Web never rewrites the request URI when routing through
            // scopes, so this is always the URI the user agent asked for.
            let original_uri = req.uri().clone();

            match crate::url_with_redirect_query(&login_url, &redirect_field, original_uri) {
                Ok(url) => HttpResponse::build(StatusCode::TEMPORARY_REDIRECT)
                    .insert_header((header::LOCATION, url.to_string()))
                    .body("Redirecting..."),
                Err(err) => {
                    error!(err = %err);
                    HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR)
                        .body("Internal Server Error")
                }
            }
        })
    }
}

/// Customizable response handler for unauthenticated or unauthorized responses.
///
/// Used with [`RequireBuilder`](crate::require::builder::RequireBuilder).
///
/// # Example
///
/// ```rust,no_run
/// use actix_login::{
///     require::{Require, SimpleResponseHandler},
///     AuthUser, AuthnBackend, UserId,
/// };
/// use actix_web::http::StatusCode;
///
/// #[derive(Clone, Debug)]
/// struct User;
///
/// impl AuthUser for User {
///     type Id = i64;
///
///     fn id(&self) -> Self::Id {
///         0
///     }
///
///     fn session_auth_hash(&self) -> &[u8] {
///         &[]
///     }
/// }
///
/// #[derive(Clone)]
/// struct Backend;
///
/// impl AuthnBackend for Backend {
///     type User = User;
///     type Credentials = ();
///     type Error = std::convert::Infallible;
///
///     async fn authenticate(
///         &self,
///         _: Self::Credentials,
///     ) -> Result<Option<Self::User>, Self::Error> {
///         Ok(Some(User))
///     }
///
///     async fn get_user(&self, _: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
///         Ok(Some(User))
///     }
/// }
///
/// let require = Require::<Backend>::builder()
///     .unauthenticated(SimpleResponseHandler::text(
///         StatusCode::UNAUTHORIZED,
///         "Sign in to continue",
///     ))
///     .build();
/// ```
#[derive(Clone, Debug)]
pub struct SimpleResponseHandler {
    /// HTTP status code to return
    pub status_code: StatusCode,
    /// Response body content
    pub body: String,
    /// Content-Type header value.
    pub content_type: String,
    /// Additional custom headers to include.
    pub headers: HashMap<String, String>,
}

impl Default for SimpleResponseHandler {
    fn default() -> Self {
        Self {
            status_code: StatusCode::UNAUTHORIZED,
            body: "Authentication required".to_string(),
            content_type: "text/plain".to_string(),
            headers: HashMap::new(),
        }
    }
}

impl SimpleResponseHandler {
    /// Create a new `SimpleResponseHandler` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the HTTP status code.
    pub fn status_code(mut self, status: StatusCode) -> Self {
        self.status_code = status;
        self
    }

    /// Set the response body.
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = body.into();
        self
    }

    /// Set the content type.
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }

    /// Add a custom header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Add multiple custom headers.
    pub fn headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers.extend(headers);
        self
    }

    /// Create an HTML response.
    pub fn html(status: StatusCode, body: impl Into<String>) -> Self {
        Self::new()
            .status_code(status)
            .content_type("text/html; charset=utf-8")
            .body(body)
    }

    /// Create a plain text response.
    pub fn text(status: StatusCode, body: impl Into<String>) -> Self {
        Self::new()
            .status_code(status)
            .content_type("text/plain; charset=utf-8")
            .body(body)
    }

    /// Create an XML response.
    pub fn xml(status: StatusCode, body: impl Into<String>) -> Self {
        Self::new()
            .status_code(status)
            .content_type("application/xml")
            .body(body)
    }

    /// Create a simple error page.
    pub fn error_page(
        status: StatusCode,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        let title = title.into();
        let message = message.into();
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>{}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .error {{ background: #f8f9fa; border-left: 4px solid #dc3545; padding: 20px; }}
        h1 {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="error">
        <h1>{}</h1>
        <p>{}</p>
    </div>
</body>
</html>"#,
            title, title, message
        );
        Self::html(status, html)
    }
}

impl ResponseHandler for SimpleResponseHandler {
    fn handle(&self, _req: HttpRequest) -> BoxFuture<'static, HttpResponse> {
        let status_code = self.status_code;
        let body = self.body.clone();
        let content_type = self.content_type.clone();
        let headers = self.headers.clone();

        Box::pin(async move {
            let mut response = HttpResponse::build(status_code).body(body);

            // Set content type, skipping it when it isn't a valid header value.
            if let Ok(content_type) = HeaderValue::from_str(&content_type) {
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, content_type);
            }

            for (name, value) in &headers {
                if let (Ok(header_name), Ok(header_value)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    response.headers_mut().insert(header_name, header_value);
                }
            }

            response
        })
    }
}

#[cfg(test)]
mod tests {
    use actix_web::test::TestRequest;

    use super::*;

    #[actix_web::test]
    async fn test_default_response() {
        let handler = SimpleResponseHandler::new();
        let request = TestRequest::default().to_http_request();

        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn test_custom_headers() {
        let handler = SimpleResponseHandler::new().header("X-Custom-Header", "custom-value");

        let request = TestRequest::default().to_http_request();
        let response = handler.handle(request).await;

        assert_eq!(
            response.headers().get("X-Custom-Header").unwrap(),
            "custom-value"
        );
    }

    #[actix_web::test]
    async fn test_redirect_handler_invalid_login_url() {
        let handler = RedirectHandler::new().login_url("http://[::1");
        let request = TestRequest::with_uri("/").to_http_request();

        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[actix_web::test]
    async fn test_redirect_handler_uses_request_uri() {
        let handler = RedirectHandler::new().login_url("/login");
        let request = TestRequest::with_uri("/return").to_http_request();

        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/login?next=%2Freturn"
        );
    }

    #[actix_web::test]
    async fn test_redirect_handler_defaults() {
        let handler = RedirectHandler::new();
        let request = TestRequest::with_uri("/").to_http_request();

        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/signin?next=%2F"
        );
    }

    #[actix_web::test]
    async fn test_redirect_handler_preserves_existing_redirect_param() {
        let handler = RedirectHandler::new().login_url("/login?next=%2Fkeep");
        let request = TestRequest::with_uri("/").to_http_request();

        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/login?next=%2Fkeep"
        );
    }

    #[actix_web::test]
    async fn test_response_handler_from_closure() {
        let handler = |_: HttpRequest| async { HttpResponse::ImATeapot().finish() };
        let request = TestRequest::default().to_http_request();

        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
    }

    #[actix_web::test]
    async fn test_simple_response_handler_invalid_headers_ignored() {
        let handler = SimpleResponseHandler::new()
            .content_type("\n")
            .header("bad header", "value")
            .header("X-Good", "ok");

        let request = TestRequest::default().to_http_request();
        let response = handler.handle(request).await;

        assert!(response.headers().get(header::CONTENT_TYPE).is_none());
        assert!(response.headers().get("bad header").is_none());
        assert_eq!(response.headers().get("X-Good").unwrap(), "ok");
    }

    #[actix_web::test]
    async fn test_simple_response_handler_error_page() {
        let handler =
            SimpleResponseHandler::error_page(StatusCode::UNAUTHORIZED, "Denied", "No access");
        let request = TestRequest::default().to_http_request();
        let response = handler.handle(request).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }
}
