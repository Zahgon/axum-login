use std::future::{ready, Ready};

use actix_web::{
    dev::Payload, error::ErrorInternalServerError, FromRequest, HttpMessage, HttpRequest,
};

use crate::{AuthSession, AuthnBackend};

impl<Backend> FromRequest for AuthSession<Backend>
where
    Backend: AuthnBackend + 'static,
{
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        ready(
            req.extensions()
                .get::<AuthSession<Backend>>()
                .cloned()
                .ok_or_else(|| {
                    ErrorInternalServerError(
                        "Can't extract auth session. Is `AuthManagerLayer` enabled?",
                    )
                }),
        )
    }
}
