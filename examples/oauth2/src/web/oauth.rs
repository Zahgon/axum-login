use actix_login::actix_session::Session;
use actix_web::{web, HttpResponse, Responder};
use askama::Template;
use oauth2::CsrfToken;
use serde::Deserialize;

use crate::{
    users::{AuthSession, Credentials},
    web::auth::{redirect_to, LoginTemplate, NEXT_URL_KEY},
};

pub const CSRF_STATE_KEY: &str = "oauth.csrf-state";

#[derive(Debug, Clone, Deserialize)]
pub struct AuthzResp {
    code: String,
    state: CsrfToken,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/oauth/callback")
            .route(web::get().to(self::get::callback))
            .route(web::head().to(self::get::callback)),
    );
}

mod get {
    use super::*;

    pub async fn callback(
        auth_session: AuthSession,
        session: Session,
        query: web::Query<AuthzResp>,
    ) -> impl Responder {
        let AuthzResp {
            code,
            state: new_state,
        } = query.into_inner();

        let Ok(Some(old_state)) = session.get(CSRF_STATE_KEY) else {
            return HttpResponse::BadRequest().finish();
        };

        let creds = Credentials {
            code,
            old_state,
            new_state,
        };

        let user = match auth_session.authenticate(creds).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return HttpResponse::Unauthorized()
                    .content_type("text/html; charset=utf-8")
                    .body(
                        LoginTemplate {
                            message: Some("Invalid CSRF state.".to_string()),
                            next: None,
                        }
                        .render()
                        .unwrap(),
                    )
            }
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };

        if auth_session.login(&user).await.is_err() {
            return HttpResponse::InternalServerError().finish();
        }

        if let Some(Ok(next)) = session.remove_as::<String>(NEXT_URL_KEY) {
            redirect_to(&next)
        } else {
            redirect_to("/")
        }
    }
}
