use actix_login::actix_session::Session;
use actix_web::{http::header, web, HttpResponse, Responder};
use askama::Template;
use serde::Deserialize;

use crate::{users::AuthSession, web::oauth::CSRF_STATE_KEY};

pub const NEXT_URL_KEY: &str = "auth.next-url";

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub message: Option<String>,
    pub next: Option<String>,
}

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/login/password").route(web::post().to(self::post::login::password)),
    )
    .service(web::resource("/login/oauth").route(web::post().to(self::post::login::oauth)))
    .service(
        web::resource("/login")
            .route(web::get().to(self::get::login))
            .route(web::head().to(self::get::login)),
    )
    .service(
        web::resource("/logout")
            .route(web::get().to(self::get::logout))
            .route(web::head().to(self::get::logout)),
    );
}

pub(super) fn html(body: String) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(body)
}

pub(super) fn redirect_to(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((header::LOCATION, location.to_owned()))
        .finish()
}

mod post {
    use super::*;

    pub(super) mod login {
        use super::*;
        use crate::users::{Credentials, PasswordCreds};

        pub async fn password(
            auth_session: AuthSession,
            creds: web::Form<PasswordCreds>,
        ) -> impl Responder {
            let creds = creds.into_inner();

            let user = match auth_session
                .authenticate(Credentials::Password(creds.clone()))
                .await
            {
                Ok(Some(user)) => user,
                Ok(None) => {
                    return html(
                        LoginTemplate {
                            message: Some("Invalid credentials.".to_string()),
                            next: creds.next,
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

            if let Some(ref next) = creds.next {
                redirect_to(next)
            } else {
                redirect_to("/")
            }
        }

        pub async fn oauth(
            auth_session: AuthSession,
            session: Session,
            next: web::Form<NextUrl>,
        ) -> impl Responder {
            let (auth_url, csrf_state) = auth_session.backend().authorize_url();

            session
                .insert(CSRF_STATE_KEY, csrf_state.secret())
                .expect("Serialization should not fail.");

            session
                .insert(NEXT_URL_KEY, next.into_inner().next)
                .expect("Serialization should not fail.");

            redirect_to(auth_url.as_str())
        }
    }
}

mod get {
    use super::*;

    pub async fn login(next: web::Query<NextUrl>) -> impl Responder {
        html(
            LoginTemplate {
                message: None,
                next: next.into_inner().next,
            }
            .render()
            .unwrap(),
        )
    }

    pub async fn logout(auth_session: AuthSession) -> impl Responder {
        match auth_session.logout().await {
            Ok(_) => redirect_to("/login"),
            Err(_) => HttpResponse::InternalServerError().finish(),
        }
    }
}
