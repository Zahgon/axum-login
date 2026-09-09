use actix_web::{http::header, web, HttpResponse, Responder};
use actix_web_flash_messages::{FlashMessage, IncomingFlashMessages};
use askama::Template;
use serde::Deserialize;

use crate::users::{AuthSession, Credentials};

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    messages: Vec<String>,
    next: Option<String>,
}

// This allows us to extract the "next" field from the query string. We use this
// to redirect after log in.
#[derive(Debug, Deserialize)]
pub struct NextUrl {
    next: Option<String>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/login")
            .route(web::post().to(self::post::login))
            .route(web::get().to(self::get::login))
            .route(web::head().to(self::get::login)),
    )
    .service(
        web::resource("/logout")
            .route(web::get().to(self::get::logout))
            .route(web::head().to(self::get::logout)),
    );
}

fn redirect_to(location: &str) -> HttpResponse {
    HttpResponse::SeeOther()
        .insert_header((header::LOCATION, location.to_owned()))
        .finish()
}

mod post {
    use super::*;

    pub async fn login(auth_session: AuthSession, creds: web::Form<Credentials>) -> impl Responder {
        let creds = creds.into_inner();

        let user = match auth_session.authenticate(creds.clone()).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                FlashMessage::error("Invalid credentials").send();

                let mut login_url = "/login".to_string();
                if let Some(next) = creds.next {
                    login_url = format!("{login_url}?next={next}");
                };

                return redirect_to(&login_url);
            }
            Err(_) => return HttpResponse::InternalServerError().finish(),
        };

        if auth_session.login(&user).await.is_err() {
            return HttpResponse::InternalServerError().finish();
        }

        FlashMessage::success(format!("Successfully logged in as {}", user.username)).send();

        if let Some(ref next) = creds.next {
            redirect_to(next)
        } else {
            redirect_to("/")
        }
    }
}

mod get {
    use super::*;

    pub async fn login(
        messages: IncomingFlashMessages,
        next: web::Query<NextUrl>,
    ) -> impl Responder {
        let body = LoginTemplate {
            messages: messages
                .iter()
                .map(|message| message.content().to_string())
                .collect(),
            next: next.into_inner().next,
        }
        .render()
        .unwrap();

        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(body)
    }

    pub async fn logout(auth_session: AuthSession) -> impl Responder {
        match auth_session.logout().await {
            Ok(_) => redirect_to("/login"),
            Err(_) => HttpResponse::InternalServerError().finish(),
        }
    }
}
