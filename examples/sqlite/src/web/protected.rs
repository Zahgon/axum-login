use actix_web::{web, HttpResponse, Resource, Responder};
use actix_web_flash_messages::IncomingFlashMessages;
use askama::Template;

use crate::users::AuthSession;

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate<'a> {
    messages: Vec<String>,
    username: &'a str,
}

pub fn resource() -> Resource {
    web::resource("/")
        .route(web::get().to(self::get::protected))
        .route(web::head().to(self::get::protected))
}

mod get {
    use super::*;

    pub async fn protected(
        auth_session: AuthSession,
        messages: IncomingFlashMessages,
    ) -> impl Responder {
        match auth_session.user().await {
            Some(user) => {
                let body = ProtectedTemplate {
                    messages: messages
                        .iter()
                        .map(|message| message.content().to_string())
                        .collect(),
                    username: &user.username,
                }
                .render()
                .unwrap();

                HttpResponse::Ok()
                    .content_type("text/html; charset=utf-8")
                    .body(body)
            }

            None => HttpResponse::InternalServerError().finish(),
        }
    }
}
