use actix_web::{web, HttpResponse, Resource, Responder};
use askama::Template;

use crate::users::AuthSession;

#[derive(Template)]
#[template(path = "protected.html")]
struct ProtectedTemplate<'a> {
    username: &'a str,
}

pub fn resource() -> Resource {
    web::resource("/")
        .route(web::get().to(self::get::protected))
        .route(web::head().to(self::get::protected))
}

mod get {
    use super::*;

    pub async fn protected(auth_session: AuthSession) -> impl Responder {
        match auth_session.user().await {
            Some(user) => HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(
                    ProtectedTemplate {
                        username: &user.username,
                    }
                    .render()
                    .unwrap(),
                ),

            None => HttpResponse::InternalServerError().finish(),
        }
    }
}
