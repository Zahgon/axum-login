use actix_web::{web, HttpResponse, Resource, Responder};
use askama::Template;

use crate::users::AuthSession;

#[derive(Template)]
#[template(path = "restricted.html")]
struct RestrictedTemplate<'a> {
    username: &'a str,
}

pub fn resource() -> Resource {
    web::resource("/restricted")
        .route(web::get().to(self::get::restricted))
        .route(web::head().to(self::get::restricted))
}

mod get {
    use super::*;

    pub async fn restricted(auth_session: AuthSession) -> impl Responder {
        match auth_session.user().await {
            Some(user) => HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(
                    RestrictedTemplate {
                        username: &user.username,
                    }
                    .render()
                    .unwrap(),
                ),

            None => HttpResponse::InternalServerError().finish(),
        }
    }
}
