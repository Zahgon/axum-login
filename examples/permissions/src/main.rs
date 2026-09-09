//! Run with
//!
//! ```not_rust
//! cargo run -p example-permissions
//! ```
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::web::App;

mod users;
mod web;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(
            |_| "actix_login=debug,actix_session=debug,sqlx=warn,actix_web=debug".into(),
        )))
        .with(tracing_subscriber::fmt::layer())
        .try_init()?;

    App::new().await?.serve().await
}
