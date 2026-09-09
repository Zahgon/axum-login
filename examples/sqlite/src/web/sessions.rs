use std::collections::HashMap;

use actix_session::{
    storage::{generate_session_key, LoadError, SaveError, SessionKey, SessionStore, UpdateError},
    SessionExt,
};
use actix_web::{
    cookie::time::{Duration, OffsetDateTime},
    dev::ResponseHead,
    HttpRequest,
};
use actix_web_flash_messages::{
    storage::{FlashMessageStore, LoadError as FlashLoadError, StoreError as FlashStoreError},
    FlashMessage,
};
use anyhow::Context;
use sqlx::SqlitePool;

/// A SQLite-backed session store.
///
/// `actix-session` ships cookie- and Redis-backed stores only, so we provide
/// our own here in order to keep session state in the same SQLite database
/// that holds our users.
#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Creates the session table if it doesn't already exist.
    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            create table if not exists sessions (
                id text primary key not null,
                state text not null,
                expiry_date integer not null
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Deletes every session which has passed its expiry.
    pub async fn delete_expired(&self) -> Result<(), sqlx::Error> {
        sqlx::query("delete from sessions where expiry_date < ?")
            .bind(OffsetDateTime::now_utc().unix_timestamp())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Runs [`Self::delete_expired`] on the given interval until cancelled.
    pub async fn continuously_delete_expired(
        self,
        period: std::time::Duration,
    ) -> Result<(), sqlx::Error> {
        let mut interval = tokio::time::interval(period);
        interval.tick().await; // The first tick completes immediately.

        loop {
            interval.tick().await;
            self.delete_expired().await?;
        }
    }

    async fn upsert(
        &self,
        session_key: &SessionKey,
        state: &HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        let state =
            serde_json::to_string(state).context("Failed to serialize session state to JSON.")?;

        sqlx::query(
            r#"
            insert into sessions (id, state, expiry_date)
            values (?, ?, ?)
            on conflict(id) do update
            set state = excluded.state, expiry_date = excluded.expiry_date
            "#,
        )
        .bind(session_key.as_ref())
        .bind(state)
        .bind(expiry_date(ttl))
        .execute(&self.pool)
        .await
        .context("Failed to persist the session state.")?;

        Ok(())
    }
}

fn expiry_date(ttl: &Duration) -> i64 {
    (OffsetDateTime::now_utc() + *ttl).unix_timestamp()
}

impl SessionStore for SqliteStore {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        let row: Option<(String,)> =
            sqlx::query_as("select state from sessions where id = ? and expiry_date > ?")
                .bind(session_key.as_ref())
                .bind(OffsetDateTime::now_utc().unix_timestamp())
                .fetch_optional(&self.pool)
                .await
                .context("Failed to load the session state.")
                .map_err(LoadError::Other)?;

        row.map(|(state,)| {
            serde_json::from_str(&state)
                .context("Failed to deserialize session state from JSON.")
                .map_err(LoadError::Deserialization)
        })
        .transpose()
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let session_key = generate_session_key();

        self.upsert(&session_key, &session_state, ttl)
            .await
            .map_err(SaveError::Other)?;

        Ok(session_key)
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        self.upsert(&session_key, &session_state, ttl)
            .await
            .map_err(UpdateError::Other)?;

        Ok(session_key)
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        sqlx::query("update sessions set expiry_date = ? where id = ?")
            .bind(expiry_date(ttl))
            .bind(session_key.as_ref())
            .execute(&self.pool)
            .await
            .context("Failed to update the session expiry.")?;

        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        sqlx::query("delete from sessions where id = ?")
            .bind(session_key.as_ref())
            .execute(&self.pool)
            .await
            .context("Failed to delete the session state.")?;

        Ok(())
    }
}

/// A session-backed flash message store.
///
/// `actix-web-flash-messages` ships a store of this kind, but it is built
/// against an older `actix-session` release, so we provide our own in order to
/// share the session machinery used by the rest of the application.
#[derive(Debug, Clone)]
pub struct SessionMessageStore {
    key: String,
}

impl Default for SessionMessageStore {
    fn default() -> Self {
        Self {
            key: "_flash".into(),
        }
    }
}

impl FlashMessageStore for SessionMessageStore {
    fn load(&self, request: &HttpRequest) -> Result<Vec<FlashMessage>, FlashLoadError> {
        request
            .get_session()
            .get(&self.key)
            .map(Option::unwrap_or_default)
            .map_err(|err| {
                FlashLoadError::GenericError(
                    anyhow::anyhow!("{err}")
                        .context("Failed to retrieve flash messages from the session."),
                )
            })
    }

    fn store(
        &self,
        messages: &[FlashMessage],
        request: HttpRequest,
        _response: &mut ResponseHead,
    ) -> Result<(), FlashStoreError> {
        let session = request.get_session();

        if messages.is_empty() {
            // Clear up previously displayed messages, but only when there are
            // any: removing an absent key would mark every session as changed.
            if session.contains_key(&self.key) {
                session.remove(&self.key);
            }
        } else {
            session.insert(&self.key, messages).map_err(|err| {
                FlashStoreError::GenericError(
                    anyhow::anyhow!("{err}")
                        .context("Failed to store flash messages in the session."),
                )
            })?;
        }

        Ok(())
    }
}
