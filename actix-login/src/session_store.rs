//! An in-memory session store.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use actix_session::storage::{
    generate_session_key, LoadError, SaveError, SessionKey, SessionStore, UpdateError,
};
use actix_web::cookie::time::{Duration, OffsetDateTime};

#[derive(Debug, Clone)]
struct Record {
    state: HashMap<String, String>,
    expires_at: OffsetDateTime,
}

/// A session store which keeps session state in process memory.
///
/// `actix-session` ships cookie- and Redis-backed stores only. This store fills
/// the gap for applications which want server-side session state without a
/// separate service, such as the examples in this repository.
///
/// State is held in a map guarded by a mutex and shared by every clone of the
/// store, so cloning is cheap and every clone sees the same sessions. Nothing
/// is persisted: restarting the process discards every session.
///
/// Expired records are dropped as they are encountered rather than by a
/// background sweep, so a session which is never read again keeps its memory
/// until the store is dropped. That makes this store a poor fit for a
/// long-running deployment with heavy session churn; reach for a Redis or
/// database store there.
///
/// # Examples
///
/// ```rust
/// use actix_login::{actix_session::SessionMiddleware, MemoryStore};
/// use actix_web::cookie::Key;
///
/// let session_middleware = SessionMiddleware::new(MemoryStore::default(), Key::generate());
/// ```
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    records: Arc<Mutex<HashMap<String, Record>>>,
}

impl MemoryStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of records currently held, expired ones included.
    pub fn len(&self) -> usize {
        self.records.lock().expect("poisoned session store").len()
    }

    /// Whether the store holds no records at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert(&self, key: &SessionKey, state: HashMap<String, String>, ttl: &Duration) {
        self.records.lock().expect("poisoned session store").insert(
            key.as_ref().to_owned(),
            Record {
                state,
                expires_at: OffsetDateTime::now_utc() + *ttl,
            },
        );
    }
}

impl SessionStore for MemoryStore {
    async fn load(
        &self,
        session_key: &SessionKey,
    ) -> Result<Option<HashMap<String, String>>, LoadError> {
        let mut records = self.records.lock().expect("poisoned session store");

        let Some(record) = records.get(session_key.as_ref()) else {
            return Ok(None);
        };

        // Note: An expired record is indistinguishable from an absent one, so
        //       drop it here rather than leaving it to be read again.
        if record.expires_at <= OffsetDateTime::now_utc() {
            records.remove(session_key.as_ref());
            return Ok(None);
        }

        Ok(Some(record.state.clone()))
    }

    async fn save(
        &self,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, SaveError> {
        let session_key = generate_session_key();
        self.insert(&session_key, session_state, ttl);
        Ok(session_key)
    }

    async fn update(
        &self,
        session_key: SessionKey,
        session_state: HashMap<String, String>,
        ttl: &Duration,
    ) -> Result<SessionKey, UpdateError> {
        self.insert(&session_key, session_state, ttl);
        Ok(session_key)
    }

    async fn update_ttl(
        &self,
        session_key: &SessionKey,
        ttl: &Duration,
    ) -> Result<(), anyhow::Error> {
        if let Some(record) = self
            .records
            .lock()
            .expect("poisoned session store")
            .get_mut(session_key.as_ref())
        {
            record.expires_at = OffsetDateTime::now_utc() + *ttl;
        }

        Ok(())
    }

    async fn delete(&self, session_key: &SessionKey) -> Result<(), anyhow::Error> {
        self.records
            .lock()
            .expect("poisoned session store")
            .remove(session_key.as_ref());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn state(value: &str) -> HashMap<String, String> {
        HashMap::from([("user.id".to_owned(), value.to_owned())])
    }

    #[tokio::test]
    async fn saved_state_is_loaded_back() {
        let store = MemoryStore::default();

        let key = store
            .save(state("1"), &Duration::minutes(5))
            .await
            .expect("save should succeed");

        assert_eq!(store.load(&key).await.unwrap(), Some(state("1")));
    }

    #[tokio::test]
    async fn an_unknown_key_loads_nothing() {
        let store = MemoryStore::default();
        let key = store.save(state("1"), &Duration::minutes(5)).await.unwrap();

        store.delete(&key).await.unwrap();

        assert_eq!(store.load(&key).await.unwrap(), None);
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn update_replaces_the_state_under_the_same_key() {
        let store = MemoryStore::default();
        let key = store.save(state("1"), &Duration::minutes(5)).await.unwrap();
        let same_key = SessionKey::try_from(key.as_ref().to_owned()).unwrap();

        let updated = store
            .update(same_key, state("2"), &Duration::minutes(5))
            .await
            .unwrap();

        assert_eq!(updated.as_ref(), key.as_ref());
        assert_eq!(store.load(&key).await.unwrap(), Some(state("2")));
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn an_expired_record_is_dropped_on_load() {
        let store = MemoryStore::default();
        let key = store
            .save(state("1"), &Duration::seconds(-1))
            .await
            .unwrap();

        assert_eq!(store.load(&key).await.unwrap(), None);
        assert!(store.is_empty(), "the expired record should be gone");
    }

    #[tokio::test]
    async fn update_ttl_revives_a_record_which_was_about_to_expire() {
        let store = MemoryStore::default();
        let key = store
            .save(state("1"), &Duration::seconds(-1))
            .await
            .unwrap();

        store.update_ttl(&key, &Duration::minutes(5)).await.unwrap();

        assert_eq!(store.load(&key).await.unwrap(), Some(state("1")));
    }

    #[tokio::test]
    async fn clones_share_one_set_of_sessions() {
        let store = MemoryStore::default();
        let key = store.save(state("1"), &Duration::minutes(5)).await.unwrap();

        assert_eq!(store.clone().load(&key).await.unwrap(), Some(state("1")));
    }
}
