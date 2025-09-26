use crate::auth::AuthBackend;
use crate::models::User;
use anyhow::Result;
use std::sync::Arc;

pub struct Authenticator {
    backend: Arc<dyn AuthBackend>,
}

impl Authenticator {
    pub fn new(backend: Arc<dyn AuthBackend>) -> Self {
        Self { backend }
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>> {
        self.backend.authenticate(username, password).await
    }

    pub async fn get_user(&self, username: &str) -> Result<Option<User>> {
        self.backend.get_user(username).await
    }
}