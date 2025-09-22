use shared_types::OrganisationId;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait SessionProvider: Send + Sync {
    fn session(&self) -> Option<Session>;
}

pub(crate) struct NoSessionProvider;

impl SessionProvider for NoSessionProvider {
    fn session(&self) -> Option<Session> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub organisation_id: Option<OrganisationId>,
    pub user_id: String,
}

#[cfg(test)]
pub mod test {
    use uuid::Uuid;

    use super::*;

    /// Session provider that returns the same static session always. Useful for testing.
    pub struct StaticSessionProvider(pub Session);

    impl StaticSessionProvider {
        pub fn new_random() -> Self {
            Self(Session {
                organisation_id: Some(Uuid::new_v4().into()),
                user_id: format!("test-user-{}", Uuid::new_v4()),
            })
        }
    }

    impl SessionProvider for StaticSessionProvider {
        fn session(&self) -> Option<Session> {
            Some(self.0.clone())
        }
    }
}
