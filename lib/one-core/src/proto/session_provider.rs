use std::fmt::Display;

use shared_types::{OrganisationId, Permission};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait SessionProvider: Send + Sync {
    fn session(&self) -> Option<Session>;
}

pub struct NoSessionProvider;

impl SessionProvider for NoSessionProvider {
    fn session(&self) -> Option<Session> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub organisation_id: Option<OrganisationId>,
    pub permissions: Vec<Permission>,
    pub user_id: String,
}

impl Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let org = self
            .organisation_id
            .map(|id| format!("'{id}'"))
            .unwrap_or("None".to_string());
        write!(
            f,
            "Session {{ user_id: '{}', organisation: {org} }}",
            self.user_id
        )
    }
}

pub trait SessionExt {
    fn user(self) -> Option<String>;
}

impl SessionExt for Option<Session> {
    fn user(self) -> Option<String> {
        self.map(|session| session.user_id)
    }
}

pub mod test {
    use uuid::Uuid;

    use super::*;

    /// Session provider that returns the same static session always. Useful for testing.
    pub struct StaticSessionProvider(pub Session);

    impl StaticSessionProvider {
        pub fn new_random() -> Self {
            Self(Session {
                organisation_id: Some(Uuid::new_v4().into()),
                permissions: vec![],
                user_id: format!("test-user-{}", Uuid::new_v4()),
            })
        }
    }

    impl Default for StaticSessionProvider {
        fn default() -> Self {
            Self::new_random()
        }
    }

    impl SessionProvider for StaticSessionProvider {
        fn session(&self) -> Option<Session> {
            Some(self.0.clone())
        }
    }
}
