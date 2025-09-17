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
    pub organisation_id: OrganisationId,
    pub user_id: String,
}
