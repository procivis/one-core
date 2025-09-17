use one_core::proto::session_provider::{Session, SessionProvider};

tokio::task_local! {
    pub(crate) static SESSION: Session;
}

pub(crate) struct CoreServerSessionProvider;

impl SessionProvider for CoreServerSessionProvider {
    fn session(&self) -> Option<Session> {
        SESSION.try_with(|s| s.clone()).ok()
    }
}
