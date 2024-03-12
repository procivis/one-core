use time::OffsetDateTime;

#[derive(PartialEq, strum::Display)]
pub(crate) enum LvvcStatus {
    #[strum(serialize = "ACCEPTED")]
    Accepted,
    #[strum(serialize = "REVOKED")]
    Revoked,
    #[strum(serialize = "SUSPENDED")]
    Suspended {
        suspend_end_date: Option<OffsetDateTime>,
    },
}
