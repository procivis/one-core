use one_core::service::statistics::dto::SystemStatsRequestDTO;

use crate::endpoint::statistics::dto::SystemStatsRequestQuery;

impl From<SystemStatsRequestQuery> for SystemStatsRequestDTO {
    fn from(value: SystemStatsRequestQuery) -> Self {
        Self {
            from: value.from,
            to: value.to,
            organisation_count: value.organisation_count.unwrap_or(5),
        }
    }
}
