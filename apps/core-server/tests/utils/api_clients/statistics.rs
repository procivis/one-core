use shared_types::OrganisationId;
use time::OffsetDateTime;

use crate::utils::api_clients::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

pub struct StatisticsApi {
    client: HttpClient,
}

impl StatisticsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn organisation_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_id: OrganisationId,
    ) -> Response {
        let mut url = format!(
            "/api/statistics/v1/dashboard?{}&organisationId={}",
            query_time_urlencoded("to", to),
            organisation_id,
        );
        if let Some(from) = from {
            url = format!("{url}&{}", query_time_urlencoded("from", from))
        }
        self.client.get(&url).await
    }

    pub async fn organisation_issuer_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_id: OrganisationId,
    ) -> Response {
        let mut url = format!(
            "/api/statistics/v1/dashboard/issuer?{}&organisationId={}&page=0&pageSize=30",
            query_time_urlencoded("to", to),
            organisation_id,
        );
        if let Some(from) = from {
            url = format!("{url}&{}", query_time_urlencoded("from", from))
        }
        self.client.get(&url).await
    }

    pub async fn organisation_verifier_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_id: OrganisationId,
    ) -> Response {
        let mut url = format!(
            "/api/statistics/v1/dashboard/verifier?{}&organisationId={}&page=0&pageSize=30",
            query_time_urlencoded("to", to),
            organisation_id,
        );
        if let Some(from) = from {
            url = format!("{url}&{}", query_time_urlencoded("from", from))
        }
        self.client.get(&url).await
    }

    pub async fn system_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
        organisation_count: Option<usize>,
    ) -> Response {
        let mut url = format!(
            "/api/statistics/v1/dashboard/system?{}",
            query_time_urlencoded("to", to),
        );
        if let Some(from) = from {
            url = format!("{url}&{}", query_time_urlencoded("from", from))
        }
        if let Some(count) = organisation_count {
            url = format!("{url}&organisationCount={count}")
        }
        self.client.get(&url).await
    }

    pub async fn system_interaction_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
    ) -> Response {
        let mut url = format!(
            "/api/statistics/v1/dashboard/system/interaction?{}&page=0&pageSize=30",
            query_time_urlencoded("to", to),
        );
        if let Some(from) = from {
            url = format!("{url}&{}", query_time_urlencoded("from", from))
        }
        self.client.get(&url).await
    }

    pub async fn system_management_stats(
        &self,
        from: Option<OffsetDateTime>,
        to: OffsetDateTime,
    ) -> Response {
        let mut url = format!(
            "/api/statistics/v1/dashboard/system/management?{}&page=0&pageSize=30",
            query_time_urlencoded("to", to),
        );
        if let Some(from) = from {
            url = format!("{url}&{}", query_time_urlencoded("from", from))
        }
        self.client.get(&url).await
    }
}
