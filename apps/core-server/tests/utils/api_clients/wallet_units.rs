use std::fmt::Display;

use shared_types::OrganisationId;

use super::{HttpClient, Response};

pub struct WalletUnitsApi {
    client: HttpClient,
}

pub struct ListFilters {
    pub organisation_id: OrganisationId,
    pub attestation: Option<String>,
}

impl ListFilters {
    pub fn new(organisation_id: OrganisationId) -> Self {
        Self {
            organisation_id,
            attestation: None,
        }
    }
}

impl WalletUnitsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn list(&self, list_filters: ListFilters) -> Response {
        let ListFilters {
            attestation,
            organisation_id,
        } = list_filters;

        let mut url =
            format!("/api/wallet-unit/v1?organisationId={organisation_id}&page=0&pageSize=50");
        if let Some(attestation) = attestation {
            url += &format!("&attestation={attestation}")
        }

        self.client.get(&url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/wallet-unit/v1/{id}");
        self.client.get(&url).await
    }
}
