use std::fmt::Display;

use shared_types::OrganisationId;

use super::{HttpClient, Response};

pub struct ManagedInstancesApi {
    client: HttpClient,
}

pub struct ListFilters {
    pub organisation_id: OrganisationId,
    pub attestation: Option<String>,
    pub user_sub: Option<String>,
    pub roles: Option<Vec<String>>,
}

impl ListFilters {
    pub fn new(organisation_id: OrganisationId) -> Self {
        Self {
            organisation_id,
            attestation: None,
            user_sub: None,
            roles: None,
        }
    }
}

impl ManagedInstancesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn list(&self, list_filters: ListFilters) -> Response {
        let ListFilters {
            attestation,
            organisation_id,
            user_sub,
            roles,
        } = list_filters;

        let mut url =
            format!("/api/managed-instance/v1?organisationId={organisation_id}&page=0&pageSize=50");
        if let Some(attestation) = attestation {
            url += &format!("&attestation={attestation}");
        }
        if let Some(user_sub) = user_sub {
            url += &format!("&userSub={user_sub}");
        }
        if let Some(roles) = roles {
            for role in roles {
                url += &format!("&roles[]={role}");
            }
        }

        self.client.get(&url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/managed-instance/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn revoke(&self, id: &impl Display) -> Response {
        let url = format!("/api/managed-instance/v1/{id}/revoke");
        self.client.post(&url, None).await
    }
}
