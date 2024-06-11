use std::fmt::Display;

use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct CredentialSchemasApi {
    client: HttpClient,
}

impl CredentialSchemasApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation_id: impl Into<Uuid>,
        schema_id: Option<&str>,
    ) -> Response {
        let body = json!({
          "claims": [
            {
              "datatype": "STRING",
              "key": "firstName",
              "required": true
            }
          ],
          "format": "JWT",
          "name": name,
          "organisationId": organisation_id.into(),
          "revocationMethod": "BITSTRINGSTATUSLIST",
          "layoutType": "CARD",
          "layoutProperties": {
            "backgroundColor": "bg-color",
            "backgroundImage": "bg-image",
            "labelColor": "label-color",
            "labelImage": "label-image",
            "primaryAttribute": "firstName",
          },
          "schemaId": schema_id,
        });

        self.client.post("/api/credential-schema/v1", body).await
    }

    pub async fn get(&self, schema_id: &impl Display) -> Response {
        let url = format!("/api/credential-schema/v1/{schema_id}");
        self.client.get(&url).await
    }

    pub async fn list(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
        include: Option<Vec<CredentialSchemaListIncludeEntityTypeEnum>>,
    ) -> Response {
        let mut url = format!("/api/credential-schema/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}");

        if let Some(include) = include {
            for item in include {
                url += &format!("&include[]={item}")
            }
        }

        self.client.get(&url).await
    }

    pub async fn delete(&self, schema_id: &impl Display) -> Response {
        let url = format!("/api/credential-schema/v1/{schema_id}");
        self.client.delete(&url).await
    }

    pub async fn share(&self, schema_id: &impl Display) -> Response {
        let url = format!("/api/credential-schema/v1/{schema_id}/share");
        self.client.post(&url, None).await
    }
}
