use std::fmt::Display;

use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct CredentialSchemasApi {
    client: HttpClient,
}

#[derive(Default)]
pub struct CreateSchemaParams {
    pub name: String,
    pub organisation_id: Uuid,
    pub format: String,
    pub claim_name: String,
    pub schema_id: Option<String>,
    pub revocation_method: Option<String>,
    pub suspension_allowed: Option<bool>,
}

impl CredentialSchemasApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, params: CreateSchemaParams) -> Response {
        let body = json!({
          "claims": [
            {
              "datatype": "OBJECT",
              "key": "firstObject",
              "required": true,
              "claims": [
                {
                  "datatype": "STRING",
                  "key": params.claim_name,
                  "required": true
                }
              ],
            }
          ],
          "format": params.format,
          "name": params.name,
          "organisationId": params.organisation_id,
          "revocationMethod": params.revocation_method.unwrap_or("NONE".into()),
          "layoutType": "CARD",
          "layoutProperties": {
            "backgroundColor": "bg-color",
            "backgroundImage": "bg-image",
            "labelColor": "label-color",
            "labelImage": "label-image",
            "primaryAttribute": format!("firstObject/{claim_name}", claim_name = params.claim_name),
          },
          "schemaId": params.schema_id,
          "allowSuspension": params.suspension_allowed.unwrap_or(false),
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
