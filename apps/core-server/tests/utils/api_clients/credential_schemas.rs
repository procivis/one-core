use std::fmt::Display;

use core_server::endpoint::credential_schema::dto::CredentialSchemaTransactionCodeRequestRestDTO;
use one_core::service::credential_schema::dto::CredentialSchemaListIncludeEntityTypeEnum;
use serde::Serialize;
use serde_json::json;
use shared_types::OrganisationId;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct CredentialSchemasApi {
    client: HttpClient,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TestClaim {
    pub datatype: String,
    pub key: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<TestClaim>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub array: Option<bool>,
}

impl TestClaim {
    pub fn primary_attribute_from_firsts(&self) -> String {
        if let Some(first_child) = self.claims.first() {
            format!(
                "{}/{}",
                self.key,
                first_child.primary_attribute_from_firsts()
            )
        } else {
            self.key.clone()
        }
    }
}

#[derive(Default)]
pub struct CreateSchemaParams {
    pub name: String,
    pub organisation_id: Uuid,
    pub format: String,
    pub claims: Vec<TestClaim>,
    pub schema_id: Option<String>,
    pub revocation_method: Option<String>,
    pub suspension_allowed: Option<bool>,
    pub key_storage_security: Option<String>,
    pub logo: Option<String>,
    pub transaction_code: Option<CredentialSchemaTransactionCodeRequestRestDTO>,
}

impl CreateSchemaParams {
    pub fn with_default_claims(mut self, claim_name: String) -> Self {
        self.claims = vec![TestClaim {
            datatype: "OBJECT".to_string(),
            key: "firstObject".to_string(),
            required: true,
            claims: vec![TestClaim {
                datatype: "STRING".to_string(),
                key: claim_name,
                required: true,
                claims: vec![],
                array: None,
            }],
            array: None,
        }];
        self
    }
}

impl CredentialSchemasApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, params: CreateSchemaParams) -> Response {
        let primary_attribute = params
            .claims
            .first()
            .map(TestClaim::primary_attribute_from_firsts)
            .unwrap_or_default();

        let mut body = json!({
          "claims": params.claims,
          "format": params.format,
          "name": params.name,
          "organisationId": params.organisation_id,
          "revocationMethod": params.revocation_method,
          "layoutType": "CARD",
          "layoutProperties": {
            "background": {
                "color": "bg-color"
            },
            "primaryAttribute": primary_attribute,
          },
          "schemaId": params.schema_id,
        });
        if let Some(suspension_allowed) = params.suspension_allowed {
            body["allowSuspension"] = json!(suspension_allowed);
        }
        if let Some(key_storage_security) = params.key_storage_security {
            body["keyStorageSecurity"] = json!(key_storage_security);
        }
        if let Some(logo) = params.logo {
            body["layoutProperties"]["logo"] = json!({"image": logo});
        }
        if let Some(transaction_code) = params.transaction_code {
            let mut code = json!({
                "type": transaction_code.r#type,
                "length": transaction_code.length
            });
            if let Some(description) = transaction_code.description {
                code["description"] = json!(description);
            }
            body["transactionCode"] = code;
        }

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
        let mut url = format!(
            "/api/credential-schema/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

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

    pub async fn import(
        &self,
        organisation_id: OrganisationId,
        credential_schema: impl Into<serde_json::Value>,
    ) -> Response {
        let schema = credential_schema.into();

        self.client
            .post(
                "/api/credential-schema/v1/import",
                Some(json!({
                    "schema": schema,
                    "organisationId": organisation_id
                })),
            )
            .await
    }
}
