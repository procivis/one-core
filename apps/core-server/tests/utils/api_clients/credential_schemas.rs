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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub translations: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mappings: Option<Vec<TestClaimMappings>>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TestClaimMappings {
    pub format: String,
    pub technical_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
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

#[derive(Default)]
pub struct CreateSchemaV2Params {
    pub name: String,
    pub organisation_id: Uuid,
    pub formats: Vec<serde_json::Value>,
    pub claims: Vec<TestClaim>,
    pub batch_size: Option<i32>,
    pub allow_suspension: Option<bool>,
    pub allow_revocation: Option<bool>,
    pub transaction_code: Option<CredentialSchemaTransactionCodeRequestRestDTO>,
    pub translations: Option<serde_json::Value>,
    pub embedded_disclosure_policy: Option<serde_json::Value>,
    pub expiration: Option<i64>,
    pub wallet_attestation: Option<serde_json::Value>,
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
                translations: None,
                mappings: None,
            }],
            array: None,
            translations: None,
            mappings: None,
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

    pub async fn get_v2(&self, schema_id: &impl Display) -> Response {
        let url = format!("/api/credential-schema/v2/{schema_id}");
        self.client.get(&url).await
    }

    pub async fn list(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
        include: Option<Vec<CredentialSchemaListIncludeEntityTypeEnum>>,
        additional_params: Option<&str>,
    ) -> Response {
        let mut url = format!(
            "/api/credential-schema/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

        if let Some(include) = include {
            for item in include {
                url += &format!("&include[]={item}")
            }
        }
        if let Some(filters) = additional_params {
            url += &format!("&{filters}");
        }

        self.client.get(&url).await
    }

    pub async fn list_v2(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
        include: Option<Vec<CredentialSchemaListIncludeEntityTypeEnum>>,
        additional_params: Option<&str>,
    ) -> Response {
        let mut url = format!(
            "/api/credential-schema/v2?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

        if let Some(include) = include {
            for item in include {
                url += &format!("&include[]={item}")
            }
        }
        if let Some(filters) = additional_params {
            url += &format!("&{filters}");
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

    pub async fn create_v2(&self, params: CreateSchemaV2Params) -> Response {
        let primary_attribute = params
            .claims
            .first()
            .map(TestClaim::primary_attribute_from_firsts)
            .unwrap_or_default();
        let body = json!({
            "name": params.name,
            "organisationId": params.organisation_id,
            "formats": params.formats,
            "claims": params.claims,
            "layoutType": "CARD",
            "layoutProperties": {
                "background": {
                    "color": "bg-color"
                },
                "primaryAttribute": primary_attribute,
            },
            "batchSize": params.batch_size,
            "allowSuspension": params.allow_suspension,
            "allowRevocation": params.allow_revocation,
            "expiration": params.expiration,
        });
        let mut body = body;
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
        if let Some(translations) = params.translations {
            body["translations"] = translations;
        }
        if let Some(embedded_disclosure_policy) = params.embedded_disclosure_policy {
            body["embeddedDisclosurePolicy"] = embedded_disclosure_policy;
        }
        if let Some(wallet_attestation) = params.wallet_attestation {
            body["walletAttestation"] = wallet_attestation;
        }
        self.client.post("/api/credential-schema/v2", body).await
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

    pub async fn import_v2(
        &self,
        organisation_id: OrganisationId,
        credential_schema: impl Into<serde_json::Value>,
    ) -> Response {
        let schema = credential_schema.into();

        self.client
            .post(
                "/api/credential-schema/v2/import",
                Some(json!({
                    "schema": schema,
                    "organisationId": organisation_id
                })),
            )
            .await
    }
}
