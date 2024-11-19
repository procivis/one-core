use std::sync::Arc;

use indexmap::IndexMap;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::{fetch_procivis_schema, from_create_request, parse_procivis_schema_claim};
use crate::config::core_config::CoreConfig;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaType, LayoutType};
use crate::model::organisation::Organisation;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::mapper::{
    create_claims_from_credential_definition, map_offered_claims_to_credential_schema,
    parse_mdoc_schema_claims,
};
use crate::provider::exchange_protocol::openid4vc::model::{
    CreateCredentialSchemaRequestDTO, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialValueDetails, OpenID4VCIIssuerMetadataResponseDTO,
};
use crate::provider::exchange_protocol::{
    BasicSchemaData, BuildCredentialSchemaResponse, HandleInvitationOperations,
};
use crate::provider::http_client::HttpClient;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::util::oidc::map_from_oidc_format_to_core;

pub struct HandleInvitationOperationsImpl {
    pub organisation: Organisation,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub config: Arc<CoreConfig>,
    pub http_client: Arc<dyn HttpClient>,
}

impl HandleInvitationOperationsImpl {
    pub fn new(
        organisation: Organisation,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        config: Arc<CoreConfig>,
        http_client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            organisation,
            credential_schemas,
            config,
            http_client,
        }
    }
}

#[async_trait::async_trait]
impl HandleInvitationOperations for HandleInvitationOperationsImpl {
    async fn get_credential_schema_name(
        &self,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
        schema_id: &str,
    ) -> Result<String, ExchangeProtocolError> {
        let display_name = issuer_metadata
            .credential_configurations_supported
            .get(schema_id)
            // Just get the first one as we sends only one token at the time
            .and_then(|credential| credential.display.clone())
            .and_then(|displays| displays.into_iter().next());

        let credential_schema_name = match display_name {
            Some(display_name) => display_name.name,
            // fallback to doctype for mdoc
            None if credential.format == "mso_mdoc" => {
                let doctype = credential
                    .doctype
                    .as_ref()
                    .ok_or(ExchangeProtocolError::Failed(
                        "docType not specified for MDOC".to_string(),
                    ))?;

                doctype.to_owned()
            }
            // fallback to credential type for other formats
            None => {
                let credential_definition =
                    credential.credential_definition.as_ref().ok_or_else(|| {
                        ExchangeProtocolError::Failed(format!(
                            "Missing credential definition for format: {}",
                            credential.format
                        ))
                    })?;

                credential_definition
                    .r#type
                    .last()
                    .ok_or_else(|| {
                        ExchangeProtocolError::Failed(
                            "Credential definition has no type specified".to_string(),
                        )
                    })?
                    .to_owned()
            }
        };

        Ok(credential_schema_name)
    }

    async fn find_schema_data(
        &self,
        _issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
        schema_id: &str,
        offer_id: &str,
    ) -> BasicSchemaData {
        if credential.format == "mso_mdoc" {
            return BasicSchemaData {
                schema_id: credential
                    .doctype
                    .as_deref()
                    .unwrap_or(schema_id)
                    .to_string(),
                schema_type: CredentialSchemaType::Mdoc.to_string(),
                offer_id: offer_id.to_owned(),
            };
        }

        BasicSchemaData {
            schema_id: schema_id.to_owned(),
            schema_type: CredentialSchemaType::ProcivisOneSchema2024.to_string(),
            offer_id: offer_id.to_owned(),
        }
    }

    async fn create_new_schema(
        &self,
        schema_data: &BasicSchemaData,
        claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential_schema_name: &str,
        organisation: Organisation,
    ) -> Result<BuildCredentialSchemaResponse, ExchangeProtocolError> {
        // The extraction of the schema_url is required for the imported_source_url that it is
        // correct on HOLDER side as well, however the HOLDER will not use it therefore we might
        // remove it when we fix the workaround for mDOC.
        // MDOC doesn't have any information about schema url. It's replaced by doctype, hence we need to figure something out for now
        let schema_url = issuer_metadata
            .credential_issuer
            .replace("/ssi/oidc-issuer/v1/", "/ssi/schema/v1/");

        let result = match schema_data.schema_type.as_str() {
            "ProcivisOneSchema2024" => {
                let procivis_schema =
                    fetch_procivis_schema(&schema_data.schema_id, &*self.http_client)
                        .await
                        .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                let schema = from_create_request(
                    CreateCredentialSchemaRequestDTO {
                        name: procivis_schema.name,
                        format: procivis_schema.format,
                        revocation_method: procivis_schema.revocation_method,
                        organisation_id: self.organisation.id,
                        claims: procivis_schema
                            .claims
                            .into_iter()
                            .map(parse_procivis_schema_claim)
                            .collect(),
                        wallet_storage_type: procivis_schema.wallet_storage_type,
                        layout_type: procivis_schema.layout_type.unwrap_or(LayoutType::Card),
                        layout_properties: procivis_schema.layout_properties,
                        schema_id: Some(schema_data.schema_id.clone()),
                    },
                    self.organisation.clone(),
                    "",
                    "JWT",
                    None,
                )
                .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                let schema = CredentialSchema {
                    schema_type: CredentialSchemaType::ProcivisOneSchema2024,
                    ..schema
                };

                let claims =
                    map_offered_claims_to_credential_schema(&schema, *credential_id, claim_keys)?;

                BuildCredentialSchemaResponse { claims, schema }
            }
            "mdoc" => {
                let result = fetch_procivis_schema(&schema_url, &*self.http_client).await;

                let (layout_type, layout_properties) = match result {
                    Ok(schema) => (
                        schema.layout_type.unwrap_or(LayoutType::Card),
                        schema.layout_properties,
                    ),
                    Err(_) => (LayoutType::Card, None),
                };
                // END OF WORKAROUND

                let credential_format = map_from_oidc_format_to_core(&credential.format)
                    .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                let metadata_credential = issuer_metadata
                    .credential_configurations_supported
                    .get(&schema_data.offer_id);

                let element_order = metadata_credential
                    .as_ref()
                    .and_then(|credential| credential.order.clone());

                let claim_schemas =
                    metadata_credential.and_then(|credential| credential.claims.clone());
                let claims_specified = claim_schemas.is_some();

                let credential_schema = from_create_request(
                    CreateCredentialSchemaRequestDTO {
                        name: credential_schema_name.to_owned(),
                        format: credential_format,
                        revocation_method: "NONE".to_string(),
                        organisation_id: self.organisation.id,
                        claims: if let Some(schemas) = claim_schemas {
                            parse_mdoc_schema_claims(schemas, element_order)
                        } else {
                            vec![]
                        },
                        wallet_storage_type: credential.wallet_storage_type.to_owned(),
                        layout_type,
                        layout_properties,
                        schema_id: Some(schema_data.schema_id.clone()),
                    },
                    self.organisation.clone(),
                    "",
                    "MDOC",
                    None,
                )
                .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                if claims_specified {
                    let claims = map_offered_claims_to_credential_schema(
                        &credential_schema,
                        *credential_id,
                        claim_keys,
                    )?;

                    BuildCredentialSchemaResponse {
                        claims,
                        schema: credential_schema,
                    }
                } else {
                    let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                        create_claims_from_credential_definition(*credential_id, claim_keys)?;

                    BuildCredentialSchemaResponse {
                        claims,
                        schema: CredentialSchema {
                            claim_schemas: Some(claim_schemas),
                            ..credential_schema
                        },
                    }
                }
            }
            _ => {
                let credential_format = map_from_oidc_format_to_core(&credential.format)
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                    create_claims_from_credential_definition(*credential_id, claim_keys)?;

                let now = OffsetDateTime::now_utc();
                let id = Uuid::new_v4();
                let credential_schema = CredentialSchema {
                    id: id.into(),
                    deleted_at: None,
                    created_date: now,
                    last_modified: now,
                    name: credential_schema_name.to_owned(),
                    format: credential_format,
                    imported_source_url: schema_url,
                    wallet_storage_type: credential.wallet_storage_type.to_owned(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: Some(claim_schemas),
                    layout_type: LayoutType::Card,
                    layout_properties: None,
                    schema_type: CredentialSchemaType::Other(schema_data.schema_type.clone()),
                    schema_id: schema_data.schema_id.clone(),
                    organisation: Some(organisation),
                    allow_suspension: false,
                };

                BuildCredentialSchemaResponse {
                    claims,
                    schema: credential_schema,
                }
            }
        };

        let mut schema = result.schema.clone();
        schema.organisation = Some(self.organisation.to_owned());

        self.credential_schemas
            .create_credential_schema(schema)
            .await
            .map_err(|_| {
                ExchangeProtocolError::Failed("Could not store credential schema".to_string())
            })?;

        Ok(result)
    }
}
