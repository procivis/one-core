use std::collections::HashMap;
use std::sync::Arc;

use one_providers::common_models::credential::CredentialId;
use one_providers::common_models::credential_schema::{OpenCredentialSchema, OpenLayoutType};
use one_providers::common_models::organisation::OpenOrganisation;
use one_providers::exchange_protocol::openid4vc::imp::mappers::map_offered_claims_to_credential_schema;
use one_providers::exchange_protocol::openid4vc::model::{
    CreateCredentialSchemaRequestDTO, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialValueDetails, OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO,
    OpenID4VCIIssuerMetadataResponseDTO,
};
use one_providers::exchange_protocol::openid4vc::{
    BasicSchemaData, BuildCredentialSchemaResponse, ExchangeProtocolError,
    HandleInvitationOperations,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::{fetch_procivis_schema, from_create_request, parse_procivis_schema_claim};
use crate::config::core_config::CoreConfig;
use crate::provider::exchange_protocol::openid4vc::mapper::{
    create_claims_from_credential_definition, parse_mdoc_schema_claims,
};
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::util::oidc::map_from_oidc_format_to_core;

pub const NESTED_CLAIM_MARKER: char = '/';

pub struct HandleInvitationOperationsImpl {
    pub organisation: OpenOrganisation,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub config: Arc<CoreConfig>,
}

impl HandleInvitationOperationsImpl {
    pub fn new(
        organisation: OpenOrganisation,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            organisation,
            credential_schemas,
            config,
        }
    }
}

#[async_trait::async_trait]
impl HandleInvitationOperations for HandleInvitationOperationsImpl {
    async fn get_credential_schema_name(
        &self,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
    ) -> Result<String, ExchangeProtocolError> {
        let display_name = issuer_metadata
            .credentials_supported
            .first()
            .and_then(|credential| credential.display.as_ref())
            .and_then(|displays| displays.first())
            .map(|display: &one_providers::exchange_protocol::openid4vc::model::OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO| display.name.to_owned());

        let credential_schema_name = match display_name {
            Some(display_name) => display_name,
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
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
    ) -> BasicSchemaData {
        if credential.format == "mso_mdoc" {
            // doctype is the schema_id for MDOC
            if let Some(doctype) = credential.doctype.to_owned() {
                return BasicSchemaData {
                    schema_id: doctype,
                    schema_type: "mdoc".to_string(),
                };
            }
        }

        let credential_schema: Option<OpenID4VCIIssuerMetadataCredentialSchemaResponseDTO> =
            issuer_metadata
                .credentials_supported
                .first() // This is not interoperable, but since in this case we only try to detect our own schema, we know there's always only one
                .and_then(|credential| credential.credential_definition.as_ref())
                .and_then(|definition| definition.credential_schema.to_owned());

        match credential_schema {
            None => BasicSchemaData {
                schema_id: Uuid::new_v4().to_string(),
                schema_type: "FallbackSchema2024".to_string(),
            },
            Some(schema) => BasicSchemaData {
                schema_id: schema.id,
                schema_type: schema.r#type,
            },
        }
    }

    async fn create_new_schema(
        &self,
        schema_data: &BasicSchemaData,
        claim_keys: &HashMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential: &OpenID4VCICredentialOfferCredentialDTO,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        credential_schema_name: &str,
        organisation: OpenOrganisation,
    ) -> Result<BuildCredentialSchemaResponse, ExchangeProtocolError> {
        let result = match schema_data.schema_type.as_str() {
            "ProcivisOneSchema2024" => {
                let procivis_schema = fetch_procivis_schema(&schema_data.schema_id)
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
                        layout_type: procivis_schema.layout_type.unwrap_or(OpenLayoutType::Card),
                        layout_properties: procivis_schema.layout_properties,
                        schema_id: Some(schema_data.schema_id.clone()),
                    },
                    self.organisation.clone().into(),
                    "",
                    "JWT",
                    None,
                )
                .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                let schema = OpenCredentialSchema {
                    schema_type: schema_data.schema_type.clone(),
                    ..schema
                };

                let claims =
                    map_offered_claims_to_credential_schema(&schema, *credential_id, claim_keys)?;

                BuildCredentialSchemaResponse { claims, schema }
            }
            "mdoc" => {
                let credential_format = map_from_oidc_format_to_core(&credential.format)
                    .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                let metadata_credential = issuer_metadata
                    .credentials_supported
                    .clone()
                    .into_iter()
                    .find(|credential| {
                        credential
                            .doctype
                            .as_ref()
                            .is_some_and(|doctype| doctype == &schema_data.schema_id)
                    });

                let element_order = metadata_credential
                    .as_ref()
                    .and_then(|credential| credential.order.to_owned());

                let claim_schemas = metadata_credential.and_then(|credential| credential.claims);
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
                        layout_type: OpenLayoutType::Card,
                        layout_properties: None,
                        schema_id: Some(schema_data.schema_id.clone()),
                    },
                    self.organisation.clone().into(),
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
                        schema: OpenCredentialSchema {
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
                let credential_schema = OpenCredentialSchema {
                    id: Uuid::new_v4().into(),
                    deleted_at: None,
                    created_date: now,
                    last_modified: now,
                    name: credential_schema_name.to_owned(),
                    format: credential_format,
                    wallet_storage_type: credential.wallet_storage_type.to_owned(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: Some(claim_schemas),
                    layout_type: OpenLayoutType::Card,
                    layout_properties: None,
                    schema_type: schema_data.schema_type.clone(),
                    schema_id: schema_data.schema_id.clone(),
                    organisation: Some(organisation),
                };

                BuildCredentialSchemaResponse {
                    claims,
                    schema: credential_schema,
                }
            }
        };

        let mut schema: crate::model::credential_schema::CredentialSchema =
            result.schema.clone().into();
        schema.organisation = Some(self.organisation.to_owned().into());

        self.credential_schemas
            .create_credential_schema(schema)
            .await
            .map_err(|_| {
                ExchangeProtocolError::Failed("Could not store credential schema".to_string())
            })?;

        Ok(result)
    }
}
