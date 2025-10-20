use std::sync::{Arc, LazyLock};

use indexmap::IndexMap;
use regex::Regex;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::{
    fetch_procivis_schema, from_create_request, map_to_import_credential_schema_request,
};
use super::model::OpenID4VCICredentialConfigurationData;
use crate::mapper::oidc::map_from_openid4vp_format;
use crate::model::credential_schema::{
    BackgroundProperties, CredentialSchema, CredentialSchemaType, LayoutProperties, LayoutType,
    LogoProperties,
};
use crate::model::organisation::Organisation;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::credential_schema::parser::CredentialSchemaImportParser;
use crate::provider::caching_loader::vct::VctTypeMetadataFetcher;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_draft13::mapper::{
    create_claims_from_credential_definition, extract_offered_claims, parse_mdoc_schema_claims,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    CreateCredentialSchemaRequestDTO, OpenID4VCICredentialValueDetails,
    OpenID4VCIIssuerMetadataResponseDTO,
};
use crate::provider::issuance_protocol::{BasicSchemaData, BuildCredentialSchemaResponse};
use crate::service::ssi_issuer::dto::SdJwtVcTypeMetadataResponseDTO;

#[allow(clippy::expect_used)]
static SCHEMA_URL_REPLACEMENT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/ssi/openid4vci/[\w-]+/").expect("Failed to compile regex"));

pub(crate) struct HandleInvitationOperationsImpl {
    pub vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
    pub http_client: Arc<dyn HttpClient>,
    pub credential_schema_parser: Arc<dyn CredentialSchemaImportParser>,
    pub credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
}

/// Interface to be implemented in order to use an exchange protocol.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[allow(clippy::too_many_arguments)]
#[async_trait::async_trait]
pub(crate) trait HandleInvitationOperations: Send + Sync {
    /// Utilizes custom logic to find out credential schema
    /// type and id from credential offer
    fn find_schema_data(
        &self,
        credential_config: &OpenID4VCICredentialConfigurationData,
        offer_id: &str,
    ) -> Result<BasicSchemaData, IssuanceProtocolError>;

    /// Allows use of custom logic to create new credential schema for
    /// incoming credential
    async fn create_new_schema(
        &self,
        schema_data: BasicSchemaData,
        claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential_config: &OpenID4VCICredentialConfigurationData,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        organisation: Organisation,
    ) -> Result<BuildCredentialSchemaResponse, IssuanceProtocolError>;
}
pub(crate) type HandleInvitationOperationsAccess = dyn HandleInvitationOperations;

impl HandleInvitationOperationsImpl {
    pub(crate) fn new(
        vct_type_metadata_cache: Arc<dyn VctTypeMetadataFetcher>,
        http_client: Arc<dyn HttpClient>,
        credential_schema_parser: Arc<dyn CredentialSchemaImportParser>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
    ) -> Self {
        Self {
            vct_type_metadata_cache,
            http_client,
            credential_schema_parser,
            credential_schema_importer,
        }
    }
}

#[async_trait::async_trait]
impl HandleInvitationOperations for HandleInvitationOperationsImpl {
    fn find_schema_data(
        &self,
        credential_config: &OpenID4VCICredentialConfigurationData,
        offer_id: &str,
    ) -> Result<BasicSchemaData, IssuanceProtocolError> {
        let format = credential_config.format.as_str();
        // Heuristic to determine if the credential is offered by a Procivis issuer or not
        let external_schema = credential_config.wallet_storage_type.is_none();

        let data = match format {
            "mso_mdoc" => BasicSchemaData {
                id: credential_config
                    .doctype
                    .as_deref()
                    .unwrap_or(offer_id)
                    .to_owned(),
                r#type: CredentialSchemaType::Mdoc.to_string(),
                external_schema,
                offer_id: offer_id.to_owned(),
            },
            // external sd-jwt vc
            "vc+sd-jwt" | "dc+sd-jwt" => {
                // We use the vc+sd-jwt format identifier for both SD-JWT-VC and SD-JWT credential formats.
                // Checking the credential configuration for the VCT is a workaround.
                let (schema_type, id) = match credential_config.vct.as_ref() {
                    Some(vct) => (CredentialSchemaType::SdJwtVc, vct.to_owned()),
                    None => (
                        CredentialSchemaType::ProcivisOneSchema2024,
                        offer_id.to_owned(),
                    ),
                };

                BasicSchemaData {
                    id,
                    r#type: schema_type.to_string(),
                    offer_id: offer_id.to_owned(),
                    external_schema,
                }
            }
            _ => BasicSchemaData {
                id: offer_id.to_owned(),
                r#type: CredentialSchemaType::ProcivisOneSchema2024.to_string(),
                offer_id: offer_id.to_owned(),
                external_schema,
            },
        };

        Ok(data)
    }

    async fn create_new_schema(
        &self,
        schema: BasicSchemaData,
        claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
        credential_id: &CredentialId,
        credential_config: &OpenID4VCICredentialConfigurationData,
        issuer_metadata: &OpenID4VCIIssuerMetadataResponseDTO,
        organisation: Organisation,
    ) -> Result<BuildCredentialSchemaResponse, IssuanceProtocolError> {
        // The extraction of the schema_url is required for the imported_source_url that it is
        // correct on HOLDER side as well, however the HOLDER will not use it therefore we might
        // remove it when we fix the workaround for mDOC.
        // MDOC doesn't have any information about schema url. It's replaced by doctype, hence we need to figure something out for now
        let schema_url = SCHEMA_URL_REPLACEMENT_REGEX
            .replace_all(&issuer_metadata.credential_issuer, "/ssi/schema/v1/")
            .into_owned();

        let credential_display_name = credential_config.display.as_ref().and_then(|display_info| {
            let display = display_info.first()?;
            Some(&display.name)
        });

        match schema.r#type.as_str() {
            "ProcivisOneSchema2024" | "SdJwtVc" if !schema.external_schema => {
                let procivis_schema = fetch_procivis_schema(&schema_url, &*self.http_client)
                    .await
                    .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;

                if procivis_schema.claims.is_empty() {
                    return Err(IssuanceProtocolError::Failed(
                        "Claim schemas cannot be empty".to_string(),
                    ));
                }

                let now = OffsetDateTime::now_utc();
                let import_credential_schema_request_dto = map_to_import_credential_schema_request(
                    now,
                    schema.id.clone(),
                    schema_url,
                    organisation.clone(),
                    procivis_schema,
                )
                .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;

                let schema = self
                    .credential_schema_parser
                    .parse_import_credential_schema(import_credential_schema_request_dto)
                    .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;

                let schema = self
                    .credential_schema_importer
                    .import_credential_schema(schema)
                    .await
                    .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;

                let claims = extract_offered_claims(&schema, *credential_id, claim_keys)?;

                Ok(BuildCredentialSchemaResponse { claims, schema })
            }
            "mdoc" => {
                let result = fetch_procivis_schema(&schema_url, &*self.http_client).await;

                let (layout_type, layout_properties, schema_name) = match result {
                    Ok(schema) => (
                        schema.layout_type.unwrap_or(LayoutType::Card),
                        schema.layout_properties,
                        Some(schema.name),
                    ),
                    Err(_) => (LayoutType::Card, None, None),
                };

                let credential_format =
                    map_from_openid4vp_format(credential_config.format.as_str())
                        .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;

                let metadata_credential = issuer_metadata
                    .credential_configurations_supported
                    .get(&schema.offer_id);

                let element_order = metadata_credential
                    .as_ref()
                    .and_then(|credential| credential.order.clone());

                let claim_schemas =
                    metadata_credential.and_then(|credential| credential.claims.clone());
                let claims_specified = claim_schemas.is_some();

                let name = schema_name
                    .as_ref()
                    .or(credential_display_name)
                    .or(credential_config.doctype.as_ref())
                    .cloned()
                    .ok_or_else(|| {
                        IssuanceProtocolError::Failed("MDOC metadata missing doctype".to_string())
                    })?;

                let credential_schema = from_create_request(
                    CreateCredentialSchemaRequestDTO {
                        name,
                        format: credential_format,
                        revocation_method: "NONE".to_string(),
                        claims: if let Some(schemas) = claim_schemas {
                            parse_mdoc_schema_claims(schemas, element_order)
                        } else {
                            vec![]
                        },
                        wallet_storage_type: credential_config.wallet_storage_type.to_owned(),
                        layout_type,
                        external_schema: false,
                        layout_properties,
                        schema_id: schema.id.clone(),
                        imported_source_url: schema_url,
                    },
                    organisation.clone(),
                    "mdoc".to_string(),
                )
                .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;

                if claims_specified {
                    let schema = self
                        .credential_schema_importer
                        .import_credential_schema(credential_schema)
                        .await
                        .map_err(|error| {
                            tracing::error!("Failed to import credential schema: {}", error);
                            IssuanceProtocolError::Failed(
                                "Could not store credential schema".to_string(),
                            )
                        })?;
                    let claims = extract_offered_claims(&schema, *credential_id, claim_keys)?;

                    Ok(BuildCredentialSchemaResponse { claims, schema })
                } else {
                    let schema = self
                        .credential_schema_importer
                        .import_credential_schema(credential_schema)
                        .await
                        .map_err(|error| {
                            tracing::error!("Failed to import credential schema: {}", error);
                            IssuanceProtocolError::Failed(
                                "Could not store credential schema".to_string(),
                            )
                        })?;
                    let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                        create_claims_from_credential_definition(*credential_id, claim_keys)?;

                    Ok(BuildCredentialSchemaResponse {
                        claims,
                        schema: CredentialSchema {
                            claim_schemas: Some(claim_schemas),
                            ..schema
                        },
                    })
                }
            }
            // external schema
            _ => {
                let credential_format = match credential_config.format.as_str() {
                    "vc+sd-jwt" if credential_config.vct.is_some() => "SD_JWT_VC".to_string(),
                    other => map_from_openid4vp_format(other)
                        .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?
                        .to_string(),
                };

                let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                    create_claims_from_credential_definition(*credential_id, claim_keys)?;

                let (schema_name, layout_properties) = {
                    let mut schema_name = None;
                    let mut layout_properties = None;

                    if let Some(vct) = &credential_config.vct {
                        let metadata_cache_item = self
                            .vct_type_metadata_cache
                            .get(vct)
                            .await
                            .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

                        if let Some(metadata_cache_item) = metadata_cache_item {
                            schema_name = metadata_cache_item.metadata.name.clone();
                            layout_properties = map_layout_properties(metadata_cache_item.metadata);
                        }
                    }

                    (schema_name, layout_properties)
                };

                let name = match schema_name.or_else(|| credential_display_name.cloned()) {
                    Some(name) => name,
                    None => credential_config
                        .credential_definition
                        .as_ref()
                        .and_then(|c| c.r#type.first())
                        .ok_or_else(|| {
                            IssuanceProtocolError::Failed(
                                "Credential definition has no type specified".to_string(),
                            )
                        })?
                        .to_owned(),
                };

                let now = OffsetDateTime::now_utc();
                let id = Uuid::new_v4();
                let credential_schema = CredentialSchema {
                    id: id.into(),
                    deleted_at: None,
                    created_date: now,
                    last_modified: now,
                    name,
                    format: credential_format,
                    imported_source_url: schema_url,
                    wallet_storage_type: credential_config.wallet_storage_type.to_owned(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: Some(claim_schemas),
                    layout_type: LayoutType::Card,
                    layout_properties,
                    external_schema: schema.external_schema,
                    schema_type: CredentialSchemaType::Other(schema.r#type),
                    schema_id: schema.id.clone(),
                    organisation: Some(organisation.clone()),
                    allow_suspension: false,
                };

                let schema = self
                    .credential_schema_importer
                    .import_credential_schema(credential_schema)
                    .await
                    .map_err(|error| {
                        tracing::error!("Failed to import credential schema: {}", error);
                        IssuanceProtocolError::Failed(
                            "Could not store credential schema".to_string(),
                        )
                    })?;

                Ok(BuildCredentialSchemaResponse { claims, schema })
            }
        }
    }
}

fn map_layout_properties(
    type_metadata: SdJwtVcTypeMetadataResponseDTO,
) -> Option<LayoutProperties> {
    type_metadata
        .layout_properties
        .map(LayoutProperties::from)
        .or_else(|| {
            let display = type_metadata.display.into_iter().next()?;

            let rendering = display.rendering?.simple?;

            let background = rendering
                .background_color
                .map(|color| BackgroundProperties {
                    color: Some(color),
                    image: None,
                });

            let logo = rendering.logo.map(|logo| LogoProperties {
                font_color: None,
                background_color: None,
                image: Some(logo.uri.to_string()),
            });

            Some(LayoutProperties {
                background,
                logo,
                primary_attribute: None,
                secondary_attribute: None,
                picture_attribute: None,
                code: None,
            })
        })
}
