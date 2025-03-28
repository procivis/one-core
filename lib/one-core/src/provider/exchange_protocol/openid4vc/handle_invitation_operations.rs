use std::sync::Arc;

use indexmap::IndexMap;
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::{fetch_procivis_schema, from_create_request, parse_procivis_schema_claim};
use super::model::OpenID4VCICredentialConfigurationData;
use crate::config::core_config::CoreConfig;
use crate::model::credential_schema::{
    BackgroundProperties, CredentialSchema, CredentialSchemaType, LayoutProperties, LayoutType,
    LogoProperties,
};
use crate::model::organisation::Organisation;
use crate::provider::caching_loader::json_schema::JsonSchemaCache;
use crate::provider::caching_loader::vct::VctTypeMetadataCache;
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
use crate::service::ssi_issuer::dto::SdJwtVcTypeMetadataResponseDTO;
use crate::util::oidc::OID4VP_TO_FORMATTER_MAP;
pub struct HandleInvitationOperationsImpl {
    pub organisation: Organisation,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub vct_type_metadata_cache: Arc<VctTypeMetadataCache>,
    pub json_schema_cache: Arc<JsonSchemaCache>,
    pub config: Arc<CoreConfig>,
    pub http_client: Arc<dyn HttpClient>,
}

impl HandleInvitationOperationsImpl {
    pub fn new(
        organisation: Organisation,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        vct_type_metadata_cache: Arc<VctTypeMetadataCache>,
        json_schema_cache: Arc<JsonSchemaCache>,
        config: Arc<CoreConfig>,
        http_client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            organisation,
            credential_schemas,
            vct_type_metadata_cache,
            json_schema_cache,
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

    fn find_schema_data(
        &self,
        credential_config: &OpenID4VCICredentialConfigurationData,
        offer_id: &str,
    ) -> Result<BasicSchemaData, ExchangeProtocolError> {
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
    ) -> Result<BuildCredentialSchemaResponse, ExchangeProtocolError> {
        // The extraction of the schema_url is required for the imported_source_url that it is
        // correct on HOLDER side as well, however the HOLDER will not use it therefore we might
        // remove it when we fix the workaround for mDOC.
        // MDOC doesn't have any information about schema url. It's replaced by doctype, hence we need to figure something out for now
        let schema_url = issuer_metadata
            .credential_issuer
            .replace("/ssi/oidc-issuer/v1/", "/ssi/schema/v1/");

        let credential_display_name = credential_config.display.as_ref().and_then(|display_info| {
            let display = display_info.first()?;
            Some(&display.name)
        });

        let result = match schema.r#type.as_str() {
            "ProcivisOneSchema2024" | "SdJwtVc" if !schema.external_schema => {
                let procivis_schema = fetch_procivis_schema(&schema_url, &*self.http_client)
                    .await
                    .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                let schema = from_create_request(
                    CreateCredentialSchemaRequestDTO {
                        name: procivis_schema.name,
                        format: procivis_schema.format,
                        revocation_method: procivis_schema.revocation_method,
                        organisation_id: self.organisation.id,
                        external_schema: false,
                        claims: procivis_schema
                            .claims
                            .into_iter()
                            .map(parse_procivis_schema_claim)
                            .collect(),
                        wallet_storage_type: procivis_schema.wallet_storage_type,
                        layout_type: procivis_schema.layout_type.unwrap_or(LayoutType::Card),
                        layout_properties: procivis_schema.layout_properties,
                        schema_id: Some(schema.id.clone()),
                    },
                    self.organisation.clone(),
                    "",
                    procivis_schema.schema_type,
                )
                .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))?;

                let claims =
                    map_offered_claims_to_credential_schema(&schema, *credential_id, claim_keys)?;

                BuildCredentialSchemaResponse { claims, schema }
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

                let credential_format = OID4VP_TO_FORMATTER_MAP
                    .get(credential_config.format.as_str())
                    .ok_or(ExchangeProtocolError::Failed(format!(
                        "Missing credential format for `{}`",
                        credential_config.format
                    )))?;

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
                        ExchangeProtocolError::Failed("MDOC metadata missing doctype".to_string())
                    })?;

                let credential_schema = from_create_request(
                    CreateCredentialSchemaRequestDTO {
                        name,
                        format: credential_format.to_string(),
                        revocation_method: "NONE".to_string(),
                        organisation_id: self.organisation.id,
                        claims: if let Some(schemas) = claim_schemas {
                            parse_mdoc_schema_claims(schemas, element_order)
                        } else {
                            vec![]
                        },
                        wallet_storage_type: credential_config.wallet_storage_type.to_owned(),
                        layout_type,
                        external_schema: false,
                        layout_properties,
                        schema_id: Some(schema.id.clone()),
                    },
                    self.organisation.clone(),
                    "",
                    "mdoc".to_string(),
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
            // external schema
            _ => {
                let credential_format = match credential_config.format.as_str() {
                    "vc+sd-jwt" if credential_config.vct.is_some() => "SD_JWT_VC".to_string(),
                    other => OID4VP_TO_FORMATTER_MAP
                        .get(other)
                        .ok_or(ExchangeProtocolError::Failed(format!(
                            "Missing credential format for `{}`",
                            other
                        )))?
                        .to_string(),
                };

                let (claim_schemas, claims): (Vec<_>, Vec<_>) =
                    create_claims_from_credential_definition(*credential_id, claim_keys)?;

                let (schema_name, layout_properties) = {
                    let mut schema_name = None;
                    let mut layout_properties = None;

                    if let Some(vct) = &credential_config.vct {
                        let metadata = self
                            .vct_type_metadata_cache
                            .get(vct)
                            .await
                            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

                        if let Some(metadata) = metadata {
                            schema_name = metadata.name.clone();
                            layout_properties = map_layout_properties(metadata);
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
                            ExchangeProtocolError::Failed(
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
                    external_schema: false,
                    imported_source_url: schema_url,
                    wallet_storage_type: credential_config.wallet_storage_type.to_owned(),
                    revocation_method: "NONE".to_string(),
                    claim_schemas: Some(claim_schemas),
                    layout_type: LayoutType::Card,
                    layout_properties,
                    schema_type: CredentialSchemaType::Other(schema.r#type),
                    schema_id: schema.id.clone(),
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
