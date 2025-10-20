use std::sync::Arc;

use time::OffsetDateTime;

use super::mapper::{fetch_procivis_schema, from_create_request};
use super::model::OpenID4VCICredentialConfigurationData;
use crate::mapper::credential_schema_claim::claim_schema_from_metadata_claim_schema;
use crate::model::credential_schema::{
    CredentialFormat, CredentialSchema, CredentialSchemaClaim, CredentialSchemaType, LayoutType,
};
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::BasicSchemaData;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper::parse_procivis_schema_claim;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::CreateCredentialSchemaRequestDTO;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::error::MissingProviderError;

pub(crate) struct HandleInvitationOperationsImpl {
    pub credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    pub http_client: Arc<dyn HttpClient>,
    pub formatter_provider: Arc<dyn CredentialFormatterProvider>,
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
        credential_config: &OpenID4VCICredentialConfigurationData,
        organisation: Organisation,
    ) -> Result<CredentialSchema, IssuanceProtocolError>;
}
pub(crate) type HandleInvitationOperationsAccess = dyn HandleInvitationOperations;

impl HandleInvitationOperationsImpl {
    pub(crate) fn new(
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        http_client: Arc<dyn HttpClient>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
    ) -> Self {
        Self {
            credential_schema_repository,
            http_client,
            formatter_provider,
        }
    }

    fn add_metadata_claim_schemas(
        &self,
        schema: &mut CredentialSchema,
    ) -> Result<(), IssuanceProtocolError> {
        let metadata_claims = get_metadata_claim_schemas(
            &*self.formatter_provider,
            schema.format.clone(),
            schema.created_date,
        )?;
        schema
            .claim_schemas
            .as_mut()
            .ok_or(IssuanceProtocolError::Failed(
                "Missing claim schemas".to_string(),
            ))?
            .extend(metadata_claims);
        Ok(())
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
        let external_schema = credential_config.procivis_schema.is_none();

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
            "dc+sd-jwt" => {
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
        credential_config: &OpenID4VCICredentialConfigurationData,
        organisation: Organisation,
    ) -> Result<CredentialSchema, IssuanceProtocolError> {
        let schema_url =
            credential_config
                .procivis_schema
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                "Missing procivis schema URL in credenetial configuration, can't create new schema"
                    .to_string(),
            ))?;

        let procivis_schema = fetch_procivis_schema(schema_url, &*self.http_client)
            .await
            .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;

        let mut schema = from_create_request(
            CreateCredentialSchemaRequestDTO {
                name: procivis_schema.name,
                format: procivis_schema.format,
                revocation_method: procivis_schema.revocation_method,
                external_schema: false,
                claims: procivis_schema
                    .claims
                    .clone()
                    .into_iter()
                    .map(parse_procivis_schema_claim)
                    .collect(),
                wallet_storage_type: procivis_schema.wallet_storage_type,
                layout_type: procivis_schema.layout_type.unwrap_or(LayoutType::Card),
                layout_properties: procivis_schema.layout_properties,
                schema_id: schema.id.to_string(),
                imported_source_url: schema_url.to_string(),
            },
            organisation.clone(),
            procivis_schema.schema_type,
        )
        .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?;
        self.add_metadata_claim_schemas(&mut schema)?;

        // Persist the schema to the database
        schema.organisation = Some(organisation);

        self.credential_schema_repository
            .create_credential_schema(schema.clone())
            .await
            .map_err(|_| {
                IssuanceProtocolError::Failed("Could not store credential schema".to_string())
            })?;

        Ok(schema)
    }
}

fn get_metadata_claim_schemas(
    formatter_provider: &dyn CredentialFormatterProvider,
    format: CredentialFormat,
    now: OffsetDateTime,
) -> Result<Vec<CredentialSchemaClaim>, IssuanceProtocolError> {
    let formatter = formatter_provider.get_credential_formatter(&format).ok_or(
        IssuanceProtocolError::Other(MissingProviderError::Formatter(format.to_string()).into()),
    )?;
    let metadata_claims = formatter
        .get_metadata_claims()
        .into_iter()
        .map(|metadata_claim| claim_schema_from_metadata_claim_schema(metadata_claim, now))
        .collect::<Vec<_>>();
    Ok(metadata_claims)
}
