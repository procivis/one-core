use std::sync::Arc;

use one_dto_mapper::convert_inner;
use shared_types::CredentialId;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::ExchangeProtocolImpl;
use crate::config::core_config::CoreConfig;
use crate::config::ConfigValidationError;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{CredentialRelations, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::{Did, DidRelations, KeyRole};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::revocation_list::{RevocationListPurpose, StatusListType};
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::mapper::get_issued_credential_update;
use crate::provider::exchange_protocol::openid4vc::error::OpenID4VCIError;
use crate::provider::exchange_protocol::openid4vc::model::SubmitIssuerResponse;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::bitstring_status_list::Params;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::CredentialAdditionalData;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::revocation::token_status_list;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::util::params::convert_params;
use crate::util::revocation_update::{get_or_create_revocation_list_id, process_update};
use crate::util::vcdm_jsonld_contexts::{vcdm_type, vcdm_v2_base_context};

pub trait ExchangeProtocol:
    ExchangeProtocolImpl<
    VCInteractionContext = serde_json::Value,
    VPInteractionContext = serde_json::Value,
>
{
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ExchangeProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>>;
    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn ExchangeProtocol>)>;
}

#[async_trait::async_trait]
pub(crate) trait ExchangeProtocolProviderExtra: ExchangeProtocolProvider {
    async fn issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_did: Did,
    ) -> Result<SubmitIssuerResponse, ServiceError>;
}

#[cfg(test)]
mockall::mock! {
    pub ExchangeProtocolProviderExtra {}

    #[async_trait::async_trait]
    impl ExchangeProtocolProvider for ExchangeProtocolProviderExtra {
        fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>>;
        fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn ExchangeProtocol>)>;
    }

    #[async_trait::async_trait]
    impl ExchangeProtocolProviderExtra for ExchangeProtocolProviderExtra {
        async fn issue_credential(
            &self,
            credential_id: &CredentialId,
            holder_did: Did,
        ) -> Result<SubmitIssuerResponse, ServiceError>;
    }
}

pub(crate) struct ExchangeProtocolProviderCoreImpl {
    inner: Arc<dyn ExchangeProtocolProvider>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    config: Arc<CoreConfig>,
    core_base_url: Option<String>,
}

#[allow(clippy::too_many_arguments)]
impl ExchangeProtocolProviderCoreImpl {
    pub fn new(
        inner: Arc<dyn ExchangeProtocolProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        credential_repository: Arc<dyn CredentialRepository>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        config: Arc<CoreConfig>,
        core_base_url: Option<String>,
    ) -> Self {
        Self {
            inner,
            formatter_provider,
            credential_repository,
            revocation_method_provider,
            key_provider,
            key_algorithm_provider,
            did_method_provider,
            revocation_list_repository,
            validity_credential_repository,
            config,
            core_base_url,
        }
    }

    fn mso_expected_update_in(&self) -> Result<Duration, ConfigValidationError> {
        self.config
            .format
            .get::<mdoc_formatter::Params>("MDOC")
            .map(|p| p.mso_expected_update_in)
    }

    async fn validate(
        &self,
        credential_id: &CredentialId,
        latest_state: &CredentialStateEnum,
        credential_schema: &CredentialSchema,
    ) -> Result<(), ServiceError> {
        match (latest_state, credential_schema.format.as_str()) {
            (CredentialStateEnum::Accepted, "MDOC") => {
                let mdoc_validity_credentials = self
                    .validity_credential_repository
                    .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                    .await?
                    .ok_or_else(|| {
                        ServiceError::Other(format!(
                            "Missing verifiable credential for MDOC: {credential_id}"
                        ))
                    })?;

                let mso_expected_update_in = self.mso_expected_update_in()?;
                let can_be_updated_at =
                    mdoc_validity_credentials.created_date + mso_expected_update_in;

                if can_be_updated_at > OffsetDateTime::now_utc() {
                    return Err(ServiceError::OpenID4VCIError(
                        OpenID4VCIError::InvalidRequest,
                    ));
                }
            }
            (CredentialStateEnum::Offered, _) => {}
            _ => {
                return Err(ServiceError::OpenID4VCIError(
                    OpenID4VCIError::CredentialRequestDenied,
                ))
            }
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl ExchangeProtocolProvider for ExchangeProtocolProviderCoreImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>> {
        self.inner.get_protocol(protocol_id)
    }

    fn detect_protocol(&self, url: &Url) -> Option<(String, Arc<dyn ExchangeProtocol>)> {
        self.inner.detect_protocol(url)
    }
}

#[async_trait::async_trait]
impl ExchangeProtocolProviderExtra for ExchangeProtocolProviderCoreImpl {
    async fn issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_did: Did,
    ) -> Result<SubmitIssuerResponse, ServiceError> {
        let Some(mut credential) = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(EntityNotFoundError::Credential(*credential_id).into());
        };

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer_did is None".to_string()))?;

        let credentials_by_issuer_did = convert_inner(
            self.credential_repository
                .get_credentials_by_issuer_did_id(&issuer_did.id, &CredentialRelations::default())
                .await?,
        );

        credential.holder_did = Some(holder_did.clone());

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(BusinessLogicError::MissingCredentialSchema)?
            .clone();
        let credential_state = credential.state;

        self.validate(credential_id, &credential_state, &credential_schema)
            .await?;

        let format = credential_schema.format.to_owned();

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(MissingProviderError::RevocationMethod(
                credential_schema.revocation_method.clone(),
            ))?;

        let did_document = self.did_method_provider.resolve(&issuer_did.did).await?;
        let key_id = did_document
            .find_verification_method(None, Some(KeyRole::AssertionMethod))
            .ok_or(ServiceError::Revocation(
                RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod),
            ))?
            .id
            .to_owned();

        let mut credential_additional_data = None;

        // TODO: refactor this when refactoring the formatters as it makes no sense for to construct this for LVVC
        if credential_schema.revocation_method == StatusListType::BitstringStatusList.to_string() {
            let Params { format } = convert_params(revocation_method.get_params()?)?;

            let formatter = self
                .formatter_provider
                .get_formatter(&format.to_string())
                .ok_or(ValidationError::InvalidFormatter(format.to_string()))?;

            credential_additional_data = Some(CredentialAdditionalData {
                credentials_by_issuer_did: convert_inner(credentials_by_issuer_did.to_owned()),
                revocation_list_id: get_or_create_revocation_list_id(
                    &credentials_by_issuer_did,
                    issuer_did,
                    RevocationListPurpose::Revocation,
                    &*self.revocation_list_repository,
                    &self.key_provider,
                    &self.key_algorithm_provider,
                    &self.core_base_url,
                    &*formatter,
                    key_id.clone(),
                    &StatusListType::BitstringStatusList,
                    &format,
                )
                .await?,
                suspension_list_id: Some(
                    get_or_create_revocation_list_id(
                        &credentials_by_issuer_did,
                        issuer_did,
                        RevocationListPurpose::Suspension,
                        &*self.revocation_list_repository,
                        &self.key_provider,
                        &self.key_algorithm_provider,
                        &self.core_base_url,
                        &*formatter,
                        key_id,
                        &StatusListType::BitstringStatusList,
                        &format,
                    )
                    .await?,
                ),
            });
        } else if credential_schema.revocation_method == StatusListType::TokenStatusList.to_string()
        {
            let token_status_list::Params { format } =
                convert_params(revocation_method.get_params()?).unwrap_or_default();

            let formatter = self
                .formatter_provider
                .get_formatter(&format.to_string())
                .ok_or(ValidationError::InvalidFormatter(format.to_string()))?;

            credential_additional_data = Some(CredentialAdditionalData {
                credentials_by_issuer_did: convert_inner(credentials_by_issuer_did.to_owned()),
                revocation_list_id: get_or_create_revocation_list_id(
                    &credentials_by_issuer_did,
                    issuer_did,
                    RevocationListPurpose::Revocation,
                    &*self.revocation_list_repository,
                    &self.key_provider,
                    &self.key_algorithm_provider,
                    &self.core_base_url,
                    &*formatter,
                    key_id.clone(),
                    &StatusListType::TokenStatusList,
                    &format,
                )
                .await?,
                suspension_list_id: None,
            });
        }

        let (update, status) = revocation_method
            .add_issued_credential(&credential, credential_additional_data)
            .await?;

        if let Some(update) = update {
            process_update(
                update,
                &*self.validity_credential_repository,
                &*self.revocation_list_repository,
            )
            .await?;
        }

        let credential_status = status
            .into_iter()
            .map(|revocation_info| revocation_info.credential_status)
            .collect();

        let key = credential
            .key
            .as_ref()
            .ok_or(ServiceError::Other("Missing Key".to_owned()))?;

        let issuer_did_value = &credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::Other("Missing issuer did".to_string()))?
            .did;

        let did_document = self.did_method_provider.resolve(issuer_did_value).await?;
        let assertion_methods = did_document
            .assertion_method
            .ok_or(ServiceError::MappingError(
                "Missing assertion_method keys".to_owned(),
            ))?;

        let issuer_jwk_key_id = match assertion_methods
            .iter()
            .find(|id| id.contains(&key.id.to_string()))
            .cloned()
        {
            Some(id) => id,
            None => assertion_methods
                .first()
                .ok_or(ServiceError::MappingError(
                    "Missing first assertion_method key".to_owned(),
                ))?
                .to_owned(),
        };

        let auth_fn = self.key_provider.get_signature_provider(
            &key.to_owned(),
            Some(issuer_jwk_key_id),
            self.key_algorithm_provider.clone(),
        )?;

        let redirect_uri = credential.redirect_uri.to_owned();

        let core_base_url = self.core_base_url.as_ref().ok_or(ServiceError::Other(
            "Missing core_base_url for credential issuance".to_string(),
        ))?;

        // TODO - remove organisation usage from here when moved to open core
        let credential_detail =
            credential_detail_response_from_model(credential.clone(), &self.config, None)?;
        let credential_data = credential_data_from_credential_detail_response(
            credential_detail,
            core_base_url,
            credential_status,
        )?;

        let additional_contexts = revocation_method
            .get_json_ld_context()?
            .url
            .map(|ctx| ctx.parse().map(|ctx| vec![ContextType::Url(ctx)]))
            .transpose()
            .map_err(|_err| {
                ServiceError::Other("Provided JSON-LD context URL is not a valid URL".to_owned())
            })?;

        let contexts = vcdm_v2_base_context(additional_contexts);

        let token = self
            .formatter_provider
            .get_formatter(&format)
            .ok_or(ValidationError::InvalidFormatter(format.to_string()))?
            .format_credentials(
                credential_data,
                &Some(holder_did.did),
                contexts,
                vcdm_type(None),
                auth_fn,
            )
            .await?;

        match (credential_schema.format.as_str(), credential_state) {
            ("MDOC", CredentialStateEnum::Accepted) => {
                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: OffsetDateTime::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await?;
            }
            ("MDOC", CredentialStateEnum::Offered) => {
                self.credential_repository
                    .update_credential(get_issued_credential_update(
                        credential_id,
                        &token,
                        holder_did.id,
                    ))
                    .await?;

                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: OffsetDateTime::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await?;
            }
            _ => {
                self.credential_repository
                    .update_credential(get_issued_credential_update(
                        credential_id,
                        &token,
                        holder_did.id,
                    ))
                    .await?;
            }
        }

        Ok(SubmitIssuerResponse {
            credential: token,
            redirect_uri,
        })
    }
}
