use std::sync::Arc;

use dto_mapper::convert_inner;
use one_providers::credential_formatter::provider::CredentialFormatterProvider;
use one_providers::did::provider::DidMethodProvider;
use one_providers::exchange_protocol::openid4vc::error::OpenID4VCIError;
use one_providers::exchange_protocol::openid4vc::model::SubmitIssuerResponse;
use one_providers::exchange_protocol::provider::ExchangeProtocolProvider;
use one_providers::key_storage::provider::KeyProvider;
use one_providers::revocation::model::CredentialAdditionalData;
use one_providers::revocation::provider::RevocationMethodProvider;
use shared_types::CredentialId;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::mapper::credential_accepted_history_event;
use super::ExchangeProtocol;
use crate::common_validator::get_latest_state;
use crate::config::core_config::CoreConfig;
use crate::config::ConfigValidationError;
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    CredentialRelations, CredentialStateEnum, CredentialStateRelations,
};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::{Did, DidRelations};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::revocation_list::RevocationListPurpose;
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::exchange_protocol::mapper::get_issued_credential_update;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::util::revocation_update::{get_revocation_list_id, process_update};

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
        fn detect_protocol(&self, url: &Url) -> Option<Arc<dyn ExchangeProtocol>>;
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
    history_repository: Arc<dyn HistoryRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
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
        history_repository: Arc<dyn HistoryRepository>,
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
            history_repository,
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
                return Err(ServiceError::BusinessLogic(
                    BusinessLogicError::InvalidCredentialState {
                        state: latest_state.to_owned(),
                    },
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

    fn detect_protocol(&self, url: &Url) -> Option<Arc<dyn ExchangeProtocol>> {
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
                    state: Some(CredentialStateRelations::default()),
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
                .get_credentials_by_issuer_did_id(
                    &issuer_did.id,
                    &CredentialRelations {
                        state: Some(CredentialStateRelations::default()),
                        ..Default::default()
                    },
                )
                .await?,
        );

        credential.holder_did = Some(holder_did.clone());

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(BusinessLogicError::MissingCredentialSchema)?
            .clone();
        let latest_credential_state = &get_latest_state(&credential)?.state;

        self.validate(credential_id, latest_credential_state, &credential_schema)
            .await?;

        let format = credential_schema.format.to_owned();

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(MissingProviderError::RevocationMethod(
                credential_schema.revocation_method.clone(),
            ))?;

        let (update, status) = revocation_method
            .add_issued_credential(
                &credential.to_owned().into(),
                Some(CredentialAdditionalData {
                    credentials_by_issuer_did: convert_inner(credentials_by_issuer_did.to_owned()),
                    revocation_list_id: get_revocation_list_id(
                        &credentials_by_issuer_did,
                        issuer_did,
                        RevocationListPurpose::Revocation,
                        &self.revocation_list_repository,
                        &self.key_provider,
                        &self.core_base_url,
                    )
                    .await?,
                    suspension_list_id: get_revocation_list_id(
                        &credentials_by_issuer_did,
                        issuer_did,
                        RevocationListPurpose::Suspension,
                        &self.revocation_list_repository,
                        &self.key_provider,
                        &self.core_base_url,
                    )
                    .await?,
                }),
            )
            .await?;
        if let Some(update) = update {
            process_update(
                update,
                &self.validity_credential_repository,
                &self.revocation_list_repository,
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

        let did_document = self
            .did_method_provider
            .resolve(&issuer_did_value.to_owned().into())
            .await?;
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

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.to_owned(), Some(issuer_jwk_key_id))?;

        let redirect_uri = credential.redirect_uri.to_owned();

        let core_base_url = self.core_base_url.as_ref().ok_or(ServiceError::Other(
            "Missing core_base_url for credential issuance".to_string(),
        ))?;

        let organisation = credential_schema
            .organisation
            .ok_or(ServiceError::MappingError(
                "Missing organisation".to_owned(),
            ))?;

        // TODO - remove organisation usage from here when moved to open core
        let credential_detail =
            credential_detail_response_from_model(credential.clone(), &self.config, &organisation)?;
        let credential_data = credential_data_from_credential_detail_response(
            &self.config,
            credential_detail,
            core_base_url,
            credential_status,
        )?;

        let json_ld_context = revocation_method.get_json_ld_context()?;

        let token = self
            .formatter_provider
            .get_formatter(&format)
            .ok_or(ValidationError::InvalidFormatter(format.to_string()))?
            .format_credentials(
                credential_data,
                &holder_did.did.clone().into(),
                &key.key_type,
                vec![],
                vec![],
                auth_fn,
                json_ld_context.url,
                None,
            )
            .await?;

        match (credential_schema.format.as_str(), latest_credential_state) {
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

                let _ = self
                    .history_repository
                    .create_history(credential_accepted_history_event(credential))
                    .await;

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

                let _ = self
                    .history_repository
                    .create_history(credential_accepted_history_event(credential))
                    .await;
            }
        }

        Ok(SubmitIssuerResponse {
            credential: token,
            format,
            redirect_uri,
        })
    }
}
