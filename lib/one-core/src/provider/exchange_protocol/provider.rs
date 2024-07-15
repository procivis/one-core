use std::collections::HashMap;
use std::sync::Arc;

use one_providers::key_storage::provider::KeyProvider;
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
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::{mdoc_formatter, CredentialData};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::dto::SubmitIssuerResponse;
use crate::provider::exchange_protocol::mapper::get_issued_credential_update;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::oidc::dto::OpenID4VCIError;

#[derive(Clone)]
pub struct DetectedProtocol {
    pub protocol: Arc<dyn ExchangeProtocol>,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait ExchangeProtocolProvider: Send + Sync {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>>;

    fn detect_protocol(&self, url: &Url) -> Option<DetectedProtocol>;

    async fn issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_did: Did,
    ) -> Result<SubmitIssuerResponse, ServiceError>;
}

pub(crate) struct ExchangeProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn ExchangeProtocol>>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    config: Arc<CoreConfig>,
    core_base_url: Option<String>,
}

#[allow(clippy::too_many_arguments)]
impl ExchangeProtocolProviderImpl {
    pub fn new(
        protocols: HashMap<String, Arc<dyn ExchangeProtocol>>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        credential_repository: Arc<dyn CredentialRepository>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        history_repository: Arc<dyn HistoryRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        config: Arc<CoreConfig>,
        core_base_url: Option<String>,
    ) -> Self {
        Self {
            protocols,
            formatter_provider,
            credential_repository,
            revocation_method_provider,
            key_provider,
            history_repository,
            did_method_provider,
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
                    return Err(ServiceError::OpenID4VCError(
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
impl ExchangeProtocolProvider for ExchangeProtocolProviderImpl {
    fn get_protocol(&self, protocol_id: &str) -> Option<Arc<dyn ExchangeProtocol>> {
        self.protocols.get(protocol_id).cloned()
    }

    fn detect_protocol(&self, url: &Url) -> Option<DetectedProtocol> {
        self.protocols
            .values()
            .find(|protocol| protocol.can_handle(url))
            .map(|protocol| DetectedProtocol {
                protocol: protocol.to_owned(),
            })
    }

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

        credential.holder_did = Some(holder_did.clone());

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(BusinessLogicError::MissingCredentialSchema)?;
        let latest_credential_state = &get_latest_state(&credential)?.state;

        self.validate(credential_id, latest_credential_state, credential_schema)
            .await?;

        let format = credential_schema.format.to_owned();

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(MissingProviderError::RevocationMethod(
                credential_schema.revocation_method.clone(),
            ))?;

        let credential_status = revocation_method
            .add_issued_credential(&credential)
            .await?
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

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.to_owned().into(), Some(issuer_jwk_key_id))?;

        let redirect_uri = credential.redirect_uri.to_owned();

        let core_base_url = self.core_base_url.as_ref().ok_or(ServiceError::Other(
            "Missing core_base_url for credential issuance".to_string(),
        ))?;

        let credential_detail =
            credential_detail_response_from_model(credential.clone(), &self.config)?;
        let credential_data = CredentialData::from_credential_detail_response(
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
                &holder_did.did,
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
