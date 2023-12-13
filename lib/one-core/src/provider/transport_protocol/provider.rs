use super::{dto::InvitationType, TransportProtocol};
use crate::common_validator::throw_if_latest_credential_state_not_eq;
use crate::config::core_config::{self};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    CredentialId, CredentialRelations, CredentialStateEnum, CredentialStateRelations,
};
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyRole};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::transport_protocol::dto::SubmitIssuerResponse;
use crate::provider::transport_protocol::mapper::get_issued_credential_update;
use crate::repository::credential_repository::CredentialRepository;
use crate::service::error::ServiceError;
use std::{collections::HashMap, sync::Arc};
use url::Url;

#[derive(Clone)]
pub struct DetectedProtocol {
    pub invitation_type: InvitationType,
    pub protocol: Arc<dyn TransportProtocol + Send + Sync>,
}

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait TransportProtocolProvider {
    fn get_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, ServiceError>;

    fn get_protocol_by_config_key(
        &self,
        protocol_config_key: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, ServiceError>;

    fn detect_protocol(&self, url: &Url) -> Option<DetectedProtocol>;

    async fn issue_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<SubmitIssuerResponse, ServiceError>;
}

pub(crate) struct TransportProtocolProviderImpl {
    protocols: HashMap<String, Arc<dyn TransportProtocol + Send + Sync>>,
    formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
    key_provider: Arc<dyn KeyProvider + Send + Sync>,
    config: Arc<core_config::CoreConfig>,
}

impl TransportProtocolProviderImpl {
    pub fn new(
        protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
        key_provider: Arc<dyn KeyProvider + Send + Sync>,
        config: Arc<core_config::CoreConfig>,
    ) -> Self {
        Self {
            protocols: protocols.into_iter().collect(),
            formatter_provider,
            credential_repository,
            revocation_method_provider,
            key_provider,
            config,
        }
    }
}

#[async_trait::async_trait]
impl TransportProtocolProvider for TransportProtocolProviderImpl {
    fn get_protocol(
        &self,
        protocol_id: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, ServiceError> {
        Ok(self
            .protocols
            .get(protocol_id)
            .ok_or(ServiceError::NotFound)?
            .to_owned())
    }

    fn get_protocol_by_config_key(
        &self,
        protocol_key: &str,
    ) -> Result<Arc<dyn TransportProtocol + Send + Sync>, ServiceError> {
        let transport_instance = &self
            .config
            .exchange
            .get_fields(protocol_key)
            .map_err(|err| ServiceError::MissingTransportProtocol(err.to_string()))?
            .r#type();

        self.get_protocol(transport_instance)
    }

    fn detect_protocol(&self, url: &Url) -> Option<DetectedProtocol> {
        for protocol in self.protocols.values() {
            if let Some(invitation_type) = protocol.detect_invitation_type(url) {
                return Some(DetectedProtocol {
                    invitation_type,
                    protocol: protocol.to_owned(),
                });
            }
        }
        None
    }

    async fn issue_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<SubmitIssuerResponse, ServiceError> {
        let credential = self
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
                    holder_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Offered)?;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let holder_did = credential
            .holder_did
            .as_ref()
            .ok_or(ServiceError::MappingError("holder did is None".to_string()))?
            .clone();

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?
            .clone();

        let format = credential_schema.format.to_owned();

        let revocation_method = self
            .revocation_method_provider
            .get_revocation_method(&credential_schema.revocation_method)?;
        let (credential_status, additional_context) =
            match revocation_method.add_issued_credential(&credential).await? {
                None => (None, vec![]),
                Some(revocation_info) => (
                    Some(revocation_info.credential_status),
                    revocation_info.additional_vc_contexts,
                ),
            };

        let keys = issuer_did
            .keys
            .as_ref()
            .ok_or(ServiceError::MappingError("Issuer has no keys".to_string()))?;

        let key = keys
            .iter()
            .find(|k| k.role == KeyRole::AssertionMethod)
            .ok_or(ServiceError::Other("Missing Key".to_owned()))?;

        let auth_fn = self.key_provider.get_signature_provider(&key.key)?;

        let redirect_uri = credential.redirect_uri.to_owned();

        let token: String = self
            .formatter_provider
            .get_formatter(&format)?
            .format_credentials(
                &credential.try_into()?,
                credential_status,
                &holder_did.did,
                &key.key.key_type,
                additional_context,
                vec![],
                auth_fn,
            )
            .await?;

        self.credential_repository
            .update_credential(get_issued_credential_update(
                credential_id,
                &token,
                &key.key,
            ))
            .await?;

        Ok(SubmitIssuerResponse {
            credential: token,
            format,
            redirect_uri,
        })
    }
}
