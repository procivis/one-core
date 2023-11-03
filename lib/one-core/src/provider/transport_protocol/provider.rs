use super::{dto::InvitationType, TransportProtocol};
use crate::common_mapper::get_algorithm_from_key_algorithm;
use crate::common_validator::throw_if_latest_credential_state_not_eq;
use crate::config::data_structure::CoreConfig;
use crate::crypto::Crypto;
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
use crate::provider::transport_protocol::dto::CreateCredentialResponseDTO;
use crate::provider::transport_protocol::mapper::from_credential_id_and_token;
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
    ) -> Result<CreateCredentialResponseDTO, ServiceError>;
}

pub(crate) struct TransportProtocolProviderImpl {
    pub(crate) protocols: HashMap<String, Arc<dyn TransportProtocol + Send + Sync>>,
    pub(crate) formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
    pub(crate) credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
    pub(crate) revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
    pub(crate) key_provider: Arc<dyn KeyProvider + Send + Sync>,
    pub(crate) config: Arc<CoreConfig>,
    pub(crate) crypto: Arc<Crypto>,
}

impl TransportProtocolProviderImpl {
    pub fn new(
        protocols: Vec<(String, Arc<dyn TransportProtocol + Send + Sync>)>,
        formatter_provider: Arc<dyn CredentialFormatterProvider + Send + Sync>,
        credential_repository: Arc<dyn CredentialRepository + Send + Sync>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider + Send + Sync>,
        key_provider: Arc<dyn KeyProvider + Send + Sync>,
        config: Arc<CoreConfig>,
        crypto: Arc<Crypto>,
    ) -> Self {
        Self {
            protocols: protocols.into_iter().collect(),
            formatter_provider,
            credential_repository,
            revocation_method_provider,
            key_provider,
            config,
            crypto,
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
            .get(protocol_key)
            .ok_or(ServiceError::MissingTransportProtocol(
                protocol_key.to_owned(),
            ))?
            .r#type;

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
    ) -> Result<CreateCredentialResponseDTO, ServiceError> {
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

        let algorithm = get_algorithm_from_key_algorithm(&key.key.key_type, &self.config)?;

        let signer = self
            .crypto
            .signers
            .get(&algorithm)
            .ok_or(ServiceError::MissingSigner(algorithm))?
            .clone();

        let key_provider = self.key_provider.get_key_storage(&key.key.storage_type)?;

        let private_key_moved = key_provider.decrypt_private_key(&key.key.private_key)?;
        let public_key_moved = key.key.public_key.clone();

        let auth_fn = Box::new(move |data: &str| {
            let signer = signer;
            let private_key = private_key_moved;
            let public_key = public_key_moved;
            signer.sign(data, &public_key, &private_key)
        });

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
            )?;

        self.credential_repository
            .update_credential(from_credential_id_and_token(credential_id, &token))
            .await?;

        Ok(CreateCredentialResponseDTO {
            credential: token,
            format,
        })
    }
}
