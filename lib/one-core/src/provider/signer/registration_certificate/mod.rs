pub mod model;
#[cfg(test)]
mod test;

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde::de::Error;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::certificate::{CertificateRelations, CertificateState};
use crate::model::did::{DidRelations, KeyFilter, KeyRole};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierType};
use crate::model::key::{Key, KeyRelations};
use crate::proto::clock::Clock;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequestDTO, CreateSignatureResponseDTO};
use crate::provider::signer::model::SignerCapabilities;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::service::error::{
    EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub payload: PayloadParams,
    pub revocation_method: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadParams {
    pub issuer: Option<Url>,
    pub audience: Option<Vec<String>>,
    pub expiry: i64,
}

pub struct RegistrationCertificate {
    params: Params,
    clock: Arc<dyn Clock>,
    revocation: Option<Arc<dyn RevocationMethod>>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    history: Arc<dyn HistoryRepository>,
}

impl RegistrationCertificate {
    pub fn new(
        params: Params,
        clock: Arc<dyn Clock>,
        revocation: Option<Arc<dyn RevocationMethod>>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        history: Arc<dyn HistoryRepository>,
    ) -> Self {
        Self {
            params,
            clock,
            revocation,
            key_provider,
            key_algorithm_provider,
            identifier_repository,
            history,
        }
    }
}

#[async_trait]
impl Signer for RegistrationCertificate {
    fn get_capabilities(&self) -> SignerCapabilities {
        use crate::config::core_config::IdentifierType;

        SignerCapabilities {
            supported_identifiers: vec![
                IdentifierType::Certificate,
                IdentifierType::Did,
                IdentifierType::Key,
            ],
            sign_required_permissions: vec!["REGISTRATION_CERTIFICATE_CREATE"],
            revoke_required_permissions: vec!["REGISTRATION_CERTIFICATE_REVOKE"],
        }
    }

    async fn sign(
        &self,
        request: CreateSignatureRequestDTO,
    ) -> Result<CreateSignatureResponseDTO, ServiceError> {
        let now = self.clock.now_utc();

        let payload: model::Payload =
            serde_json::from_value(request.data.clone()).map_err(|e| {
                ServiceError::Validation(ValidationError::DeserializationError(e.to_string()))
            })?;
        let payload_name = payload.name.clone();

        let issuer = self
            .identifier_repository
            .get(
                request.issuer,
                &IdentifierRelations {
                    organisation: None,
                    did: Some(DidRelations {
                        keys: Some(KeyRelations { organisation: None }),
                        organisation: None,
                    }),
                    key: Some(KeyRelations { organisation: None }),
                    certificates: Some(CertificateRelations {
                        key: Some(KeyRelations { organisation: None }),
                        organisation: None,
                    }),
                },
            )
            .await?
            .ok_or(ServiceError::EntityNotFound(
                EntityNotFoundError::Identifier(request.issuer),
            ))?;

        let jwt_id = match self.revocation.as_deref() {
            Some(list) => {
                let list_entry_id = list
                    .add_signature("REGISTRATION_CERTIFICATE".to_owned(), &issuer)
                    .await?;
                Uuid::from(list_entry_id)
            }
            None => Uuid::new_v4(),
        };
        let jwt_payload = JWTPayload::<model::Payload> {
            issued_at: Some(now),
            expires_at: Some(now + Duration::seconds(self.params.payload.expiry)),
            invalid_before: None,
            issuer: None,
            subject: None,
            audience: self.params.payload.audience.clone(),
            jwt_id: Some(jwt_id.to_string()),
            proof_of_possession_key: None,
            custom: payload,
        };
        let signed_jwt = self
            .create_and_sign_jwt(&request, issuer, jwt_payload)
            .await?;

        if let Err(error) = self
            .history
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now,
                source: HistorySource::Core,
                action: HistoryAction::Created,
                entity_id: Some(jwt_id.into()),
                entity_type: HistoryEntityType::Signature,
                metadata: Some(HistoryMetadata::External(request.data)),
                name: payload_name,
                target: None,
                organisation_id: None,
                user: None,
            })
            .await
        {
            tracing::warn!("Failed to write history entry: {}", error);
        }

        Ok(CreateSignatureResponseDTO {
            id: jwt_id,
            result: signed_jwt,
        })
    }

    async fn revoke(&self, id: Uuid) -> Result<(), ServiceError> {
        match self.revocation.as_deref() {
            Some(list) => {
                list.revoke_signature("REGISTRATION_CERTIFICATE".to_owned(), id.into())
                    .await
            }
            None => Err(RevocationError::OperationNotSupported(
                "No revocation method configured for REGISTRATION_CERTIFICATE".to_string(),
            )),
        }?;

        if let Err(error) = self
            .history
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: OffsetDateTime::now_utc(),
                source: HistorySource::Core,
                action: HistoryAction::Revoked,
                entity_id: Some(id.into()),
                entity_type: HistoryEntityType::Signature,
                metadata: None,
                name: "".to_owned(),
                target: None,
                organisation_id: None,
                user: None,
            })
            .await
        {
            tracing::warn!("Failed to write history entry: {}", error);
        }

        Ok(())
    }
}

impl RegistrationCertificate {
    async fn create_and_sign_jwt(
        &self,
        request: &CreateSignatureRequestDTO,
        issuer: Identifier,
        payload: JWTPayload<model::Payload>,
    ) -> Result<String, ServiceError> {
        let (key, key_id, pubkey_info) = self.get_signing_key_for_identifier(issuer, request)?;

        let key_algorithm = key
            .key_algorithm_type()
            .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
            .ok_or_else(|| {
                ServiceError::MissingProvider(MissingProviderError::KeyAlgorithmProvider(
                    KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                        key.key_type.to_owned(),
                    ),
                ))
            })?;

        let algorithm = key_algorithm
            .issuance_jose_alg_id()
            .ok_or(ServiceError::MappingError("Missing JOSE alg".to_string()))?;

        let signer = self.key_provider.get_signature_provider(
            &key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let jwt = Jwt::new(
            "rc-wrp+jwt".to_owned(),
            algorithm.to_owned(),
            key_id,
            pubkey_info,
            payload,
        );
        Ok(jwt.tokenize(Some(&*signer)).await?)
    }

    fn get_signing_key_for_identifier(
        &self,
        ident: Identifier,
        request: &CreateSignatureRequestDTO,
    ) -> Result<(Key, Option<String>, Option<JwtPublicKeyInfo>), ServiceError> {
        Ok(match ident.r#type {
            IdentifierType::Did => {
                let did = ident.did.ok_or(ServiceError::MappingError(
                    "Missing identifier did".to_owned(),
                ))?;

                let assertion_key = match &request.issuer_key {
                    Some(requested_key) => did.find_key(
                        requested_key,
                        &KeyFilter::role_filter(KeyRole::AssertionMethod),
                    ),
                    None => did
                        .find_first_matching_key(&KeyFilter::role_filter(KeyRole::AssertionMethod)),
                }?
                .ok_or(ValidationError::KeyNotFound)?;

                (
                    assertion_key.key.clone(),
                    Some(did.verification_method_id(assertion_key)),
                    None,
                )
            }
            IdentifierType::Key => {
                let key = ident.key.ok_or(ServiceError::MappingError(
                    "Missing identifier key".to_owned(),
                ))?;

                if let Some(requested_key) = &request.issuer_key
                    && *requested_key != key.id
                {
                    return Err(ServiceError::EntityNotFound(EntityNotFoundError::Key(
                        *requested_key,
                    )));
                }

                let pubkey = key
                    .key_algorithm_type()
                    .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
                    .ok_or_else(|| {
                        ServiceError::MissingProvider(MissingProviderError::KeyAlgorithmProvider(
                            KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                                key.key_type.to_owned(),
                            ),
                        ))
                    })?
                    .reconstruct_key(&key.public_key, None, None)
                    .map_err(|e| ServiceError::MappingError(e.to_string()))?
                    .public_key_as_jwk()
                    .map_err(|e| ServiceError::MappingError(e.to_string()))?;

                (key, None, Some(JwtPublicKeyInfo::Jwk(pubkey.into())))
            }
            IdentifierType::Certificate => {
                let certs = ident.certificates.ok_or(ServiceError::MappingError(
                    "Missing identifier certificates".to_owned(),
                ))?;

                let selected_cert = match &request.issuer_certificate {
                    Some(requested_id) => {
                        let requested_cert = certs
                            .into_iter()
                            .find(|cert| cert.id == *requested_id)
                            .ok_or(ServiceError::EntityNotFound(
                                EntityNotFoundError::Certificate(*requested_id),
                            ))?;
                        if requested_cert.state != CertificateState::Active {
                            return Err(ServiceError::Other(
                                "Certificate is not active".to_owned(),
                            ));
                        }
                        requested_cert
                    }
                    None => certs
                        .into_iter()
                        .find(|cert| cert.state == CertificateState::Active)
                        .ok_or(ServiceError::Other(
                            "No valid certificates found".to_owned(),
                        ))?,
                };

                let key = selected_cert.key.ok_or(ServiceError::MappingError(
                    "Missing key for certificate".to_owned(),
                ))?;
                let pubkey_info = Some(JwtPublicKeyInfo::X5c(
                    pem_chain_into_x5c(&selected_cert.chain)
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?,
                ));
                (key, None, pubkey_info)
            }
        })
    }
}

impl TryFrom<Option<&crate::config::core_config::Params>> for Params {
    type Error = serde_json::error::Error;

    fn try_from(params: Option<&crate::config::core_config::Params>) -> Result<Self, Self::Error> {
        let result = match params.and_then(|inner| inner.merge()) {
            Some(merged) => serde_json::from_value::<Self>(merged)?,
            None => return Err(Error::missing_field("payload.duration")),
        };

        // GEN-5.2.4-08: The `exp` field in the WRPRC payload shall indicate a time not later than
        // 12 months after the issuance time specified in the `iat` field specified in GEN-5.2.4-01.
        if Duration::seconds(result.payload.expiry) > Duration::days(365) {
            return Err(Error::custom(
                "expiry cannot occur later than 12 months after issuance (GEN-5.2.4-08)",
            ));
        }

        // Currently, we support only Token Status List
        if let Some(rev) = &result.revocation_method
            && rev.as_str() != "TOKENSTATUSLIST"
        {
            return Err(Error::unknown_variant(rev, &["TOKENSTATUSLIST"]));
        };

        Ok(result)
    }
}
