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

use crate::config::core_config::{KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::certificate::{CertificateRelations, CertificateState};
use crate::model::did::{DidRelations, KeyFilter, KeyRole};
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
};
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierType};
use crate::model::key::{Key, KeyRelations};
use crate::proto::clock::Clock;
use crate::proto::jwt::JwtPublicKeyInfo;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequestDTO, CreateSignatureResponseDTO};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::registration_certificate::model::{
    WRPRegistrationCertificate, WRPRegistrationCertificatePayload,
};
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;

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
    pub max_validity_duration: i64,
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

    fn nbf_and_exp(
        &self,
        request: &CreateSignatureRequestDTO,
    ) -> Result<(OffsetDateTime, OffsetDateTime), SignerError> {
        let now = self.clock.now_utc();
        let max_validity_duration = Duration::seconds(self.params.payload.max_validity_duration);
        let nbf = match request.validity_start {
            None => now,
            Some(nbf) => {
                if nbf < now {
                    return Err(SignerError::ValidityBoundaryInThePast {
                        validity_boundary: nbf,
                    });
                }
                nbf
            }
        };
        let exp = match request.validity_end {
            None => nbf + max_validity_duration,
            Some(exp) => {
                if exp < now {
                    return Err(SignerError::ValidityBoundaryInThePast {
                        validity_boundary: exp,
                    });
                }
                if exp < nbf {
                    return Err(SignerError::ValidityStartAfterEnd {
                        validity_start: nbf,
                        validity_end: exp,
                    });
                }
                if exp - nbf > max_validity_duration {
                    return Err(SignerError::ValidityPeriodTooLong {
                        validity_start: nbf,
                        validity_end: exp,
                        max_duration: max_validity_duration,
                    });
                }
                exp
            }
        };
        Ok((nbf, exp))
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
            signing_key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::Dilithium,
                KeyAlgorithmType::BbsPlus,
            ],
            revocation_methods: vec![RevocationType::TokenStatusList],
        }
    }

    async fn sign(
        &self,
        request: CreateSignatureRequestDTO,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        let now = self.clock.now_utc();
        let (nbf, exp) = self.nbf_and_exp(&request)?;
        let payload: model::RequestData = serde_json::from_value(request.data.clone())?;
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
            .await
            .error_while("Loading issuer identifier")?
            .ok_or(SignerError::IdentifierNotFound(request.issuer))?;

        let issuer_certificate = if let Some(requested_certificate_id) = &request.issuer_certificate
        {
            Some(
                issuer
                    .certificates
                    .as_ref()
                    .ok_or(SignerError::NoActiveCertificates(request.issuer))?
                    .iter()
                    .find(|c| &c.id == requested_certificate_id)
                    .ok_or(SignerError::CertificateNotFound(*requested_certificate_id))?
                    .to_owned(),
            )
        } else if let Some(certificates) = &issuer.certificates {
            Some(
                certificates
                    .iter()
                    .find(|c| c.state == CertificateState::Active)
                    .ok_or(SignerError::NoActiveCertificates(request.issuer))?
                    .to_owned(),
            )
        } else {
            None
        };

        let (jwt_id, status) = match self.revocation.as_deref() {
            Some(list) => {
                let (list_entry_id, revocation_info) = list
                    .add_signature(
                        "REGISTRATION_CERTIFICATE".to_owned(),
                        &issuer,
                        &issuer_certificate,
                    )
                    .await
                    .error_while("Adding signature to revocation list")?;
                (
                    Uuid::from(list_entry_id),
                    Some(model::Status {
                        status_list: revocation_info.credential_status.additional_fields,
                    }),
                )
            }
            None => (Uuid::new_v4(), None),
        };
        let jwt_payload = WRPRegistrationCertificatePayload {
            issued_at: Some(now),
            expires_at: Some(exp),
            invalid_before: Some(nbf),
            issuer: None,
            subject: payload.subject.clone(),
            audience: self.params.payload.audience.clone(),
            jwt_id: Some(jwt_id.to_string()),
            proof_of_possession_key: None,
            custom: model::Payload {
                status,
                ..payload.into()
            },
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

    async fn revoke(&self, id: Uuid) -> Result<(), SignerError> {
        match self.revocation.as_deref() {
            Some(list) => list
                .revoke_signature(id.into())
                .await
                .error_while("revoking registration certificate")
                .map_err(SignerError::from),
            None => Err(SignerError::RevocationNotSupported),
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
        payload: WRPRegistrationCertificatePayload,
    ) -> Result<String, SignerError> {
        let (key, key_id, pubkey_info) = self.get_signing_key_for_identifier(issuer, request)?;

        let key_algorithm = key
            .key_algorithm_type()
            .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
            .ok_or_else(|| SignerError::MissingKeyAlgorithmProvider(key.key_type.to_owned()))?;

        let algorithm = key_algorithm
            .issuance_jose_alg_id()
            .ok_or(SignerError::MappingError("Missing JOSE alg".to_string()))?;

        let signer = self
            .key_provider
            .get_signature_provider(&key, None, self.key_algorithm_provider.clone())
            .error_while("getting signature provider")?;
        let jwt = WRPRegistrationCertificate::new(
            "rc-wrp+jwt".to_owned(),
            algorithm.to_owned(),
            key_id,
            pubkey_info,
            payload,
        );
        Ok(jwt
            .tokenize(Some(&*signer))
            .await
            .error_while("signing registration certificate")?)
    }

    fn get_signing_key_for_identifier(
        &self,
        ident: Identifier,
        request: &CreateSignatureRequestDTO,
    ) -> Result<(Key, Option<String>, Option<JwtPublicKeyInfo>), SignerError> {
        Ok(match ident.r#type {
            IdentifierType::Did => {
                let did = ident.did.ok_or(SignerError::MappingError(
                    "Missing identifier did".to_owned(),
                ))?;

                let key_filter = KeyFilter::role_filter(KeyRole::AssertionMethod);
                let assertion_key = match &request.issuer_key {
                    Some(requested_key) => did.find_key(requested_key, &key_filter),
                    None => did.find_first_matching_key(&key_filter),
                }
                .error_while("Retrieving assertion method key from DID")?
                .ok_or(SignerError::NoMatchingKeyOnDid {
                    did: Box::new(did.did.clone()),
                    filter: key_filter,
                })?;

                (
                    assertion_key.key.clone(),
                    Some(did.verification_method_id(assertion_key)),
                    None,
                )
            }
            IdentifierType::Key => {
                let key = ident.key.ok_or(SignerError::MappingError(
                    "Missing identifier key".to_owned(),
                ))?;

                if let Some(requested_key) = &request.issuer_key
                    && *requested_key != key.id
                {
                    return Err(SignerError::KeyNotFound(*requested_key));
                }

                let pubkey = key
                    .key_algorithm_type()
                    .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
                    .ok_or_else(|| {
                        SignerError::MissingKeyAlgorithmProvider(key.key_type.to_owned())
                    })?
                    .reconstruct_key(&key.public_key, None, None)
                    .error_while("Reconstructing signing key")?
                    .public_key_as_jwk()
                    .error_while("Converting signing key to JWK")?;

                (key, None, Some(JwtPublicKeyInfo::Jwk(pubkey)))
            }
            IdentifierType::Certificate => {
                let certs = ident.certificates.ok_or(SignerError::MappingError(
                    "Missing identifier certificates".to_owned(),
                ))?;

                let selected_cert = match &request.issuer_certificate {
                    Some(requested_id) => {
                        let requested_cert = certs
                            .into_iter()
                            .find(|cert| cert.id == *requested_id)
                            .ok_or(SignerError::CertificateNotFound(*requested_id))?;
                        if requested_cert.state != CertificateState::Active {
                            return Err(SignerError::CertificateNotActive(requested_cert.id));
                        }
                        requested_cert
                    }
                    None => certs
                        .into_iter()
                        .find(|cert| cert.state == CertificateState::Active)
                        .ok_or(SignerError::NoActiveCertificates(ident.id))?,
                };

                let key = selected_cert.key.ok_or(SignerError::MappingError(
                    "Missing key for certificate".to_owned(),
                ))?;
                let pubkey_info = Some(JwtPublicKeyInfo::X5c(
                    pem_chain_into_x5c(&selected_cert.chain)
                        .map_err(|e| SignerError::MappingError(e.to_string()))?,
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
        if Duration::seconds(result.payload.max_validity_duration) > Duration::days(365) {
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
