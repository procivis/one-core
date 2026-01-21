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
use crate::model::did::KeyRole;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::proto::clock::Clock;
use crate::proto::jwt::JwtPublicKeyInfo;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{
    CreateSignatureRequestDTO, CreateSignatureResponseDTO, RevocationInfo,
};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::registration_certificate::model::{
    WRPRegistrationCertificate, WRPRegistrationCertificatePayload,
};
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};

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
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl RegistrationCertificate {
    pub fn new(
        params: Params,
        clock: Arc<dyn Clock>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            params,
            clock,
            revocation_method_provider,
            key_provider,
            key_algorithm_provider,
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
        issuer: Identifier,
        request: CreateSignatureRequestDTO,
        revocation_info: Option<RevocationInfo>,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        let now = self.clock.now_utc();
        let (nbf, exp) = self.nbf_and_exp(&request)?;
        let payload: model::RequestData = serde_json::from_value(request.data.clone())?;

        let (jwt_id, status) = match revocation_info {
            Some(RevocationInfo { id, status }) => (
                Uuid::from(id),
                Some(model::Status {
                    status_list: status.additional_fields,
                }),
            ),
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

        Ok(CreateSignatureResponseDTO {
            id: jwt_id,
            result: signed_jwt,
        })
    }

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_method_provider
            .get_revocation_method(self.params.revocation_method.as_ref()?)
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
        let selected_key = ident
            .select_key(KeySelection {
                key: request.issuer_key,
                key_filter: Some(KeyFilter::role_filter(KeyRole::AssertionMethod)),
                certificate: request.issuer_certificate,
                did: None,
            })
            .error_while("Selecting signing key")?;
        let result = match selected_key {
            SelectedKey::Key(key) => {
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

                (key.clone(), None, Some(JwtPublicKeyInfo::Jwk(pubkey)))
            }
            SelectedKey::Certificate { certificate, key } => {
                let pubkey_info = Some(JwtPublicKeyInfo::X5c(
                    pem_chain_into_x5c(&certificate.chain)
                        .map_err(|e| SignerError::MappingError(e.to_string()))?,
                ));
                (key.clone(), None, pubkey_info)
            }
            SelectedKey::Did { did, key } => {
                let key_id = did.verification_method_id(key);
                (key.key.clone(), Some(key_id), None)
            }
        };
        Ok(result)
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
        Ok(result)
    }
}
