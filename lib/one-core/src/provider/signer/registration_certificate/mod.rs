pub mod model;
#[cfg(test)]
mod test;

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde::de::Error;
use shared_types::{Permission, RevocationMethodId};
use time::Duration;
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
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::registration_certificate::model::{
    Status, WRPRegistrationCertificate, WRPRegistrationCertificatePayload,
};
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};
use crate::validator::permissions::RequiredPermssions;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub payload: PayloadParams,
    pub revocation_method: Option<RevocationMethodId>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadParams {
    pub issuer: Option<Url>,
    pub audience: Option<Vec<String>>,
    pub max_validity_duration: i64,
}

pub struct RegistrationCertificate {
    config_key: String,
    params: Params,
    clock: Arc<dyn Clock>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    session_provider: Arc<dyn SessionProvider>,
}

impl RegistrationCertificate {
    pub fn new(
        config_name: String,
        params: Params,
        clock: Arc<dyn Clock>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            config_key: config_name,
            params,
            clock,
            revocation_method_provider,
            key_provider,
            key_algorithm_provider,
            session_provider,
        }
    }

    async fn handle_revocation(
        &self,
        identifier: &Identifier,
        selected_key: &SelectedKey<'_>,
    ) -> Result<Option<(Uuid, Option<Status>)>, SignerError> {
        Ok(if let Some(revocation_method) = self.revocation_method() {
            let (id, revocation_info) = revocation_method
                .add_signature(
                    self.config_key.clone(),
                    identifier,
                    selected_key.certificate(),
                )
                .await
                .error_while("Adding signature to revocation list")?;
            Some((
                Uuid::from(id),
                Some(Status {
                    status_list: revocation_info.credential_status.additional_fields,
                }),
            ))
        } else {
            None
        })
    }
}

#[async_trait]
impl Signer for RegistrationCertificate {
    fn get_capabilities(&self) -> SignerCapabilities {
        use crate::config::core_config::IdentifierType;
        SignerCapabilities {
            features: vec![],
            supported_identifiers: vec![IdentifierType::Certificate],
            sign_required_permissions: vec![Permission::RegistrationCertificateCreate],
            revoke_required_permissions: vec![Permission::RegistrationCertificateRevoke],
            signing_key_algorithms: vec![
                KeyAlgorithmType::Ecdsa,
                KeyAlgorithmType::Eddsa,
                KeyAlgorithmType::MlDsa,
                KeyAlgorithmType::BbsPlus,
            ],
            revocation_methods: vec![RevocationType::TokenStatusList],
        }
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        // Check permissions in provider because internal calls for `Issuer::Key` do _not_ go through the service
        RequiredPermssions::at_least_one(self.get_capabilities().sign_required_permissions)
            .check(&*self.session_provider)
            .error_while("validating provider required permissions")?;

        let now = self.clock.now_utc();
        let SignatureValidity { start, end } = calculate_signature_validity(
            Duration::seconds(self.params.payload.max_validity_duration),
            &request,
        )?;
        let payload: model::RequestData = serde_json::from_value(request.data.clone())?;

        let Issuer::Identifier {
            identifier,
            certificate,
            key,
        } = issuer
        else {
            return Err(SignerError::KeyIssuerNotSupported);
        };
        let selected_key = identifier
            .select_key(KeySelection {
                key,
                key_filter: Some(KeyFilter::role_filter(KeyRole::AssertionMethod)),
                certificate,
                did: None,
            })
            .error_while("Selecting signing key")?;

        let revocation_info = self.handle_revocation(&identifier, &selected_key).await?;
        let SelectedKey::Certificate { certificate, key } = selected_key else {
            return Err(SignerError::InvalidIssuerIdentifier(identifier.id));
        };
        let pubkey_info = Some(JwtPublicKeyInfo::X5c(
            pem_chain_into_x5c(&certificate.chain)
                .map_err(|e| SignerError::MappingError(e.to_string()))?,
        ));

        let (jwt_id, status) = revocation_info.unwrap_or((Uuid::new_v4(), None));
        let jwt_payload = WRPRegistrationCertificatePayload {
            issued_at: Some(now),
            invalid_before: Some(start),
            expires_at: Some(end),
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
            .create_and_sign_jwt(key.clone(), pubkey_info, jwt_payload)
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
        key: Key,
        pubkey_info: Option<JwtPublicKeyInfo>,
        payload: WRPRegistrationCertificatePayload,
    ) -> Result<String, SignerError> {
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
            None,
            pubkey_info,
            payload,
        );
        Ok(jwt
            .tokenize(Some(&*signer))
            .await
            .error_while("signing registration certificate")?)
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
