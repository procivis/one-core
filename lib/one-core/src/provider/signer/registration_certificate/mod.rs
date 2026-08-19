mod mapper;
pub mod model;

use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use serde::Deserialize;
use serde::de::Error;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{Permission, RevocationMethodId, SignerId};
use standardized_types::etsi_119_475::registration_certificate::Status;
use time::Duration;
use url::Url;
use uuid::Uuid;

use crate::config::core_config::{KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::did::KeyRole;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::proto::jwt::JwtPublicKeyInfo;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::registration_certificate::mapper::payload_from_request_data;
use crate::provider::signer::registration_certificate::model::{
    WRPRegistrationCertificate, WRPRegistrationCertificatePayload,
};
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::util::key_selection::{CertificateFilter, KeyFilter, KeySelection, SelectedKey};

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub payload: PayloadParams,
    /// exposed publicly via `GET /api/config/v1`
    #[serde_as(as = "DurationSeconds<i64>")]
    pub max_validity_duration_seconds: Duration,
    pub revocation_method: RevocationMethodId,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadParams {
    pub issuer: Option<Url>,
    pub audience: Option<Vec<String>>,
}

#[derive(Provider)]
pub struct RegistrationCertificate {
    config_key: SignerId,
    params: Params,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl RegistrationCertificate {
    pub fn new(
        config_name: SignerId,
        params: Params,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            config_key: config_name,
            params,
            revocation_method_provider,
            key_provider,
            key_algorithm_provider,
        }
    }

    async fn handle_revocation(
        &self,
        identifier: &Identifier,
        selected_key: &SelectedKey,
    ) -> Result<(Uuid, Status), SignerError> {
        let revocation_method =
            self.revocation_method()?
                .ok_or(SignerError::MissingRevocationMethod(
                    self.params.revocation_method.clone(),
                ))?;
        let (id, revocation_info) = revocation_method
            .add_signature(
                self.config_key.to_owned(),
                identifier,
                selected_key.certificate(),
            )
            .await
            .error_while("Adding signature to revocation list")?;
        Ok((
            Uuid::from(id),
            Status {
                status_list: revocation_info.credential_status.additional_fields,
            },
        ))
    }
}

#[async_trait]
impl Signer for RegistrationCertificate {
    fn config_name(&self) -> &SignerId {
        &self.config_key
    }

    fn get_capabilities(&self) -> SignerCapabilities {
        use crate::config::core_config::IdentifierType;
        SignerCapabilities {
            features: vec![],
            supported_identifiers: vec![IdentifierType::Certificate],
            sign_required_permissions: vec![Permission::RegistrationCertificateSign],
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
        let now = crate::clock::now_utc();
        let SignatureValidity { start, end } =
            calculate_signature_validity(self.params.max_validity_duration_seconds, &request)?;
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
                key: KeyFilter::did_role(KeyRole::AssertionMethod).and_id(key),
                certificate: CertificateFilter::id(certificate),
                ..Default::default()
            })
            .await
            .error_while("Selecting signing key")?;

        let (jwt_id, status) = self.handle_revocation(&identifier, &selected_key).await?;
        let SelectedKey::Certificate { certificate, key } = selected_key else {
            return Err(SignerError::InvalidIssuerIdentifier(identifier.id));
        };
        let pubkey_info = Some(JwtPublicKeyInfo::X5c(
            pem_chain_into_x5c(&certificate.chain).error_while("parsing PEM chain")?,
        ));

        let jwt_payload = WRPRegistrationCertificatePayload {
            issued_at: Some(now),
            invalid_before: Some(start),
            expires_at: Some(end),
            issuer: None,
            subject: Some(payload.get_subject_id().to_owned()),
            audience: self.params.payload.audience.clone(),
            jwt_id: Some(jwt_id.to_string()),
            proof_of_possession_key: None,
            custom: payload_from_request_data(payload, status),
        };
        let signed_jwt = self
            .create_and_sign_jwt(*key, pubkey_info, jwt_payload)
            .await?;

        Ok(CreateSignatureResponseDTO {
            id: jwt_id,
            result: signed_jwt,
        })
    }

    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError> {
        Ok(Some(
            self.revocation_method_provider
                .get_revocation_method(&self.params.revocation_method)?,
        ))
    }
}

impl RegistrationCertificate {
    async fn create_and_sign_jwt(
        &self,
        key: Key,
        pubkey_info: Option<JwtPublicKeyInfo>,
        payload: WRPRegistrationCertificatePayload,
    ) -> Result<String, SignerError> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_key(&key)
            .error_while("getting key algorithm")?;

        let signer = self.key_provider.get_signature_provider(
            &key,
            None,
            self.key_algorithm_provider.clone(),
        )?;
        let jwt = WRPRegistrationCertificate::new(
            "rc-wrp+jwt".to_owned(),
            key_algorithm.issuance_jose_alg_id(),
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
        if result.max_validity_duration_seconds > Duration::days(365) {
            return Err(Error::custom(
                "expiry cannot occur later than 12 months after issuance (GEN-5.2.4-08)",
            ));
        }
        Ok(result)
    }
}
