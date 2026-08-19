use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::InstanceId;
use standardized_types::openid4vci::KeyStorageSecurityLevel;
use time::Duration;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::instance::Instance;
use crate::model::key::Key;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::ephemeral_key::EphemeralKey;
use crate::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::proto::wallet_provider_client::dto::IssueWalletAttestationResponse;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CertificateDetails, CredentialStatus, IdentifierDetails,
};
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::instance_repository::InstanceRepository;
use crate::service::error::MissingProviderError;
use crate::service::managed_instance::dto::{
    IssueWalletUnitAttestationRequestDTO, IssueWalletUnitAttestationResponseDTO,
    IssueWiaRequestDTO, IssueWuaRequestDTO,
};

#[derive(Debug)]
pub(crate) struct WIARequestParams {
    pub key_algorithm: KeyAlgorithmType,
}

#[derive(Debug)]
pub(crate) struct WUARequestParams<'a> {
    pub attested_keys: &'a [&'a Key],
    pub security_level: KeyStorageSecurityLevel,
}

#[derive(Debug)]
pub(crate) enum IssueWalletAttestationRequest<'a> {
    Wia(WIARequestParams),
    Wua(WUARequestParams<'a>),
    WuaAndWia(WUARequestParams<'a>, WIARequestParams),
}

/// Minimal claims shape for a revocation-status check: any wallet attestation (WUA or WIA) that
/// carries a token status list entry can be parsed into this.
#[derive(Debug, serde::Deserialize)]
struct AttestationStatusClaims {
    #[serde(default)]
    status: Option<SdJwtVcStatus>,
}

#[derive(PartialEq)]
pub enum WalletUnitStatusCheckResponse {
    Revoked,
    Active,
}

pub(crate) struct IssuedWalletUnitAttestations {
    pub provider_response: IssueWalletUnitAttestationResponseDTO,
    pub wia_pop_key: Option<AuthenticationFn>,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub(crate) trait HolderWalletUnitProto: Send + Sync {
    async fn issue_wallet_attestations<'a>(
        &self,
        holder_wallet_unit_id: &InstanceId,
        request: IssueWalletAttestationRequest<'a>,
    ) -> Result<IssuedWalletUnitAttestations, Error>;

    async fn check_wallet_unit_status(
        &self,
        holder_wallet_unit: &Instance,
    ) -> Result<WalletUnitStatusCheckResponse, Error>;

    /// Check the revocation status of a wallet attestation (WUA or WIA) against the token
    /// status list it points to. An attestation without a `status` claim counts as active.
    async fn check_attestation_status(
        &self,
        attestation: &str,
    ) -> Result<WalletUnitStatusCheckResponse, Error>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[expect(clippy::enum_variant_names)]
    #[error("Mapping error: `{0}`")]
    MappingError(String),

    #[error("JSON error: `{0}`")]
    JsonSerialization(#[from] serde_json::Error),
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::JsonSerialization(_) | Self::Encoding(_) => ErrorCode::BR_0000,
            Self::MappingError(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

pub struct HolderWalletUnitProtoImpl {
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    holder_wallet_instance_repository: Arc<dyn InstanceRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl HolderWalletUnitProtoImpl {
    pub(crate) fn new(
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        holder_wallet_unit_repository: Arc<dyn InstanceRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            key_provider,
            key_algorithm_provider,
            wallet_provider_client,
            revocation_method_provider,
            holder_wallet_instance_repository: holder_wallet_unit_repository,
            certificate_validator,
        }
    }

    async fn create_proof_of_key_possesion(
        &self,
        wallet_provider_url: &str,
        key_handle: &KeyHandle,
        key_algorithm: &dyn KeyAlgorithm,
    ) -> Result<String, Error> {
        let public_key = key_handle.public_key_as_jwk().error_while("creating JWK")?;

        let now = crate::clock::now_utc();
        let jwt = Jwt::new(
            "JWT".to_string(),
            key_algorithm.issuance_jose_alg_id(),
            None,
            Some(JwtPublicKeyInfo::Jwk(public_key)),
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now + Duration::hours(10)),
                invalid_before: Some(now),
                audience: Some(vec![wallet_provider_url.to_string()]),
                custom: (),
                ..Default::default()
            },
        );

        let jwt_header_json = serde_json::to_string(&jwt.header)?;
        let payload_json = serde_json::to_string(&jwt.payload)?;
        let mut token = format!(
            "{}.{}",
            string_to_b64url_string(&jwt_header_json)?,
            string_to_b64url_string(&payload_json)?,
        );

        let signature = key_handle
            .sign(token.as_bytes())
            .await
            .error_while("signing")?;

        let signature_encoded = bin_to_b64url_string(&signature)?;

        token.push('.');
        token.push_str(&signature_encoded);

        Ok(token)
    }

    fn get_key_handle(&self, key: &Key) -> Result<(KeyHandle, Arc<dyn KeyAlgorithm>), Error> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_key(key)
            .error_while("getting key algorithm")?;

        let key_storage = self.key_provider.get_key_storage(&key.storage_type)?;

        let key_handle = key_storage
            .key_handle(key)
            .error_while("getting key handle")?;

        Ok((key_handle, key_algorithm))
    }
}

#[async_trait]
impl HolderWalletUnitProto for HolderWalletUnitProtoImpl {
    async fn check_attestation_status(
        &self,
        attestation: &str,
    ) -> Result<WalletUnitStatusCheckResponse, Error> {
        const TOKENSTATUSLIST_ENTRY_TYPE: &str = "TokenStatusListEntry";
        const URI_KEY: &str = "uri";
        const INDEX_KEY: &str = "idx";

        // only the `status` claim matters here, so the token is parsed into a minimal shape
        // that fits both a WUA and a WIA
        let parsed_attestation: Jwt<AttestationStatusClaims> =
            Jwt::build_from_token(attestation, None, None)
                .await
                .error_while("parsing attestation token")?;

        let Some(status) = &parsed_attestation.payload.custom.status else {
            return Ok(WalletUnitStatusCheckResponse::Active);
        };

        let issuer_identifier = match (
            parsed_attestation.header.jwk,
            parsed_attestation.header.x5c.as_ref(),
        ) {
            (Some(jwk), None) => IdentifierDetails::Key(jwk),
            (None, Some(x5c)) => {
                let chain = x5c_into_pem_chain(x5c).error_while("parsing x5c")?;

                let ParsedCertificate {
                    attributes,
                    subject_common_name,
                    ..
                } = self
                    .certificate_validator
                    .parse_pem_chain(
                        &chain,
                        CertificateValidationOptions::signature_and_revocation(None),
                    )
                    .await
                    .error_while("parsing PEM chain")?;

                IdentifierDetails::Certificate(CertificateDetails {
                    chain,
                    fingerprint: attributes.fingerprint,
                    expiry: attributes.not_after,
                    subject_common_name,
                    x5_references: Default::default(),
                })
            }
            _ => {
                return Err(Error::MappingError(
                    "Wallet attestation issuer not found".to_string(),
                ));
            }
        };

        let (revocation_provider, _) = self
            .revocation_method_provider
            .get_revocation_method_by_status_type(TOKENSTATUSLIST_ENTRY_TYPE)
            .ok_or(
                MissingProviderError::RevocationMethodByCredentialStatusType(
                    TOKENSTATUSLIST_ENTRY_TYPE.to_string(),
                ),
            )
            .error_while("getting revocation provider")?;

        let revocation_status = revocation_provider
            .check_credential_revocation_status(
                &CredentialStatus {
                    id: None,
                    r#type: TOKENSTATUSLIST_ENTRY_TYPE.to_string(),
                    status_purpose: None,
                    additional_fields: HashMap::from([
                        (
                            URI_KEY.to_string(),
                            status.status_list.uri.clone().to_string().into(),
                        ),
                        (
                            INDEX_KEY.to_string(),
                            status.status_list.index.to_string().into(),
                        ),
                    ]),
                },
                &issuer_identifier,
                None,
                false,
            )
            .await
            .error_while("checking credential status")?;

        Ok(match revocation_status {
            RevocationState::Valid => WalletUnitStatusCheckResponse::Active,
            RevocationState::Revoked
            | RevocationState::Suspended { .. }
            | RevocationState::Expired => WalletUnitStatusCheckResponse::Revoked,
        })
    }

    async fn check_wallet_unit_status(
        &self,
        holder_wallet_unit: &Instance,
    ) -> Result<WalletUnitStatusCheckResponse, Error> {
        let key = holder_wallet_unit
            .authentication_key
            .as_ref()
            .ok_or(Error::MappingError(
                "holder wallet unit authentication key not found".to_string(),
            ))?;

        for wua in &holder_wallet_unit.wallet_unit_attestations.as_ref().await? {
            if let WalletUnitStatusCheckResponse::Revoked = self
                .check_attestation_status(&wua.attestation.clone())
                .await?
            {
                return Ok(WalletUnitStatusCheckResponse::Revoked);
            }
        }

        let (key_handle, key_algorithm) = self.get_key_handle(key.as_ref().await?.as_ref())?;
        let bearer_token = self
            .create_proof_of_key_possesion(
                &holder_wallet_unit.provider_url,
                &key_handle,
                key_algorithm.as_ref(),
            )
            .await?;

        let revocation_check_status = self
            .wallet_provider_client
            .issue_attestation(
                &holder_wallet_unit.provider_url,
                holder_wallet_unit.provider_instance_id,
                &bearer_token,
                IssueWalletUnitAttestationRequestDTO {
                    wia: vec![],
                    wua: vec![],
                },
            )
            .await
            .error_while("issuing attestation")?;

        match revocation_check_status {
            IssueWalletAttestationResponse::Active(_) => Ok(WalletUnitStatusCheckResponse::Active),
            IssueWalletAttestationResponse::Revoked => Ok(WalletUnitStatusCheckResponse::Revoked),
        }
    }

    async fn issue_wallet_attestations<'a>(
        &self,
        holder_wallet_unit_id: &InstanceId,
        request: IssueWalletAttestationRequest<'a>,
    ) -> Result<IssuedWalletUnitAttestations, Error> {
        let holder_wallet_instance = self
            .holder_wallet_instance_repository
            .get(holder_wallet_unit_id)
            .await
            .error_while("getting holder wallet unit")?;

        let authentication_key =
            holder_wallet_instance
                .authentication_key
                .as_ref()
                .ok_or(Error::MappingError(
                    "holder wallet unit authentication key not found".to_string(),
                ))?;

        let mut wia_pop_key = None;
        let wia_proof = match request {
            IssueWalletAttestationRequest::Wia(WIARequestParams { key_algorithm })
            | IssueWalletAttestationRequest::WuaAndWia(_, WIARequestParams { key_algorithm }) => {
                let key_algorithm = self
                    .key_algorithm_provider
                    .key_algorithm_from_type(key_algorithm)
                    .error_while("getting key algorithm for WIA key")?;

                let key = EphemeralKey::new(key_algorithm.to_owned())
                    .error_while("generating WIA PoP key")?;

                let proof = self
                    .create_proof_of_key_possesion(
                        &holder_wallet_instance.provider_url,
                        key.key_handle(),
                        key_algorithm.as_ref(),
                    )
                    .await?;
                wia_pop_key = Some(key.into());
                vec![IssueWiaRequestDTO { proof }]
            }
            IssueWalletAttestationRequest::Wua(_) => {
                vec![]
            }
        };

        let wua_proof = match request {
            IssueWalletAttestationRequest::WuaAndWia(
                WUARequestParams {
                    attested_keys,
                    security_level,
                },
                _,
            )
            | IssueWalletAttestationRequest::Wua(WUARequestParams {
                attested_keys,
                security_level,
            }) => {
                let mut requests = Vec::with_capacity(attested_keys.len());
                for key in attested_keys {
                    let (key_handle, key_algorithm) = self.get_key_handle(key)?;
                    let proof = self
                        .create_proof_of_key_possesion(
                            &holder_wallet_instance.provider_url,
                            &key_handle,
                            key_algorithm.as_ref(),
                        )
                        .await?;

                    requests.push(IssueWuaRequestDTO {
                        proof,
                        security_level,
                    });
                }
                requests
            }
            _ => vec![],
        };

        let (key_handle, key_algorithm) =
            self.get_key_handle(authentication_key.as_ref().await?.as_ref())?;
        let bearer_token = self
            .create_proof_of_key_possesion(
                &holder_wallet_instance.provider_url,
                &key_handle,
                key_algorithm.as_ref(),
            )
            .await?;

        let issuance_result = self
            .wallet_provider_client
            .issue_attestation(
                &holder_wallet_instance.provider_url,
                holder_wallet_instance.provider_instance_id,
                &bearer_token,
                IssueWalletUnitAttestationRequestDTO {
                    wia: wia_proof,
                    wua: wua_proof,
                },
            )
            .await
            .error_while("issuing attestation")?;

        if let IssueWalletAttestationResponse::Active(provider_response) = issuance_result {
            Ok(IssuedWalletUnitAttestations {
                provider_response,
                wia_pop_key,
            })
        } else {
            Err(Error::MappingError(
                "Failed to issue wallet attestations".to_string(),
            ))
        }
    }
}
