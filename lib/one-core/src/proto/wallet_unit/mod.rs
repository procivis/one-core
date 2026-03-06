use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::HolderWalletUnitId;
use time::{Duration, OffsetDateTime};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::holder_wallet_unit::{HolderWalletUnit, HolderWalletUnitRelations};
use crate::model::key::{Key, KeyRelations};
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::model::{
    CertificateDetails, CredentialStatus, IdentifierDetails,
};
use crate::provider::issuance_protocol::model::KeyStorageSecurityLevel;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::wallet_provider_client::WalletProviderClient;
use crate::provider::wallet_provider_client::dto::IssueWalletAttestationResponse;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::service::error::MissingProviderError;
use crate::service::wallet_provider::dto::{
    IssueWalletUnitAttestationRequestDTO, IssueWalletUnitAttestationResponseDTO,
    IssueWiaRequestDTO, IssueWuaRequestDTO, WalletUnitAttestationClaims,
};
pub enum IssueWalletAttestationRequest<'a> {
    Wia,
    Wua(&'a Key, KeyStorageSecurityLevel),
    WuaAndWia(&'a Key, KeyStorageSecurityLevel),
}

#[derive(PartialEq)]
pub enum WalletUnitStatusCheckResponse {
    Revoked,
    Active,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub(crate) trait HolderWalletUnitProto: Send + Sync {
    async fn issue_wallet_attestations<'a>(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
        request: IssueWalletAttestationRequest<'a>,
    ) -> Result<IssueWalletUnitAttestationResponseDTO, Error>;

    async fn check_wallet_unit_status(
        &self,
        holder_wallet_unit: &HolderWalletUnit,
    ) -> Result<WalletUnitStatusCheckResponse, Error>;

    async fn check_wallet_unit_attestation_status(
        &self,
        wua: &str,
    ) -> Result<WalletUnitStatusCheckResponse, Error>;

    async fn get_authentication_key(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
    ) -> Result<Key, Error>;
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
    holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
}

impl HolderWalletUnitProtoImpl {
    pub(crate) fn new(
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
    ) -> Self {
        Self {
            key_provider,
            key_algorithm_provider,
            wallet_provider_client,
            revocation_method_provider,
            holder_wallet_unit_repository,
            certificate_validator,
        }
    }

    async fn create_proof_of_key_possesion(
        &self,
        wallet_provider_url: &str,
        key: &Key,
    ) -> Result<String, Error> {
        let key_algorithm_type = key
            .key_algorithm_type()
            .ok_or_else(|| {
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(key.key_type.to_owned())
            })
            .error_while("getting key algorithm")?;

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(key_algorithm_type)
            .ok_or_else(|| {
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                    key_algorithm_type.to_string(),
                )
            })
            .error_while("getting key algorithm")?;

        let jose_alg = key_algorithm.issuance_jose_alg_id().ok_or_else(|| {
            Error::MappingError(format!(
                "Invalid key algorithm for issuance: {key_algorithm_type}",
            ))
        })?;

        let key_storage = self
            .key_provider
            .get_key_storage(&key.storage_type)
            .ok_or(MissingProviderError::KeyStorage(
                key.storage_type.to_string(),
            ))
            .error_while("getting key storage")?;

        let key_handle = key_storage
            .key_handle(key)
            .error_while("getting key handle")?;

        let public_key = key_handle.public_key_as_jwk().error_while("creating JWK")?;

        let now = OffsetDateTime::now_utc();
        let jwt = Jwt::new(
            "JWT".to_string(),
            jose_alg,
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
}

#[async_trait]
impl HolderWalletUnitProto for HolderWalletUnitProtoImpl {
    async fn check_wallet_unit_attestation_status(
        &self,
        wua: &str,
    ) -> Result<WalletUnitStatusCheckResponse, Error> {
        const TOKENSTATUSLIST_ENTRY_TYPE: &str = "TokenStatusListEntry";
        const URI_KEY: &str = "uri";
        const INDEX_KEY: &str = "idx";

        let parsed_wallet_unit_attestation: Jwt<WalletUnitAttestationClaims> =
            Jwt::build_from_token(wua, None, None)
                .await
                .error_while("parsing WUA token")?;

        let Some(status) = &parsed_wallet_unit_attestation.payload.custom.status else {
            return Ok(WalletUnitStatusCheckResponse::Active);
        };

        let issuer_identifier = match (
            parsed_wallet_unit_attestation.header.jwk,
            parsed_wallet_unit_attestation.header.x5c.as_ref(),
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
                })
            }
            _ => {
                return Err(Error::MappingError(
                    "Wallet unit attestation issuer not found".to_string(),
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
            RevocationState::Revoked | RevocationState::Suspended { .. } => {
                WalletUnitStatusCheckResponse::Revoked
            }
        })
    }

    async fn check_wallet_unit_status(
        &self,
        holder_wallet_unit: &HolderWalletUnit,
    ) -> Result<WalletUnitStatusCheckResponse, Error> {
        let key = holder_wallet_unit
            .authentication_key
            .as_ref()
            .ok_or(Error::MappingError(
                "holder wallet unit authentication key not found".to_string(),
            ))?;

        if let Some(wallet_unit_attestations) = &holder_wallet_unit.wallet_unit_attestations {
            for wua in wallet_unit_attestations {
                if let WalletUnitStatusCheckResponse::Revoked = self
                    .check_wallet_unit_attestation_status(&wua.attestation.clone())
                    .await?
                {
                    return Ok(WalletUnitStatusCheckResponse::Revoked);
                }
            }
        }

        let bearer_token = self
            .create_proof_of_key_possesion(&holder_wallet_unit.wallet_provider_url, key)
            .await?;

        let revocation_check_status = self
            .wallet_provider_client
            .issue_attestation(
                &holder_wallet_unit.wallet_provider_url,
                holder_wallet_unit.provider_wallet_unit_id,
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

    async fn get_authentication_key(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
    ) -> Result<Key, Error> {
        let holder_wallet_unit = self
            .holder_wallet_unit_repository
            .get_holder_wallet_unit(
                holder_wallet_unit_id,
                &HolderWalletUnitRelations {
                    authentication_key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(Error::MappingError(
                "holder wallet unit not found".to_string(),
            ))?;

        holder_wallet_unit
            .authentication_key
            .ok_or(Error::MappingError(
                "holder wallet unit authentication key not found".to_string(),
            ))
    }

    async fn issue_wallet_attestations<'a>(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
        request: IssueWalletAttestationRequest<'a>,
    ) -> Result<IssueWalletUnitAttestationResponseDTO, Error> {
        let holder_wallet_unit = self
            .holder_wallet_unit_repository
            .get_holder_wallet_unit(
                holder_wallet_unit_id,
                &HolderWalletUnitRelations {
                    authentication_key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .error_while("getting holder wallet unit")?
            .ok_or(Error::MappingError(
                "holder wallet unit not found".to_string(),
            ))?;

        let authentication_key =
            holder_wallet_unit
                .authentication_key
                .as_ref()
                .ok_or(Error::MappingError(
                    "holder wallet unit authentication key not found".to_string(),
                ))?;

        let wia_proof = match request {
            IssueWalletAttestationRequest::Wia | IssueWalletAttestationRequest::WuaAndWia(_, _) => {
                let proof = self
                    .create_proof_of_key_possesion(
                        &holder_wallet_unit.wallet_provider_url,
                        authentication_key,
                    )
                    .await?;
                vec![IssueWiaRequestDTO { proof }]
            }
            IssueWalletAttestationRequest::Wua(_, _) => {
                vec![]
            }
        };

        let wua_proof = match request {
            IssueWalletAttestationRequest::WuaAndWia(attested_key, security_level)
            | IssueWalletAttestationRequest::Wua(attested_key, security_level) => {
                let proof = self
                    .create_proof_of_key_possesion(
                        &holder_wallet_unit.wallet_provider_url,
                        attested_key,
                    )
                    .await?;
                vec![IssueWuaRequestDTO {
                    proof,
                    security_level,
                }]
            }
            _ => vec![],
        };

        let bearer_token = self
            .create_proof_of_key_possesion(
                &holder_wallet_unit.wallet_provider_url,
                authentication_key,
            )
            .await?;

        let issuance_result = self
            .wallet_provider_client
            .issue_attestation(
                &holder_wallet_unit.wallet_provider_url,
                holder_wallet_unit.provider_wallet_unit_id,
                &bearer_token,
                IssueWalletUnitAttestationRequestDTO {
                    wia: wia_proof,
                    wua: wua_proof,
                },
            )
            .await
            .error_while("issuing attestation")?;

        if let IssueWalletAttestationResponse::Active(response) = issuance_result {
            Ok(response)
        } else {
            Err(Error::MappingError(
                "Failed to issue wallet attestations".to_string(),
            ))
        }
    }
}
