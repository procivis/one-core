use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{DidValue, HolderWalletUnitId};
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::model::holder_wallet_unit::{HolderWalletUnit, HolderWalletUnitRelations};
use crate::model::key::{Key, KeyRelations};
use crate::model::wallet_unit_attestation::{KeyStorageSecurityLevel, WalletUnitAttestation};
use crate::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::wallet_provider_client::WalletProviderClient;
use crate::provider::wallet_provider_client::dto::IssueWalletAttestationResponse;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::service::error::{MissingProviderError, ServiceError};
use crate::service::wallet_provider::dto::{
    IssueWaaRequestDTO, IssueWalletUnitAttestationRequestDTO,
    IssueWalletUnitAttestationResponseDTO, IssueWuaRequestDTO, WalletUnitAttestationClaims,
};
use crate::service::wallet_unit::error::HolderWalletUnitError;
pub enum IssueWalletAttestationRequest<'a> {
    Waa,
    Wua(&'a Key, KeyStorageSecurityLevel),
    WuaAndWaa(&'a Key, KeyStorageSecurityLevel),
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait HolderWalletUnitProto: Send + Sync {
    async fn issue_wallet_attestations<'a>(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
        request: IssueWalletAttestationRequest<'a>,
    ) -> Result<IssueWalletUnitAttestationResponseDTO, ServiceError>;

    async fn is_holder_wallet_unit_revoked(
        &self,
        holder_wallet_unit: &HolderWalletUnit,
    ) -> Result<bool, ServiceError>;

    async fn get_authentication_key(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
    ) -> Result<Key, ServiceError>;
}

pub struct HolderWalletUnitProtoImpl {
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
}

impl HolderWalletUnitProtoImpl {
    pub fn new(
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    ) -> Self {
        Self {
            key_provider,
            key_algorithm_provider,
            wallet_provider_client,
            revocation_method_provider,
            holder_wallet_unit_repository,
        }
    }

    async fn create_proof_of_key_possesion(
        &self,
        wallet_provider_url: &str,
        key: &Key,
    ) -> Result<String, ServiceError> {
        let key_algorithm_type = key.key_algorithm_type().ok_or_else(|| {
            ServiceError::MappingError(format!("Invalid key algorithm type: {}", key.key_type))
        })?;

        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_type(key_algorithm_type)
            .ok_or_else(|| {
                ServiceError::MappingError(format!(
                    "Missing key algorithm: {:?}",
                    key_algorithm_type
                ))
            })?;

        let jose_alg = key_algorithm.issuance_jose_alg_id().ok_or_else(|| {
            ServiceError::MappingError(format!(
                "Invalid key algorithm for issuance: {:?}",
                key_algorithm_type
            ))
        })?;

        let key_storage = self.key_provider.get_key_storage(&key.storage_type).ok_or(
            MissingProviderError::KeyStorage(key.storage_type.to_string()),
        )?;

        let key_handle = key_storage
            .key_handle(key)
            .map_err(|e| ServiceError::KeyStorageError(KeyStorageError::SignerError(e)))?;

        let public_key = key_handle.public_key_as_jwk()?;

        let now = OffsetDateTime::now_utc();
        let jwt = Jwt::new(
            "JWT".to_string(),
            jose_alg,
            None,
            Some(JwtPublicKeyInfo::Jwk(public_key.into())),
            JWTPayload {
                issued_at: Some(now),
                expires_at: Some(now + Duration::hours(10)),
                invalid_before: Some(now),
                audience: Some(vec![wallet_provider_url.to_string()]),
                custom: (),
                ..Default::default()
            },
        );

        let jwt_header_json = serde_json::to_string(&jwt.header).map_err(|e| {
            ServiceError::MappingError(format!("Failed to serialize JWT header: {e}"))
        })?;
        let payload_json = serde_json::to_string(&jwt.payload).map_err(|e| {
            ServiceError::MappingError(format!("Failed to serialize JWT payload: {e}"))
        })?;
        let mut token = format!(
            "{}.{}",
            string_to_b64url_string(&jwt_header_json).map_err(|e| ServiceError::MappingError(
                format!("Failed to convert JWT header to base64url: {e}")
            ))?,
            string_to_b64url_string(&payload_json).map_err(|e| ServiceError::MappingError(
                format!("Failed to convert JWT payload to base64url: {e}")
            ))?,
        );

        let signature = key_handle
            .sign(token.as_bytes())
            .await
            .map_err(|e| ServiceError::KeyStorageError(KeyStorageError::SignerError(e)))?;

        let signature_encoded = bin_to_b64url_string(&signature).map_err(|e| {
            ServiceError::MappingError(format!("Failed to convert signature to base64url: {e}"))
        })?;

        token.push('.');
        token.push_str(&signature_encoded);

        Ok(token)
    }

    async fn check_wallet_unit_attestation_status(
        &self,
        wallet_unit_attestations: &WalletUnitAttestation,
    ) -> Result<bool, ServiceError> {
        const TOKENSTATUSLIST_STATUS_TYPE: &str = "TOKENSTATUSLIST";

        let parsed_wallet_unit_attestation: Jwt<WalletUnitAttestationClaims> =
            Jwt::build_from_token(&wallet_unit_attestations.attestation, None, None).await?;

        let revocation_list_url: Url = wallet_unit_attestations
            .revocation_list_url
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Wallet unit attestation revocation list url not found".to_string(),
            ))?
            .parse()
            .map_err(|e| {
                ServiceError::MappingError(format!("Failed to parse revocation list url: {e}"))
            })?;

        let (revocation_provider, _) = self
            .revocation_method_provider
            .get_revocation_method_by_status_type(TOKENSTATUSLIST_STATUS_TYPE)
            .ok_or(ServiceError::MappingError(
                "Token status list revocation method not found".to_string(),
            ))?;

        let issuer_identifier = {
            let issuer: DidValue = parsed_wallet_unit_attestation
                .payload
                .issuer
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Wallet unit attestation issuer not found".to_string(),
                ))?
                .parse()
                .map_err(|e| ServiceError::MappingError(format!("Failed to parse issuer: {e}")))?;

            IdentifierDetails::Did(issuer)
        };

        let revocation_status = revocation_provider
            .check_credential_revocation_status(
                &CredentialStatus {
                    id: Some(revocation_list_url),
                    r#type: TOKENSTATUSLIST_STATUS_TYPE.to_string(),
                    status_purpose: None,
                    additional_fields: HashMap::new(),
                },
                &issuer_identifier,
                None,
                false,
            )
            .await;

        match revocation_status {
            Ok(CredentialRevocationState::Valid) => Ok(true),
            Ok(_) => Ok(false),
            Err(e) => Err(ServiceError::Revocation(e)),
        }
    }
}

#[async_trait]
impl HolderWalletUnitProto for HolderWalletUnitProtoImpl {
    async fn is_holder_wallet_unit_revoked(
        &self,
        holder_wallet_unit: &HolderWalletUnit,
    ) -> Result<bool, ServiceError> {
        let key =
            holder_wallet_unit
                .authentication_key
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "holder wallet unit authentication key not found".to_string(),
                ))?;

        let bearer_token = self
            .create_proof_of_key_possesion(&holder_wallet_unit.wallet_provider_url, key)
            .await?;

        let IssueWalletAttestationResponse::Active(_) = self
            .wallet_provider_client
            .issue_attestation(
                &holder_wallet_unit.wallet_provider_url,
                holder_wallet_unit.provider_wallet_unit_id,
                &bearer_token,
                IssueWalletUnitAttestationRequestDTO {
                    waa: vec![],
                    wua: vec![],
                },
            )
            .await
            .map_err(HolderWalletUnitError::from)?
        else {
            return Ok(false);
        };

        let Some(wallet_unit_attestations) = holder_wallet_unit.wallet_unit_attestations.as_ref()
        else {
            return Ok(false);
        };

        for wua in wallet_unit_attestations {
            if !self.check_wallet_unit_attestation_status(wua).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn get_authentication_key(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
    ) -> Result<Key, ServiceError> {
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
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::MappingError(
                "holder wallet unit not found".to_string(),
            ))?;

        holder_wallet_unit
            .authentication_key
            .ok_or(ServiceError::MappingError(
                "holder wallet unit authentication key not found".to_string(),
            ))
    }

    async fn issue_wallet_attestations<'a>(
        &self,
        holder_wallet_unit_id: &HolderWalletUnitId,
        request: IssueWalletAttestationRequest<'a>,
    ) -> Result<IssueWalletUnitAttestationResponseDTO, ServiceError> {
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
            .map_err(ServiceError::from)?
            .ok_or(ServiceError::MappingError(
                "holder wallet unit not found".to_string(),
            ))?;

        let authentication_key =
            holder_wallet_unit
                .authentication_key
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "holder wallet unit authentication key not found".to_string(),
                ))?;

        let waa_proof = match request {
            IssueWalletAttestationRequest::Waa | IssueWalletAttestationRequest::WuaAndWaa(_, _) => {
                let proof = self
                    .create_proof_of_key_possesion(
                        &holder_wallet_unit.wallet_provider_url,
                        authentication_key,
                    )
                    .await?;
                vec![IssueWaaRequestDTO { proof }]
            }
            IssueWalletAttestationRequest::Wua(_, _) => {
                vec![]
            }
        };

        let wua_proof = match request {
            IssueWalletAttestationRequest::WuaAndWaa(attested_key, security_level)
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
                    waa: waa_proof,
                    wua: wua_proof,
                },
            )
            .await
            .map_err(HolderWalletUnitError::from)?;

        if let IssueWalletAttestationResponse::Active(response) = issuance_result {
            Ok(response)
        } else {
            Err(ServiceError::MappingError(
                "Failed to issue wallet attestations".to_string(),
            ))
        }
    }
}
