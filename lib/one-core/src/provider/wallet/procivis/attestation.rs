use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_dto_mapper::convert_inner;
use serde::Serialize;
use shared_types::IdentifierId;
use standardized_types::jwk::PublicJwk;
use time::Duration;
use uuid::Uuid;

use super::ProcivisWalletProvider;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::model::identifier::IdentifierData;
use crate::model::managed_instance::ManagedInstance;
use crate::model::managed_instance_attestation::{
    ManagedInstanceAttestation, UpdateManagedInstanceAttestationRequest,
};
use crate::model::wallet_instance_attestation::AttestationType;
use crate::proto::jwt::model::{JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey};
use crate::proto::jwt::{Jwt, JwtPublicKeyInfo};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::wallet::dto::CreatedAttestation;
use crate::provider::wallet::error::WalletProviderError;
use crate::service::managed_instance::dto::{
    AttestationStatus, IssueWiaRequestDTO, IssueWuaRequestDTO, NoncePayload,
    WalletInstanceAttestationClaims, WalletUnitAttestationClaims,
};
use crate::service::managed_instance::validator::validate_proof_payload;
use crate::util::key_selection::KeyFilter;

const WIA_JWT_TYPE: &str = "oauth-client-attestation+jwt";
const WUA_JWT_TYPE: &str = "key-attestation+jwt";

impl ProcivisWalletProvider {
    pub(super) async fn create_key_attestation(
        &self,
        wua_request: IssueWuaRequestDTO,
        issuer: IdentifierId,
        managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError> {
        let holder_jwk = self
            .verify_pop(&wua_request.proof, self.params.device_auth_leeway_seconds)
            .await
            .error_while("verifying WUA request pop")?;

        let attestation_params = &self.params.wallet_key_attestation;
        let revocation_method = attestation_params
            .revocation_method
            .as_ref()
            .map(|revocation_method| {
                self.revocation_method_provider
                    .get_revocation_method(revocation_method)
            })
            .transpose()?;

        let now = crate::clock::now_utc();
        let ka_expiration_date = now + attestation_params.expiration_seconds;
        let status_expiration_date = if revocation_method.is_some() {
            ka_expiration_date + attestation_params.status_period_seconds
        } else {
            ka_expiration_date
        };
        let attestation = ManagedInstanceAttestation {
            id: Uuid::new_v4().into(),
            instance_id: managed_instance.id,
            created_date: now,
            last_modified: now,
            expiration_date: status_expiration_date,
            r#type: AttestationType::KeyAttestation,
            attestation_content_hash: None,
            revocation: None,
        };
        self.managed_instance_attestation_repository
            .create_attestation(attestation.to_owned())
            .await
            .error_while("creating attestation")?;

        let revocation_info = if let Some(revocation_method) = revocation_method {
            Some(
                revocation_method
                    .add_issued_attestation(&attestation)
                    .await
                    .error_while("adding attestation")?,
            )
        } else {
            None
        };

        let status = revocation_info
            .and_then(|info| {
                let obj: serde_json::Value = info
                    .credential_status
                    .additional_fields
                    .into_iter()
                    .collect();
                serde_json::from_value(obj).ok()
            })
            .map(|status_list| SdJwtVcStatus {
                status_list,
                custom_claims: Default::default(),
            });

        let issuer_key = self.get_issuer_key(issuer).await?;
        let signed_attestation = issuer_key
            .sign_jwt(
                WUA_JWT_TYPE.to_string(),
                JWTPayload {
                    issued_at: Some(now),
                    expires_at: Some(ka_expiration_date),
                    invalid_before: Some(now),
                    issuer: None,
                    subject: self
                        .core_base_url
                        .clone()
                        .map(|base_url| format!("{base_url}/{}", managed_instance.provider)),
                    audience: None,
                    jwt_id: None,
                    proof_of_possession_key: None,
                    custom: WalletUnitAttestationClaims {
                        certification: Some(self.params.wallet_certification.to_owned()),
                        key_storage: vec![wua_request.security_level],
                        attested_keys: vec![holder_jwk],
                        eudi_wallet_info: convert_inner(self.params.eudi_wallet_info.to_owned()),
                        key_storage_status: status.map(|status| AttestationStatus {
                            status,
                            expires_at: status_expiration_date,
                        }),
                        status: None,
                    },
                },
            )
            .await?;

        self.managed_instance_attestation_repository
            .update_attestation(
                &attestation.id,
                UpdateManagedInstanceAttestationRequest {
                    attestation_content_hash: Some(Some(signed_attestation.hash)),
                },
            )
            .await
            .error_while("updating attestation")?;

        Ok(CreatedAttestation {
            jwt: signed_attestation.jwt,
            id: attestation.id,
        })
    }

    pub(super) async fn create_wia(
        &self,
        wia_request: IssueWiaRequestDTO,
        issuer: IdentifierId,
        managed_instance: &ManagedInstance,
    ) -> Result<CreatedAttestation, WalletProviderError> {
        let holder_binding_jwk = self
            .verify_pop(&wia_request.proof, self.params.device_auth_leeway_seconds)
            .await
            .error_while("verifying WIA request pop")?;

        let attestation_params = &self.params.wallet_instance_attestation;
        let revocation_method = attestation_params
            .revocation_method
            .as_ref()
            .map(|revocation_method| {
                self.revocation_method_provider
                    .get_revocation_method(revocation_method)
            })
            .transpose()?;

        let now = crate::clock::now_utc();
        let wia_expiration_date = now + attestation_params.expiration_seconds;
        let status_expiration_date = if revocation_method.is_some() {
            wia_expiration_date + attestation_params.status_period_seconds
        } else {
            wia_expiration_date
        };
        let attestation = ManagedInstanceAttestation {
            id: Uuid::new_v4().into(),
            instance_id: managed_instance.id,
            created_date: now,
            last_modified: now,
            expiration_date: status_expiration_date,
            r#type: AttestationType::WalletInstanceAttestation,
            attestation_content_hash: None,
            revocation: None,
        };
        self.managed_instance_attestation_repository
            .create_attestation(attestation.to_owned())
            .await
            .error_while("creating attestation")?;

        let revocation_info = if let Some(revocation_method) = revocation_method {
            Some(
                revocation_method
                    .add_issued_attestation(&attestation)
                    .await
                    .error_while("adding attestation")?,
            )
        } else {
            None
        };

        let status = revocation_info
            .and_then(|info| {
                let obj: serde_json::Value = info
                    .credential_status
                    .additional_fields
                    .into_iter()
                    .collect();
                serde_json::from_value(obj).ok()
            })
            .map(|status_list| SdJwtVcStatus {
                status_list,
                custom_claims: Default::default(),
            });

        let issuer_key = self.get_issuer_key(issuer).await?;
        let signed_attestation = issuer_key
            .sign_jwt(
                WIA_JWT_TYPE.to_string(),
                JWTPayload {
                    issued_at: Some(now),
                    expires_at: Some(wia_expiration_date),
                    invalid_before: Some(now),
                    issuer: None,
                    // As per https://drafts.oauth.net/draft-ietf-oauth-attestation-based-client-auth/draft-ietf-oauth-attestation-based-client-auth.html#section-5.1
                    // sub: REQUIRED. The sub (subject) claim MUST specify client_id value of the OAuth Client.
                    subject: Some(self.params.wallet_client_id.clone()),
                    audience: None,
                    jwt_id: None,
                    proof_of_possession_key: Some(ProofOfPossessionKey {
                        key_id: None,
                        jwk: ProofOfPossessionJwk::Jwk {
                            jwk: holder_binding_jwk,
                        },
                    }),
                    custom: WalletInstanceAttestationClaims {
                        wallet_name: Some(self.params.wallet_name.clone()),
                        wallet_link: Some(self.params.wallet_link.clone()),
                        wallet_solution_certification_information: Some(
                            self.params.wallet_certification.to_owned(),
                        ),
                        eudi_wallet_info: convert_inner(self.params.eudi_wallet_info.clone()),
                        client_status: status.map(|status| AttestationStatus {
                            status,
                            expires_at: status_expiration_date,
                        }),
                    },
                },
            )
            .await?;

        self.managed_instance_attestation_repository
            .update_attestation(
                &attestation.id,
                UpdateManagedInstanceAttestationRequest {
                    attestation_content_hash: Some(Some(signed_attestation.hash)),
                },
            )
            .await
            .error_while("updating attestation")?;

        Ok(CreatedAttestation {
            jwt: signed_attestation.jwt,
            id: attestation.id,
        })
    }

    async fn get_issuer_key(
        &self,
        issuer_identifier_id: IdentifierId,
    ) -> Result<IssuerKey, WalletProviderError> {
        let issuer_identifier = self
            .identifier_repository
            .get(issuer_identifier_id)
            .await
            .error_while("getting identifier")?;

        let selection = issuer_identifier
            .select_key(KeyFilter::algorithms(vec![KeyAlgorithmType::Ecdsa]).into())
            .await
            .error_while("selecting key")?;
        let issuer_key = selection.key();

        let key_id = if let IdentifierData::Did(issuer_did) = &issuer_identifier.data {
            let issuer_did = issuer_did.as_ref().await?;

            let key = issuer_did
                .find_key(
                    &issuer_key.id,
                    &KeyFilter::algorithms(vec![KeyAlgorithmType::Ecdsa]),
                )
                .await
                .error_while("finding key")?;

            Some(issuer_did.verification_method_id(&key))
        } else {
            None
        };

        let auth_fn = self.key_provider.get_signature_provider(
            issuer_key,
            key_id,
            self.key_algorithm_provider.clone(),
        )?;

        let public_key_info = match &issuer_identifier.data {
            IdentifierData::Key(_) | IdentifierData::Did(_) => {
                let key_handle = self
                    .key_provider
                    .get_key_storage(&issuer_key.storage_type)?
                    .key_handle(issuer_key)
                    .error_while("getting issuer key handle")?;
                JwtPublicKeyInfo::Jwk(key_handle.public_key_as_jwk().error_while("creating JWK")?)
            }
            IdentifierData::Certificate(certificates) => {
                let certificates = certificates.as_ref().await?;
                let cert = certificates
                    .iter()
                    .find(|cert| cert.key.as_ref().is_some_and(|k| k.id() == issuer_key.id))
                    .ok_or(WalletProviderError::MappingError(
                        "Cert with matching key not found".to_string(),
                    ))?;
                let x5c = pem_chain_into_x5c(&cert.chain).error_while("parsing PEM chain")?;
                JwtPublicKeyInfo::X5c(x5c)
            }
            IdentifierData::CertificateAuthority(_) => {
                return Err(WalletProviderError::MappingError(format!(
                    "Invalid issuer identifier type {}",
                    issuer_identifier.data.r#type()
                )));
            }
        };

        Ok(IssuerKey {
            public_key_info,
            auth_fn,
        })
    }

    async fn verify_pop(
        &self,
        pop: &str,
        leeway: Duration,
    ) -> Result<PublicJwk, WalletProviderError> {
        let pop_token =
            Jwt::<NoncePayload>::decompose_token(pop).error_while("parsing pop token")?;
        let jwk = pop_token
            .header
            .jwk
            .clone()
            .ok_or(WalletProviderError::CouldNotVerifyProof(
                "Missing jwk".to_string(),
            ))
            .error_while("validating PoP header")?;
        let key_handle = self
            .parse_jwk(&pop_token.header.algorithm, &jwk)
            .error_while("parsing JWK")?;
        key_handle
            .verify(pop_token.unverified_jwt.as_bytes(), &pop_token.signature)
            .map_err(|e| WalletProviderError::CouldNotVerifyProof(e.to_string()))
            .error_while("verifying PoP signature")?;
        validate_proof_payload(&pop_token, leeway, self.core_base_url.as_deref(), None)
            .error_while("validating proof payload")?;
        Ok(jwk)
    }

    fn parse_jwk(
        &self,
        key_algorithm: &str,
        jwk: &PublicJwk,
    ) -> Result<KeyHandle, WalletProviderError> {
        let (_, key_algorithm) = self
            .key_algorithm_provider
            .key_algorithm_from_jose_alg(key_algorithm)
            .ok_or(WalletProviderError::CouldNotVerifyProof(format!(
                "Missing key algorithm for {key_algorithm}"
            )))?;

        key_algorithm
            .parse_jwk(jwk)
            .map_err(|e| WalletProviderError::CouldNotVerifyProof(e.to_string()))
    }
}

struct IssuerKey {
    public_key_info: JwtPublicKeyInfo,
    auth_fn: AuthenticationFn,
}

struct SignedAttestation {
    jwt: String,
    hash: String,
}

impl IssuerKey {
    async fn sign_jwt<CustomPayload: Serialize>(
        &self,
        r#type: String,
        payload: JWTPayload<CustomPayload>,
    ) -> Result<SignedAttestation, WalletProviderError> {
        let jose_alg = self
            .auth_fn
            .jose_alg()
            .error_while("preparing attestation header")?;
        let key_id = self.auth_fn.get_key_id();

        let jwt = Jwt::new(
            r#type,
            jose_alg,
            key_id,
            Some(self.public_key_info.to_owned()),
            payload,
        );
        let jwt = jwt
            .tokenize(Some(self.auth_fn.as_ref()))
            .await
            .error_while("creating WUA token")?;

        let hash = SHA256.hash_base64(jwt.as_bytes()).map_err(|e| {
            WalletProviderError::MappingError(format!(
                "Could not hash wallet unit attestation: {e}"
            ))
        })?;

        Ok(SignedAttestation { jwt, hash })
    }
}
