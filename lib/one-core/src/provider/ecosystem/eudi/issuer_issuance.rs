use shared_types::OrganisationId;

use super::EudiEcosystem;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::wallet_instance_attestation::AttestationType;
use crate::proto::wallet_instance::WalletUnitStatusCheckResponse;
use crate::proto::wrp_validator::error::WRPValidatorError;
use crate::provider::ecosystem::error::{EcosystemError, WalletAttestationRejection};
use crate::provider::ecosystem::model::WalletAttestationArtifact;

impl EudiEcosystem {
    pub(super) async fn resolve_wallet_attestation(
        &self,
        attestation: &WalletAttestationArtifact<'_>,
        organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        let (token, r#type, wallet_provider, issuer_untrusted, revoked) = match attestation {
            WalletAttestationArtifact::WalletInstance { token, jwt } => (
                *token,
                AttestationType::WalletInstanceAttestation,
                jwt.wallet_provider_key(),
                WalletAttestationRejection::WiaIssuerUntrusted,
                WalletAttestationRejection::WiaRevoked,
            ),
            WalletAttestationArtifact::Key { token, jwt } => (
                *token,
                AttestationType::KeyAttestation,
                jwt.wallet_provider_key(),
                WalletAttestationRejection::KaIssuerUntrusted,
                WalletAttestationRejection::KaRevoked,
            ),
        };
        let wallet_provider = wallet_provider.error_while("extracting wallet provider key")?;

        self.wrp_validator
            .validate_wallet_provider(wallet_provider, &self.trust_scope(organisation_id))
            .await
            .map_err(|e| match e {
                WRPValidatorError::WalletProviderNotTrusted => issuer_untrusted.into(),
                _ => EcosystemError::Nested(e.error_while("validating wallet provider")),
            })?;

        let status = self
            .wallet_unit_proto
            .check_attestation_status(token, r#type)
            .await
            .error_while("checking wallet attestation status")?;
        if status != WalletUnitStatusCheckResponse::Active {
            return Err(revoked.into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    use serde_json::json;
    use shared_types::EcosystemId;
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::config::core_config::CoreConfig;
    use crate::error::{ErrorCode, ErrorCodeMixin};
    use crate::proto::credential_validity_manager::MockCredentialValidityManager;
    use crate::proto::jwt::Jwt;
    use crate::proto::jwt::model::DecomposedJwt;
    use crate::proto::session_provider::NoSessionProvider;
    use crate::proto::wallet_instance::MockHolderWalletUnitProto;
    use crate::proto::wrp_validator::MockWRPValidator;
    use crate::provider::blob_storage::provider::MockBlobStorageProvider;
    use crate::provider::credential_formatter::model::PublicKeySource;
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::trust_list_subscriber::etsi_lotl::model::TslServiceEntry;
    use crate::provider::trust_list_subscriber::{TrustEntityMetadata, TrustEntityResponse};
    use crate::repository::credential_repository::MockCredentialRepository;
    use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::repository::interaction_repository::MockInteractionRepository;
    use crate::repository::proof_schema_repository::MockProofSchemaRepository;
    use crate::service::managed_instance::dto::{
        WalletInstanceAttestationClaims, WalletUnitAttestationClaims,
    };

    const WALLET_PROVIDER_CERTIFICATE: &str = "wallet-provider-certificate";

    #[derive(Default)]
    struct Mocks {
        wrp_validator: MockWRPValidator,
        wallet_unit_proto: MockHolderWalletUnitProto,
    }

    fn setup(mocks: Mocks) -> EudiEcosystem {
        EudiEcosystem::new(
            "EUDI".into(),
            json!({}),
            CoreConfig::default(),
            Arc::new(MockHistoryRepository::new()),
            Arc::new(MockInteractionRepository::new()),
            Arc::new(mocks.wrp_validator),
            Arc::new(MockBlobStorageProvider::new()),
            Arc::new(NoSessionProvider),
            Arc::new(MockCredentialFormatterProvider::new()),
            Arc::new(MockCredentialRepository::new()),
            Arc::new(MockCredentialSchemaRepository::new()),
            Arc::new(MockProofSchemaRepository::new()),
            Arc::new(mocks.wallet_unit_proto),
            Arc::new(MockCredentialValidityManager::new()),
        )
        .unwrap()
    }

    /// unsigned, `x5c` names the wallet provider
    fn token(payload: serde_json::Value) -> String {
        let encode = |value: serde_json::Value| {
            Base64UrlSafeNoPadding::encode_to_string(value.to_string()).unwrap()
        };
        format!(
            "{}.{}",
            encode(json!({ "alg": "ES256", "x5c": [WALLET_PROVIDER_CERTIFICATE] })),
            encode(payload)
        )
    }

    fn wia() -> (String, DecomposedJwt<WalletInstanceAttestationClaims>) {
        let token = token(json!({ "wallet_name": "wallet" }));
        let jwt = Jwt::<WalletInstanceAttestationClaims>::decompose_token(&token).unwrap();
        (token, jwt)
    }

    fn ka() -> (String, DecomposedJwt<WalletUnitAttestationClaims>) {
        let token = token(json!({ "key_storage": [], "attested_keys": [] }));
        let jwt = Jwt::<WalletUnitAttestationClaims>::decompose_token(&token).unwrap();
        (token, jwt)
    }

    fn trusted_wallet_provider() -> MockWRPValidator {
        let mut wrp_validator = MockWRPValidator::new();
        wrp_validator
            .expect_validate_wallet_provider()
            .once()
            .withf(|key_source, scope| {
                assert!(matches!(
                    key_source,
                    PublicKeySource::X5c { x5c } if x5c == &[WALLET_PROVIDER_CERTIFICATE]
                ));
                assert_eq!(EcosystemId::from("EUDI"), scope.ecosystem);
                true
            })
            .returning(|_, _| {
                Ok(TrustEntityResponse {
                    derived_role: None,
                    metadata: TrustEntityMetadata::Tsl(TslServiceEntry {
                        service_name: "service".to_string(),
                        service_type_identifier: "http://example.com/svc".to_string(),
                        service_status: "active".to_string(),
                    }),
                })
            });
        wrp_validator
    }

    fn untrusted_wallet_provider() -> MockWRPValidator {
        let mut wrp_validator = MockWRPValidator::new();
        wrp_validator
            .expect_validate_wallet_provider()
            .once()
            .returning(|_, _| Err(WRPValidatorError::WalletProviderNotTrusted));
        wrp_validator
    }

    fn attestation_status(
        expected_token: String,
        expected_type: AttestationType,
        status: WalletUnitStatusCheckResponse,
    ) -> MockHolderWalletUnitProto {
        let mut wallet_unit_proto = MockHolderWalletUnitProto::new();
        wallet_unit_proto
            .expect_check_attestation_status()
            .once()
            .withf(move |token, r#type| token == expected_token && *r#type == expected_type)
            .returning(move |_, _| {
                Ok(match status {
                    WalletUnitStatusCheckResponse::Active => WalletUnitStatusCheckResponse::Active,
                    WalletUnitStatusCheckResponse::Revoked => {
                        WalletUnitStatusCheckResponse::Revoked
                    }
                    WalletUnitStatusCheckResponse::Expired => {
                        WalletUnitStatusCheckResponse::Expired
                    }
                })
            });
        wallet_unit_proto
    }

    #[tokio::test]
    async fn test_wia_trusted_and_active() {
        let (token, jwt) = wia();
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: attestation_status(
                token.clone(),
                AttestationType::WalletInstanceAttestation,
                WalletUnitStatusCheckResponse::Active,
            ),
        });

        ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::WalletInstance {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_wia_issuer_key_taken_from_header_not_iss() {
        let token = token(json!({ "iss": "did:example:wallet-provider", "wallet_name": "wallet" }));
        let jwt = Jwt::<WalletInstanceAttestationClaims>::decompose_token(&token).unwrap();
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: attestation_status(
                token.clone(),
                AttestationType::WalletInstanceAttestation,
                WalletUnitStatusCheckResponse::Active,
            ),
        });

        ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::WalletInstance {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_ka_trusted_and_active() {
        let (token, jwt) = ka();
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: attestation_status(
                token.clone(),
                AttestationType::KeyAttestation,
                WalletUnitStatusCheckResponse::Active,
            ),
        });

        ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::Key {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_wia_issuer_untrusted() {
        let (token, jwt) = wia();
        // trust fails first, the status is never checked
        let ecosystem = setup(Mocks {
            wrp_validator: untrusted_wallet_provider(),
            wallet_unit_proto: MockHolderWalletUnitProto::new(),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::WalletInstance {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::WiaIssuerUntrusted)
        ));
        assert_eq!(ErrorCode::BR_0494, error.error_code());
    }

    #[tokio::test]
    async fn test_ka_issuer_untrusted() {
        let (token, jwt) = ka();
        let ecosystem = setup(Mocks {
            wrp_validator: untrusted_wallet_provider(),
            wallet_unit_proto: MockHolderWalletUnitProto::new(),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::Key {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KaIssuerUntrusted)
        ));
        assert_eq!(ErrorCode::BR_0496, error.error_code());
    }

    #[tokio::test]
    async fn test_wia_revoked() {
        let (token, jwt) = wia();
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: attestation_status(
                token.clone(),
                AttestationType::WalletInstanceAttestation,
                WalletUnitStatusCheckResponse::Revoked,
            ),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::WalletInstance {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::WiaRevoked)
        ));
        assert_eq!(ErrorCode::BR_0505, error.error_code());
    }

    #[tokio::test]
    async fn test_ka_revoked() {
        let (token, jwt) = ka();
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: attestation_status(
                token.clone(),
                AttestationType::KeyAttestation,
                WalletUnitStatusCheckResponse::Revoked,
            ),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::Key {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KaRevoked)
        ));
        assert_eq!(ErrorCode::BR_0499, error.error_code());
    }

    #[tokio::test]
    async fn test_ka_expired_status_period() {
        let (token, jwt) = ka();
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: attestation_status(
                token.clone(),
                AttestationType::KeyAttestation,
                WalletUnitStatusCheckResponse::Expired,
            ),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::Key {
                    token: &token,
                    jwt: &jwt,
                },
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KaRevoked)
        ));
    }
}
