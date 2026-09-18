use shared_types::OrganisationId;
use time::Duration;

use super::EudiEcosystem;
use crate::clock::now_utc;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::credential_schema::WalletAttestation;
use crate::model::wallet_instance_attestation::AttestationType;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::wallet_instance::WalletUnitStatusCheckResponse;
use crate::proto::wrp_validator::error::WRPValidatorError;
use crate::provider::ecosystem::error::{
    EcosystemError, RejectionReason, WalletAttestationRejection,
};
use crate::provider::ecosystem::model::WalletAttestationArtifact;
use crate::service::managed_instance::dto::{
    AttestationStatus, WalletInstanceAttestationClaims, WalletUnitAttestationClaims,
};

impl EudiEcosystem {
    pub(super) async fn resolve_wallet_attestation(
        &self,
        attestation: &WalletAttestationArtifact<'_>,
        requirements: &WalletAttestation,
        organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        match attestation {
            WalletAttestationArtifact::WalletInstance { token, jwt } => {
                self.check_wallet_instance_attestation(token, jwt, requirements, organisation_id)
                    .await
            }
            WalletAttestationArtifact::Key { token, jwt } => {
                self.check_key_attestation(token, jwt, requirements, organisation_id)
                    .await
            }
        }
    }

    async fn check_wallet_instance_attestation(
        &self,
        token: &str,
        jwt: &DecomposedJwt<WalletInstanceAttestationClaims>,
        requirements: &WalletAttestation,
        organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        let wallet_provider = jwt
            .wallet_provider_key()
            .error_while("extracting wallet provider key")?;
        self.wrp_validator
            .validate_wallet_provider(wallet_provider, &self.trust_scope(organisation_id))
            .await
            .map_err(|e| match e {
                WRPValidatorError::WalletProviderNotTrusted => {
                    WalletAttestationRejection::WalletInstanceAttestation(
                        RejectionReason::IssuerUntrusted,
                    )
                    .into()
                }
                _ => EcosystemError::Nested(e.error_while("validating wallet provider")),
            })?;

        if !status_period_satisfied(
            jwt.payload.custom.client_status.as_ref(),
            requirements.preferred_instance_attestation_lifetime,
            self.params.leeway_seconds,
        ) {
            return Err(WalletAttestationRejection::WalletInstanceAttestation(
                RejectionReason::StatusPeriod,
            )
            .into());
        }

        let status = self
            .wallet_unit_proto
            .check_attestation_status(token, AttestationType::WalletInstanceAttestation)
            .await
            .error_while("checking wallet attestation status")?;
        match status {
            WalletUnitStatusCheckResponse::Active => Ok(()),
            WalletUnitStatusCheckResponse::Revoked => Err(
                WalletAttestationRejection::WalletInstanceAttestation(RejectionReason::Revoked)
                    .into(),
            ),
            WalletUnitStatusCheckResponse::Expired => {
                Err(WalletAttestationRejection::WalletInstanceAttestation(
                    RejectionReason::StatusPeriod,
                )
                .into())
            }
        }
    }

    async fn check_key_attestation(
        &self,
        token: &str,
        jwt: &DecomposedJwt<WalletUnitAttestationClaims>,
        requirements: &WalletAttestation,
        organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        let wallet_provider = jwt
            .wallet_provider_key()
            .error_while("extracting wallet provider key")?;
        self.wrp_validator
            .validate_wallet_provider(wallet_provider, &self.trust_scope(organisation_id))
            .await
            .map_err(|e| match e {
                WRPValidatorError::WalletProviderNotTrusted => {
                    WalletAttestationRejection::KeyAttestation(RejectionReason::IssuerUntrusted)
                        .into()
                }
                _ => EcosystemError::Nested(e.error_while("validating wallet provider")),
            })?;

        if !status_period_satisfied(
            jwt.payload.custom.key_storage_status.as_ref(),
            requirements.preferred_key_storage_attestation_lifetime,
            self.params.leeway_seconds,
        ) {
            return Err(
                WalletAttestationRejection::KeyAttestation(RejectionReason::StatusPeriod).into(),
            );
        }

        let status = self
            .wallet_unit_proto
            .check_attestation_status(token, AttestationType::KeyAttestation)
            .await
            .error_while("checking wallet attestation status")?;
        match status {
            WalletUnitStatusCheckResponse::Active => Ok(()),
            WalletUnitStatusCheckResponse::Revoked => {
                Err(WalletAttestationRejection::KeyAttestation(RejectionReason::Revoked).into())
            }
            WalletUnitStatusCheckResponse::Expired => Err(
                WalletAttestationRejection::KeyAttestation(RejectionReason::StatusPeriod).into(),
            ),
        }
    }
}

fn status_period_satisfied(
    status: Option<&AttestationStatus>,
    preferred_period: Option<Duration>,
    leeway: Duration,
) -> bool {
    match (status, preferred_period) {
        (None, None) => true,
        (None, Some(_)) => false,
        (Some(status), preferred_period) => {
            status.expires_at >= now_utc() - leeway + preferred_period.unwrap_or(Duration::ZERO)
        }
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
    use crate::model::credential_schema::WalletAttestation;
    use crate::proto::credential_validity_manager::MockCredentialValidityManager;
    use crate::proto::jwt::Jwt;
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

    fn wia_with_status(
        period: Duration,
    ) -> (String, DecomposedJwt<WalletInstanceAttestationClaims>) {
        let token = token(json!({
            "wallet_name": "wallet",
            "client_status": status_claim(period),
        }));
        let jwt = Jwt::<WalletInstanceAttestationClaims>::decompose_token(&token).unwrap();
        (token, jwt)
    }

    fn ka_with_status(period: Duration) -> (String, DecomposedJwt<WalletUnitAttestationClaims>) {
        let token = token(json!({
            "key_storage": [],
            "attested_keys": [],
            "key_storage_status": status_claim(period),
        }));
        let jwt = Jwt::<WalletUnitAttestationClaims>::decompose_token(&token).unwrap();
        (token, jwt)
    }

    fn status_claim(period: Duration) -> serde_json::Value {
        json!({
            "status": { "status_list": { "idx": 0, "uri": "https://example.com/status" } },
            "exp": (now_utc() + period).unix_timestamp(),
        })
    }

    fn no_preference() -> WalletAttestation {
        WalletAttestation {
            require_instance_attestation: true,
            key_storage_security_level: None,
            preferred_key_storage_attestation_lifetime: None,
            preferred_instance_attestation_lifetime: None,
        }
    }

    fn preferred_periods(period: Duration) -> WalletAttestation {
        WalletAttestation {
            preferred_key_storage_attestation_lifetime: Some(period),
            preferred_instance_attestation_lifetime: Some(period),
            ..no_preference()
        }
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
                &no_preference(),
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
                &no_preference(),
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
                &no_preference(),
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
                &no_preference(),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(
                WalletAttestationRejection::WalletInstanceAttestation(
                    RejectionReason::IssuerUntrusted
                )
            )
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
                &no_preference(),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KeyAttestation(
                RejectionReason::IssuerUntrusted
            ))
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
                &no_preference(),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(
                WalletAttestationRejection::WalletInstanceAttestation(RejectionReason::Revoked)
            )
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
                &no_preference(),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KeyAttestation(
                RejectionReason::Revoked
            ))
        ));
        assert_eq!(ErrorCode::BR_0499, error.error_code());
    }

    #[tokio::test]
    async fn test_ka_expired_by_status_check() {
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
                &no_preference(),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KeyAttestation(
                RejectionReason::StatusPeriod
            ))
        ));
        assert_eq!(ErrorCode::BR_0507, error.error_code());
    }

    #[tokio::test]
    async fn test_wia_status_period_satisfied() {
        let (token, jwt) = wia_with_status(Duration::days(31));
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
                &preferred_periods(Duration::days(30)),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_wia_status_period_within_leeway() {
        // within the default 1 minute leeway
        let (token, jwt) = wia_with_status(Duration::days(30) - Duration::seconds(30));
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
                &preferred_periods(Duration::days(30)),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_wia_status_period_too_short() {
        let (token, jwt) = wia_with_status(Duration::days(10));
        // rejected before the status list is consulted
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: MockHolderWalletUnitProto::new(),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::WalletInstance {
                    token: &token,
                    jwt: &jwt,
                },
                &preferred_periods(Duration::days(30)),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(
                WalletAttestationRejection::WalletInstanceAttestation(
                    RejectionReason::StatusPeriod
                )
            )
        ));
        assert_eq!(ErrorCode::BR_0506, error.error_code());
    }

    #[tokio::test]
    async fn test_wia_status_period_ended_without_preference() {
        let (token, jwt) = wia_with_status(-Duration::hours(1));
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: MockHolderWalletUnitProto::new(),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::WalletInstance {
                    token: &token,
                    jwt: &jwt,
                },
                &no_preference(),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(
                WalletAttestationRejection::WalletInstanceAttestation(
                    RejectionReason::StatusPeriod
                )
            )
        ));
    }

    #[tokio::test]
    async fn test_ka_status_period_too_short() {
        let (token, jwt) = ka_with_status(Duration::days(10));
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: MockHolderWalletUnitProto::new(),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::Key {
                    token: &token,
                    jwt: &jwt,
                },
                &preferred_periods(Duration::days(30)),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KeyAttestation(
                RejectionReason::StatusPeriod
            ))
        ));
        assert_eq!(ErrorCode::BR_0507, error.error_code());
    }

    #[tokio::test]
    async fn test_ka_without_status_but_preference_set() {
        let (token, jwt) = ka();
        let ecosystem = setup(Mocks {
            wrp_validator: trusted_wallet_provider(),
            wallet_unit_proto: MockHolderWalletUnitProto::new(),
        });

        let error = ecosystem
            .resolve_wallet_attestation(
                &WalletAttestationArtifact::Key {
                    token: &token,
                    jwt: &jwt,
                },
                &preferred_periods(Duration::days(30)),
                Uuid::new_v4().into(),
            )
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            EcosystemError::WalletAttestation(WalletAttestationRejection::KeyAttestation(
                RejectionReason::StatusPeriod
            ))
        ));
    }
}
