use std::collections::{HashMap, HashSet};

use shared_types::IdentifierTrustInformationId;
use standardized_types::etsi_119_475::registration_certificate::Payload;

use super::EudiEcosystem;
use super::mapper::map_dcql_credentials;
use crate::config::core_config::BlobStorageType;
use crate::error::ErrorCode::{BR_0224, BR_0487};
use crate::error::{ContextWithErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::blob::BlobType;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::{
    IdentifierTrustInformationType, ParsedTrustInformation, TrustInformationInput,
};

impl EudiEcosystem {
    pub(super) async fn parse_trust_information(
        &self,
        identifier: &Identifier,
        trust_information: &[TrustInformationInput],
    ) -> Result<Vec<ParsedTrustInformation>, EcosystemError> {
        if trust_information
            .iter()
            .any(|info| info.r#type != IdentifierTrustInformationType::RegistrationCertificate)
        {
            return Err(EcosystemError::NotApplicable);
        }

        let rp_ids = self.etsi_rp_ids_for_identifier(identifier).await?;
        if rp_ids.is_empty() && !trust_information.is_empty() {
            return Err(EcosystemError::InvalidTrustInformation(
                "No ETSI wallet relying party organization_id specified".to_string(),
            ));
        }
        let mut reg_certs_by_rp: HashMap<&str, Payload> = HashMap::new();
        let mut result = Vec::with_capacity(trust_information.len());
        for trust_info in trust_information {
            // Use the unverified subject only to select an existing relying party. The
            // validator below still verifies the JWT and checks that its subject matches.
            let parsed: DecomposedJwt<()> = Jwt::decompose_token(&trust_info.data)
                .error_while("parsing registration certificate")?;
            let rp_id = parsed
                .payload
                .subject
                .as_ref()
                .and_then(|subject| rp_ids.get(subject))
                .ok_or_else(|| {
                    EcosystemError::InvalidTrustInformation(
                        "No access certificate matches the registration certificate subject"
                            .to_string(),
                    )
                })?;
            let reg_cert_info = self
                .wrp_validator
                .validate_registration_certificate(
                    &trust_info.data,
                    rp_id,
                    None,
                    self.config
                        .global_settings
                        .certificate_validation
                        .leeway_seconds,
                )
                .await
                .error_while("validating registration certificate")?;
            if let Some(last_reg_cert) = reg_certs_by_rp.get(rp_id.as_str()) {
                self.wrp_validator
                    .validate_registration_certificates_consistency(
                        last_reg_cert,
                        &reg_cert_info.payload.custom,
                    )
                    .error_while("validating registration certificates similarity")?;
            }
            reg_certs_by_rp.insert(rp_id.as_str(), reg_cert_info.payload.custom.clone());

            result.push(ParsedTrustInformation {
                valid_from: reg_cert_info.payload.invalid_before,
                valid_to: reg_cert_info.payload.expires_at,
                intended_use: reg_cert_info.payload.custom.intended_use_id,
                allowed_issuance_types: map_dcql_credentials(
                    reg_cert_info
                        .payload
                        .custom
                        .provides_attestations
                        .unwrap_or_default(),
                )?,
                allowed_verification_types: map_dcql_credentials(
                    reg_cert_info.payload.custom.credentials.unwrap_or_default(),
                )?,
                blob_type: BlobType::RegistrationCertificate,
            });
        }
        Ok(result)
    }

    pub(super) async fn find_orphaned_trust_information(
        &self,
        identifier: &Identifier,
    ) -> Result<Vec<IdentifierTrustInformationId>, EcosystemError> {
        let trust_information = identifier.trust_information.as_ref().await?;
        if trust_information.is_empty() {
            return Ok(vec![]);
        }

        let rp_ids = self.etsi_rp_ids_for_identifier(identifier).await?;

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        let mut orphaned = Vec::new();
        for info in &trust_information {
            let blob = blob_storage
                .get(&info.blob_id)
                .await
                .error_while("loading trust information blob")?
                .ok_or_else(|| {
                    EcosystemError::MappingError(format!(
                        "Trust information blob {} not found",
                        info.blob_id
                    ))
                })?;
            let blob_value = std::str::from_utf8(&blob.value).map_err(|e| {
                EcosystemError::MappingError(format!("failed to parse blob value: {e}"))
            })?;
            let parsed: DecomposedJwt<()> =
                Jwt::decompose_token(blob_value).error_while("parsing trust information blob")?;

            let covered = parsed
                .payload
                .subject
                .is_some_and(|subject| rp_ids.contains(&subject));
            if !covered {
                orphaned.push(info.id);
            }
        }
        Ok(orphaned)
    }

    /// The ETSI relying party ids of all non-deleted access certificates of the
    /// identifier. Certificates that are not access certificates are tolerated (the
    /// identifier might carry additional, unrelated certificates).
    async fn etsi_rp_ids_for_identifier(
        &self,
        identifier: &Identifier,
    ) -> Result<HashSet<String>, EcosystemError> {
        let mut rp_ids = HashSet::new();
        let certificates = match &identifier.data {
            IdentifierData::Certificate(certificates)
            | IdentifierData::CertificateAuthority(certificates) => certificates
                .as_ref()
                .await?
                .iter()
                .filter(|cert| cert.deleted_at.is_none())
                .cloned()
                .collect::<Vec<_>>(),
            _ => vec![],
        };
        for cert in &certificates {
            let result = self
                .wrp_validator
                .validate_access_certificate(&cert.chain, None)
                .await;
            match result {
                Ok(ac_info) => {
                    rp_ids.insert(ac_info.relying_party_id);
                }
                Err(err) if matches!(err.error_code(), BR_0224 | BR_0487) => {
                    // ignore this error, as the identifier might have additional certificates
                    // that are not access certificates
                }
                Err(err) => return Err(err.error_while("validating access cert").into()),
            }
        }
        Ok(rp_ids)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap as StdHashMap;
    use std::sync::Arc;

    use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
    use serde_json::json;
    use shared_types::BlobId;
    use similar_asserts::assert_eq;
    use standardized_types::etsi_119_475::Credential;
    use standardized_types::etsi_119_475::registration_certificate::{
        Status, SupervisoryAuthority,
    };
    use standardized_types::openid4vp::dcql::{CredentialFormat, SdJwtVcMeta};
    use url::Url;
    use uuid::Uuid;

    use super::*;
    use crate::config::core_config::CoreConfig;
    use crate::error::ErrorCode;
    use crate::model::blob::Blob;
    use crate::model::relation::RelatedVec;
    use crate::proto::credential_validity_manager::MockCredentialValidityManager;
    use crate::proto::session_provider::NoSessionProvider;
    use crate::proto::wallet_instance::MockHolderWalletUnitProto;
    use crate::proto::wrp_validator::MockWRPValidator;
    use crate::proto::wrp_validator::error::WRPValidatorError;
    use crate::proto::wrp_validator::model::{
        AccessCertificateResult, RegistrationCertificateResult,
    };
    use crate::provider::blob_storage::MockBlobStorage;
    use crate::provider::blob_storage::provider::MockBlobStorageProvider;
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::signer::registration_certificate::model::WRPRegistrationCertificatePayload;
    use crate::repository::credential_repository::MockCredentialRepository;
    use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::repository::proof_schema_repository::MockProofSchemaRepository;
    use crate::service::test_utilities::{dummy_certificate, dummy_identifier};

    #[derive(Default)]
    struct Mocks {
        wrp_validator: MockWRPValidator,
        blob_storage_provider: MockBlobStorageProvider,
    }

    fn setup(mocks: Mocks) -> EudiEcosystem {
        EudiEcosystem::new(
            "EUDI".into(),
            json!({}),
            CoreConfig::default(),
            Arc::new(MockHistoryRepository::new()),
            Arc::new(mocks.wrp_validator),
            Arc::new(mocks.blob_storage_provider),
            Arc::new(NoSessionProvider),
            Arc::new(MockCredentialFormatterProvider::new()),
            Arc::new(MockCredentialRepository::new()),
            Arc::new(MockCredentialSchemaRepository::new()),
            Arc::new(MockProofSchemaRepository::new()),
            Arc::new(MockHolderWalletUnitProto::new()),
            Arc::new(MockCredentialValidityManager::new()),
        )
        .unwrap()
    }

    fn dummy_reg_cert_payload() -> WRPRegistrationCertificatePayload {
        WRPRegistrationCertificatePayload {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: Some("rp1".to_string()),
            audience: None,
            jwt_id: None,
            proof_of_possession_key: None,
            custom: Payload {
                name: "".to_string(),
                sub_ln: None,
                sub_gn: None,
                sub_fn: None,
                country: "".to_string(),
                registry_uri: Url::parse("https://example.com").unwrap(),
                service_descriptions: vec![],
                entitlements: vec![],
                privacy_policy: Url::parse("https://example.com").unwrap(),
                info_uri: Url::parse("https://example.com").unwrap(),
                supervisory_authority: SupervisoryAuthority {
                    email: "".to_string(),
                    phone: "".to_string(),
                    uri: "".to_string(),
                },
                policy_id: vec![],
                certificate_policy: Url::parse("https://example.com").unwrap(),
                status: Status {
                    status_list: StdHashMap::new(),
                },
                provides_attestations: Some(vec![Credential {
                    format: CredentialFormat::SdJwtVc(SdJwtVcMeta {
                        vct_values: vec!["https://example.com".to_string()],
                    }),
                    claim: None,
                }]),
                credentials: Some(vec![Credential {
                    format: CredentialFormat::SdJwtVc(SdJwtVcMeta {
                        vct_values: vec!["https://example2.com".to_string()],
                    }),
                    claim: None,
                }]),
                purpose: None,
                intended_use_id: Some("intended_use_id".to_string()),
                public_body: None,
                support_uri: Url::parse("https://example.com").unwrap(),
                intermediary: None,
            },
        }
    }

    fn identifier_with_certificates(
        certificates: Vec<crate::model::certificate::Certificate>,
    ) -> Identifier {
        let mut identifier = dummy_identifier();
        identifier.data = IdentifierData::Certificate(RelatedVec::from(certificates));
        identifier
    }

    fn fake_jwt(sub: &str) -> String {
        fake_jwt_with_payload(json!({ "sub": sub }))
    }

    fn fake_jwt_with_payload(payload: serde_json::Value) -> String {
        let header = Base64UrlSafeNoPadding::encode_to_string(r#"{"alg":"none"}"#).unwrap();
        let payload = Base64UrlSafeNoPadding::encode_to_string(payload.to_string()).unwrap();
        format!("{header}.{payload}.")
    }

    fn dummy_trust_info(
        id: IdentifierTrustInformationId,
        identifier_id: shared_types::IdentifierId,
        blob_id: BlobId,
    ) -> crate::model::identifier_trust_information::IdentifierTrustInformation {
        crate::model::identifier_trust_information::IdentifierTrustInformation {
            id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            valid_from: None,
            valid_to: None,
            intended_use: None,
            allowed_issuance_types: vec![],
            allowed_verification_types: vec![],
            identifier_id,
            blob_id,
        }
    }

    fn blob_storage_provider_returning(jwt: String) -> MockBlobStorageProvider {
        let mut blob_storage = MockBlobStorage::default();
        blob_storage.expect_get().returning(move |id| {
            Ok(Some(Blob {
                id: *id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                value: jwt.clone().into_bytes(),
                r#type: BlobType::RegistrationCertificate,
            }))
        });
        let blob_storage = Arc::new(blob_storage);
        let mut blob_storage_provider = MockBlobStorageProvider::default();
        blob_storage_provider
            .expect_get_blob_storage()
            .returning(move |_| Ok(blob_storage.clone()));
        blob_storage_provider
    }

    fn access_certificate_validator(relying_party_id: &'static str) -> MockWRPValidator {
        let mut wrp_validator = MockWRPValidator::new();
        wrp_validator
            .expect_validate_access_certificate()
            .once()
            .returning(move |_, _| {
                Ok(AccessCertificateResult {
                    trust_entity: None,
                    relying_party_id: relying_party_id.to_string(),
                    registry_url: None,
                })
            });
        wrp_validator
    }

    #[tokio::test]
    async fn test_find_orphaned_trust_information_returns_all_when_no_certificates() {
        let identifier_id = Uuid::new_v4().into();
        let mut identifier = identifier_with_certificates(vec![]);
        let trust_info_id = Uuid::new_v4().into();
        identifier.trust_information = RelatedVec::from(vec![dummy_trust_info(
            trust_info_id,
            identifier_id,
            Uuid::new_v4().into(),
        )]);

        let ecosystem = setup(Mocks {
            blob_storage_provider: blob_storage_provider_returning(fake_jwt("rp1")),
            ..Default::default()
        });

        let orphaned = ecosystem
            .find_orphaned_trust_information(&identifier)
            .await
            .unwrap();

        assert_eq!(orphaned, vec![trust_info_id]);
    }

    #[tokio::test]
    async fn test_find_orphaned_trust_information_keeps_matching_sub() {
        let identifier_id = Uuid::new_v4().into();
        let mut identifier = identifier_with_certificates(vec![dummy_certificate(identifier_id)]);
        let trust_info_id = Uuid::new_v4().into();
        identifier.trust_information = RelatedVec::from(vec![dummy_trust_info(
            trust_info_id,
            identifier_id,
            Uuid::new_v4().into(),
        )]);

        let ecosystem = setup(Mocks {
            wrp_validator: access_certificate_validator("rp1"),
            blob_storage_provider: blob_storage_provider_returning(fake_jwt("rp1")),
        });

        let orphaned = ecosystem
            .find_orphaned_trust_information(&identifier)
            .await
            .unwrap();

        assert!(orphaned.is_empty());
    }

    #[tokio::test]
    async fn test_find_orphaned_trust_information_flags_mismatched_sub() {
        let identifier_id = Uuid::new_v4().into();
        let mut identifier = identifier_with_certificates(vec![dummy_certificate(identifier_id)]);
        let trust_info_id = Uuid::new_v4().into();
        identifier.trust_information = RelatedVec::from(vec![dummy_trust_info(
            trust_info_id,
            identifier_id,
            Uuid::new_v4().into(),
        )]);

        let ecosystem = setup(Mocks {
            wrp_validator: access_certificate_validator("rp1"),
            blob_storage_provider: blob_storage_provider_returning(fake_jwt("someone-else")),
        });

        let orphaned = ecosystem
            .find_orphaned_trust_information(&identifier)
            .await
            .unwrap();

        assert_eq!(orphaned, vec![trust_info_id]);
    }

    #[tokio::test]
    async fn test_find_orphaned_trust_information_keeps_all_remaining_relying_parties() {
        let identifier_id = Uuid::new_v4().into();
        let certificates = [("rp1", false), ("rp2", false), ("rp1", true), ("rp3", true)].map(
            |(rp_id, deleted)| {
                let mut cert = dummy_certificate(identifier_id);
                cert.chain = rp_id.to_string();
                cert.deleted_at = deleted.then(crate::clock::now_utc);
                cert
            },
        );
        let mut identifier = identifier_with_certificates(certificates.into());
        let trust_information = ["rp1", "rp2", "rp3"].map(|rp_id| {
            (
                dummy_trust_info(Uuid::new_v4().into(), identifier_id, Uuid::new_v4().into()),
                rp_id,
            )
        });
        let orphaned_id = trust_information[2].0.id;
        identifier.trust_information = RelatedVec::from(
            trust_information
                .iter()
                .map(|(info, _)| info.clone())
                .collect::<Vec<_>>(),
        );

        let mut wrp_validator = MockWRPValidator::new();
        wrp_validator
            .expect_validate_access_certificate()
            .times(2)
            .returning(|chain, _| {
                Ok(AccessCertificateResult {
                    trust_entity: None,
                    relying_party_id: chain.to_string(),
                    registry_url: None,
                })
            });
        let mut blob_storage = MockBlobStorage::default();
        blob_storage.expect_get().times(3).returning(move |id| {
            let (_, rp_id) = trust_information
                .iter()
                .find(|(info, _)| info.blob_id == *id)
                .unwrap();
            Ok(Some(Blob {
                id: *id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                value: fake_jwt(rp_id).into_bytes(),
                r#type: BlobType::RegistrationCertificate,
            }))
        });
        let blob_storage = Arc::new(blob_storage);
        let mut blob_storage_provider = MockBlobStorageProvider::default();
        blob_storage_provider
            .expect_get_blob_storage()
            .returning(move |_| Ok(blob_storage.clone()));
        let ecosystem = setup(Mocks {
            wrp_validator,
            blob_storage_provider,
        });

        let orphaned = ecosystem
            .find_orphaned_trust_information(&identifier)
            .await
            .unwrap();

        assert_eq!(orphaned, vec![orphaned_id]);
    }

    #[tokio::test]
    async fn test_parse_trust_information_accepts_valid_registration_certificate() {
        let identifier_id = Uuid::new_v4().into();
        let identifier = identifier_with_certificates(vec![dummy_certificate(identifier_id)]);

        let mut wrp_validator = MockWRPValidator::new();
        wrp_validator
            .expect_validate_access_certificate()
            .once()
            .returning(|_, _| {
                Ok(AccessCertificateResult {
                    trust_entity: None,
                    relying_party_id: "rp1".to_string(),
                    registry_url: None,
                })
            });
        wrp_validator
            .expect_validate_registration_certificate()
            .once()
            .returning(|_, rp_id, _, _| {
                assert_eq!(rp_id, "rp1");
                Ok(RegistrationCertificateResult {
                    trust_entity: None,
                    payload: dummy_reg_cert_payload(),
                })
            });

        let ecosystem = setup(Mocks {
            wrp_validator,
            ..Default::default()
        });

        let result = ecosystem
            .parse_trust_information(
                &identifier,
                &[TrustInformationInput {
                    data: fake_jwt("rp1"),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                }],
            )
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].blob_type, BlobType::RegistrationCertificate);
        assert_eq!(result[0].intended_use, Some("intended_use_id".to_string()));
        assert_eq!(result[0].allowed_issuance_types.len(), 1);
        assert_eq!(result[0].allowed_verification_types.len(), 1);
    }

    #[tokio::test]
    async fn test_parse_trust_information_accepts_multiple_relying_parties() {
        let identifier_id = Uuid::new_v4().into();
        let mut cert_a = dummy_certificate(identifier_id);
        cert_a.chain = "chain-a".to_string();
        let mut cert_b = dummy_certificate(identifier_id);
        cert_b.chain = "chain-b".to_string();
        let identifier = identifier_with_certificates(vec![cert_a, cert_b]);

        let mut wrp_validator = MockWRPValidator::new();
        wrp_validator
            .expect_validate_access_certificate()
            .times(2)
            .returning(|chain, _| {
                let relying_party_id = if chain == "chain-a" { "rp1" } else { "rp2" };
                Ok(AccessCertificateResult {
                    trust_entity: None,
                    relying_party_id: relying_party_id.to_string(),
                    registry_url: None,
                })
            });
        wrp_validator
            .expect_validate_registration_certificate()
            .times(4)
            .returning(|token, rp_id, _, _| {
                assert_eq!(token, fake_jwt(rp_id));
                let mut payload = dummy_reg_cert_payload();
                payload.subject = Some(rp_id.to_string());
                payload.custom.name = rp_id.to_string();
                payload.custom.intended_use_id = Some(rp_id.to_string());
                Ok(RegistrationCertificateResult {
                    trust_entity: None,
                    payload,
                })
            });
        wrp_validator
            .expect_validate_registration_certificates_consistency()
            .times(2)
            .returning(|first, second| {
                assert_eq!(first.name, second.name);
                Ok(())
            });

        let ecosystem = setup(Mocks {
            wrp_validator,
            ..Default::default()
        });

        let result = ecosystem
            .parse_trust_information(
                &identifier,
                // Interleave the relying parties to check consistency within each group.
                &["rp1", "rp2", "rp1", "rp2"].map(|rp_id| TrustInformationInput {
                    data: fake_jwt(rp_id),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                }),
            )
            .await
            .unwrap();

        assert_eq!(
            result
                .iter()
                .map(|info| info.intended_use.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("rp1"), Some("rp2"), Some("rp1"), Some("rp2")]
        );
    }

    #[tokio::test]
    async fn test_parse_trust_information_rejects_inconsistent_certificates_for_same_rp() {
        let identifier_id = Uuid::new_v4().into();
        let identifier = identifier_with_certificates(vec![dummy_certificate(identifier_id)]);
        let mut wrp_validator = access_certificate_validator("rp1");
        wrp_validator
            .expect_validate_registration_certificate()
            .times(2)
            .returning(|_, _, _, _| {
                Ok(RegistrationCertificateResult {
                    trust_entity: None,
                    payload: dummy_reg_cert_payload(),
                })
            });
        wrp_validator
            .expect_validate_registration_certificates_consistency()
            .once()
            .returning(|_, _| {
                Err(WRPValidatorError::RegistrationCertificateMissmatch {
                    field_name: "name".to_string(),
                    first_value: "first name".to_string(),
                    second_value: "second name".to_string(),
                })
            });
        let ecosystem = setup(Mocks {
            wrp_validator,
            ..Default::default()
        });

        let error = ecosystem
            .parse_trust_information(
                &identifier,
                &["rp1", "rp1"].map(|rp_id| TrustInformationInput {
                    data: fake_jwt(rp_id),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                }),
            )
            .await
            .unwrap_err();

        assert_eq!(error.error_code(), ErrorCode::BR_0224);
    }

    #[rstest::rstest]
    #[case(json!({ "sub": "unknown-rp" }))]
    #[case(json!({ "sub": "deleted-rp" }))]
    #[case(json!({}))]
    #[tokio::test]
    async fn test_parse_trust_information_rejects_subject_without_access_certificate(
        #[case] payload: serde_json::Value,
    ) {
        let identifier_id = Uuid::new_v4().into();
        let mut deleted_cert = dummy_certificate(identifier_id);
        deleted_cert.chain = "deleted-rp".to_string();
        deleted_cert.deleted_at = Some(crate::clock::now_utc());
        let identifier =
            identifier_with_certificates(vec![dummy_certificate(identifier_id), deleted_cert]);
        let ecosystem = setup(Mocks {
            wrp_validator: access_certificate_validator("rp1"),
            ..Default::default()
        });

        let error = ecosystem
            .parse_trust_information(
                &identifier,
                &[TrustInformationInput {
                    data: fake_jwt_with_payload(payload),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                }],
            )
            .await
            .unwrap_err();

        assert_eq!(error.error_code(), ErrorCode::BR_0416);
    }

    #[tokio::test]
    async fn test_parse_trust_information_propagates_registration_certificate_validation_error() {
        let identifier_id = Uuid::new_v4().into();
        let identifier = identifier_with_certificates(vec![dummy_certificate(identifier_id)]);
        let mut wrp_validator = access_certificate_validator("rp1");
        wrp_validator
            .expect_validate_registration_certificate()
            .once()
            .returning(|_, rp_id, _, _| {
                assert_eq!(rp_id, "rp1");
                Err(WRPValidatorError::MissingIssuer)
            });
        let ecosystem = setup(Mocks {
            wrp_validator,
            ..Default::default()
        });

        let error = ecosystem
            .parse_trust_information(
                &identifier,
                &[TrustInformationInput {
                    data: fake_jwt("rp1"),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                }],
            )
            .await
            .unwrap_err();

        assert_eq!(error.error_code(), ErrorCode::BR_0492);
    }

    #[tokio::test]
    async fn test_parse_trust_information_fails_when_no_access_certificate() {
        let identifier_id = Uuid::new_v4().into();
        let mut cert = dummy_certificate(identifier_id);
        cert.chain = "not an access certificate".to_string();
        let identifier = identifier_with_certificates(vec![cert]);

        let mut wrp_validator = MockWRPValidator::new();
        wrp_validator
            .expect_validate_access_certificate()
            .once()
            .returning(|_, _| Err(WRPValidatorError::MissingSigningDetails));

        let ecosystem = setup(Mocks {
            wrp_validator,
            ..Default::default()
        });

        let result = ecosystem
            .parse_trust_information(
                &identifier,
                &[TrustInformationInput {
                    data: "reg cert jwt".to_string(),
                    r#type: IdentifierTrustInformationType::RegistrationCertificate,
                }],
            )
            .await;

        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0416);
    }
}
