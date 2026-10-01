use std::collections::HashSet;

use standardized_types::etsi_119_475::registration_certificate::Payload;

use super::EudiEcosystem;
use super::mapper::map_dcql_credentials;
use crate::error::ErrorCode::{BR_0224, BR_0487};
use crate::error::{ContextWithErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::blob::BlobType;
use crate::model::identifier::{Identifier, IdentifierData};
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

        let rp_id = self.etsi_rp_id_for_identifier(identifier).await?;
        let mut last_reg_cert_jwt: Option<Payload> = None;
        let mut result = Vec::with_capacity(trust_information.len());
        for trust_info in trust_information {
            let reg_cert_info = self
                .wrp_validator
                .validate_registration_certificate(
                    &trust_info.data,
                    rp_id.as_ref().ok_or_else(|| {
                        EcosystemError::InvalidTrustInformation(
                            "No organization_id specified".to_string(),
                        )
                    })?,
                    None,
                    self.config
                        .global_settings
                        .certificate_validation
                        .leeway_seconds,
                )
                .await
                .error_while("validating registration certificate")?;
            if let Some(last_reg_cert) = &last_reg_cert_jwt {
                self.wrp_validator
                    .validate_registration_certificates_consistency(
                        last_reg_cert,
                        &reg_cert_info.payload.custom,
                    )
                    .error_while("validating registration certificates similarity")?;
            }
            last_reg_cert_jwt = Some(reg_cert_info.payload.custom.clone());

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

    /// The single ETSI relying party id shared by all (non-deleted) access certificates of the
    /// identifier, if any. Certificates that are not access certificates are tolerated (the
    /// identifier might carry additional, unrelated certificates).
    async fn etsi_rp_id_for_identifier(
        &self,
        identifier: &Identifier,
    ) -> Result<Option<String>, EcosystemError> {
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
        if rp_ids.len() > 1 {
            return Err(EcosystemError::InvalidTrustInformation(
                "Conflicting organization identifier values specified".to_string(),
            ));
        };
        Ok(rp_ids.into_iter().next())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap as StdHashMap;
    use std::sync::Arc;

    use serde_json::json;
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
    use crate::model::relation::RelatedVec;
    use crate::proto::credential_validity_manager::MockCredentialValidityManager;
    use crate::proto::session_provider::NoSessionProvider;
    use crate::proto::wallet_instance::MockHolderWalletUnitProto;
    use crate::proto::wrp_validator::MockWRPValidator;
    use crate::proto::wrp_validator::error::WRPValidatorError;
    use crate::proto::wrp_validator::model::{
        AccessCertificateResult, RegistrationCertificateResult,
    };
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
            subject: Some("subject".to_string()),
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
                    data: "reg cert jwt".to_string(),
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
    async fn test_parse_trust_information_fails_on_rp_id_conflict() {
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
