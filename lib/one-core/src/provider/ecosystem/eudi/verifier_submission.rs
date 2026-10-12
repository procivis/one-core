use shared_types::OrganisationId;

use super::mapper::formatter_requires_namespaces;
use super::{EudiEcosystem, pid_schema_ids};
use crate::error::ContextWithErrorCode;
use crate::model::claim::Claim;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::ecosystem::EcosystemTrustResult;
use crate::model::relation::{Related, RelatedVec};
use crate::proto::wrp_validator::credential_category;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::error::EcosystemError;
#[cfg(test)]
use crate::service::test_utilities::CredentialBuilder;

impl EudiEcosystem {
    pub(super) async fn resolve_verifier_submission(
        &self,
        claims: &RelatedVec<Claim>,
        schema_format: &Related<CredentialSchemaFormat>,
        issuer_details: &IdentifierDetails,
        organisation_id: OrganisationId,
    ) -> Result<EcosystemTrustResult, EcosystemError> {
        let schema_format = schema_format.as_ref().await?;
        let format = &schema_format.format;
        let formatter = self.formatter_provider.get_credential_formatter(format)?;

        let namespaced = formatter_requires_namespaces(formatter.as_ref());
        let claims = claims.as_ref().await?;
        let category = credential_category(&claims, namespaced);

        let IdentifierDetails::Certificate(issuer_certificate) = issuer_details else {
            return Err(EcosystemError::MissingIdentifier);
        };

        let trust_entity = self
            .wrp_validator
            .validate_credential_issuer(
                Some(&issuer_certificate.chain),
                &schema_format,
                &pid_schema_ids(&self.params.credential_schemas, format),
                category,
                issuer_certificate.x5_references,
                &self.trust_scope(organisation_id),
            )
            .await
            .error_while("validating credential issuer")?;

        Ok(if trust_entity.is_some() {
            EcosystemTrustResult::Trusted
        } else {
            EcosystemTrustResult::Compliant
        })
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use rstest::rstest;
    use serde_json::json;
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::config::core_config::CoreConfig;
    use crate::model::credential::Credential;
    use crate::proto::credential_validity_manager::MockCredentialValidityManager;
    use crate::proto::session_provider::NoSessionProvider;
    use crate::proto::wallet_instance::MockHolderWalletUnitProto;
    use crate::proto::wrp_validator::MockWRPValidator;
    use crate::provider::blob_storage::provider::MockBlobStorageProvider;
    use crate::provider::credential_formatter::MockCredentialFormatter;
    use crate::provider::credential_formatter::model::CertificateDetails;
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::trust_list_subscriber::etsi_lotl::model::TslServiceEntry;
    use crate::provider::trust_list_subscriber::{TrustEntityMetadata, TrustEntityResponse};
    use crate::repository::credential_repository::MockCredentialRepository;
    use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::repository::proof_schema_repository::MockProofSchemaRepository;
    use crate::service::test_utilities::{dummy_credential, generic_formatter_capabilities};

    #[rstest]
    #[case::trusted(EcosystemTrustResult::Trusted)]
    #[case::compliant(EcosystemTrustResult::Compliant)]
    #[tokio::test]
    async fn uses_concrete_format_and_preserves_issuer_verdict(
        #[case] expected: EcosystemTrustResult,
    ) {
        let mut credential = dummy_credential();
        let mut schema = credential
            .common()
            .schema
            .as_ref()
            .await
            .unwrap()
            .to_owned();
        let first = schema.formats.as_ref().await.unwrap()[0].clone();
        let mut selected = first.clone();
        selected.id = Uuid::new_v4().into();
        selected.format = "MDOC".into();
        selected.ecosystem_schema_id = "mdoc-pid".into();
        schema.formats = vec![first, selected.clone()].into();
        credential.common_mut().schema = schema.into();
        credential = CredentialBuilder {
            format: Some(selected.clone().into()),
            ..credential.into()
        }
        .build();

        let mut formatter = MockCredentialFormatter::new();
        formatter
            .expect_get_capabilities()
            .returning(generic_formatter_capabilities);
        let mut formatters = MockCredentialFormatterProvider::new();
        formatters
            .expect_get_credential_formatter()
            .withf(|format| format == &"MDOC".into())
            .times(1)
            .return_once(|_| Ok(Arc::new(formatter)));
        let mut wrp = MockWRPValidator::new();
        wrp.expect_validate_credential_issuer().times(1).returning(
            move |_, format, pid_ids, _, _, _| {
                assert_eq!(format.id, selected.id);
                assert_eq!(format.ecosystem_schema_id, "mdoc-pid");
                assert_eq!(pid_ids, &["mdoc-pid".to_string()]);
                Ok(
                    (expected == EcosystemTrustResult::Trusted).then(|| TrustEntityResponse {
                        derived_role: None,
                        metadata: TrustEntityMetadata::Tsl(TslServiceEntry {
                            service_name: "PID provider".into(),
                            service_type_identifier: "pid".into(),
                            service_status: "active".into(),
                        }),
                    }),
                )
            },
        );
        let ecosystem = EudiEcosystem::new(
            "EUDI".into(),
            json!({"credentialSchemas": [{"format": "MDOC", "pidSchemaIds": ["mdoc-pid"]}]}),
            CoreConfig::default(),
            Arc::new(MockHistoryRepository::new()),
            Arc::new(wrp),
            Arc::new(MockBlobStorageProvider::new()),
            Arc::new(NoSessionProvider),
            Arc::new(formatters),
            Arc::new(MockCredentialRepository::new()),
            Arc::new(MockCredentialSchemaRepository::new()),
            Arc::new(MockProofSchemaRepository::new()),
            Arc::new(MockHolderWalletUnitProto::new()),
            Arc::new(MockCredentialValidityManager::new()),
        )
        .unwrap();
        let issuer = IdentifierDetails::Certificate(CertificateDetails {
            chain: "issuer-chain".into(),
            fingerprint: "fingerprint".into(),
            expiry: crate::clock::now_utc(),
            subject_common_name: None,
            x5_references: Default::default(),
        });
        assert2::let_assert!(
            Credential::IssuerSingle {
                claims,
                credential,
                ..
            } = credential
        );
        let result = ecosystem
            .resolve_verifier_submission(
                &claims,
                &credential.format,
                &issuer,
                Uuid::new_v4().into(),
            )
            .await
            .unwrap();
        assert_eq!(expected, result);
    }
}
