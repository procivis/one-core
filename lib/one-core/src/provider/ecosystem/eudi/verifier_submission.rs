use shared_types::OrganisationId;

use super::mapper::formatter_requires_namespaces;
use super::{EudiEcosystem, pid_schema_ids};
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::relation::OptionalRelatedExt;
use crate::proto::wrp_validator::credential_category;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::error::EcosystemError;

impl EudiEcosystem {
    pub(super) async fn resolve_verifier_submission(
        &self,
        credential: &Credential,
        issuer_details: &IdentifierDetails,
        organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        let schema_format = credential.format.as_required_ref().await?;
        let format = &schema_format.format;
        let formatter = self.formatter_provider.get_credential_formatter(format)?;

        let namespaced = formatter_requires_namespaces(formatter.as_ref());
        let claims = credential.claims.as_ref().await?;
        let category = credential_category(&claims, namespaced);

        let IdentifierDetails::Certificate(issuer_certificate) = issuer_details else {
            return Err(EcosystemError::MissingIdentifier);
        };

        self.wrp_validator
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

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use serde_json::json;
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::config::core_config::CoreConfig;
    use crate::proto::credential_validity_manager::MockCredentialValidityManager;
    use crate::proto::session_provider::NoSessionProvider;
    use crate::proto::wallet_instance::MockHolderWalletUnitProto;
    use crate::proto::wrp_validator::MockWRPValidator;
    use crate::provider::blob_storage::provider::MockBlobStorageProvider;
    use crate::provider::credential_formatter::MockCredentialFormatter;
    use crate::provider::credential_formatter::model::CertificateDetails;
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::repository::credential_repository::MockCredentialRepository;
    use crate::repository::credential_schema_repository::MockCredentialSchemaRepository;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::repository::interaction_repository::MockInteractionRepository;
    use crate::repository::proof_schema_repository::MockProofSchemaRepository;
    use crate::service::test_utilities::{dummy_credential, generic_formatter_capabilities};

    #[tokio::test]
    async fn uses_concrete_format_from_multiformat_schema() {
        let mut credential = dummy_credential();
        let mut schema = credential.schema.as_ref().await.unwrap().to_owned();
        let first = schema.formats.as_ref().await.unwrap()[0].clone();
        let mut selected = first.clone();
        selected.id = Uuid::new_v4().into();
        selected.format = "MDOC".into();
        selected.ecosystem_schema_id = "mdoc-pid".into();
        schema.formats = vec![first, selected.clone()].into();
        credential.schema = schema.into();
        credential.format = Some(selected.clone().into());

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
                Ok(None)
            },
        );
        let ecosystem = EudiEcosystem::new(
            "EUDI".into(),
            json!({"credentialSchemas": [{"format": "MDOC", "pidSchemaIds": ["mdoc-pid"]}]}),
            CoreConfig::default(),
            Arc::new(MockHistoryRepository::new()),
            Arc::new(MockInteractionRepository::new()),
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
        ecosystem
            .resolve_verifier_submission(&credential, &issuer, Uuid::new_v4().into())
            .await
            .unwrap();
    }
}
