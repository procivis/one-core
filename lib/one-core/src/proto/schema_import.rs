use std::sync::Arc;

use crate::model::organisation::Organisation;
use crate::proto::credential_schema::Error as CredentialSchemaError;
use crate::proto::credential_schema::url_importer::CredentialSchemaUrlImporter;
use crate::proto::proof_schema::{Error as ProofSchemaError, ProofSchemaImporter};

/// Imports the credential and proof schemas published by a remote party.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait SchemaImporter: Send + Sync {
    /// Downloads and imports all credential and proof schemas published under the given URLs.
    ///
    /// Schemas already imported are left as they are, and schemas which cannot be imported
    /// are skipped with the failure only logged - a repeated import must not fail the
    /// caller.
    async fn import_schemas(
        &self,
        credential_schema_urls: &[String],
        proof_schema_urls: &[String],
        organisation: &Organisation,
    );
}

pub(crate) struct SchemaImporterProto {
    credential_schema_url_importer: Arc<dyn CredentialSchemaUrlImporter>,
    proof_schema_importer: Arc<dyn ProofSchemaImporter>,
}

impl SchemaImporterProto {
    pub(crate) fn new(
        credential_schema_url_importer: Arc<dyn CredentialSchemaUrlImporter>,
        proof_schema_importer: Arc<dyn ProofSchemaImporter>,
    ) -> Self {
        Self {
            credential_schema_url_importer,
            proof_schema_importer,
        }
    }
}

#[async_trait::async_trait]
impl SchemaImporter for SchemaImporterProto {
    async fn import_schemas(
        &self,
        credential_schema_urls: &[String],
        proof_schema_urls: &[String],
        organisation: &Organisation,
    ) {
        for url in credential_schema_urls {
            match self
                .credential_schema_url_importer
                .import_credential_schema_from_url(url, organisation.to_owned())
                .await
            {
                Ok(_) => {}
                // A provider re-advertises its schemas on every sync, so meeting one that
                // is already imported is the normal case rather than a failure.
                Err(CredentialSchemaError::AlreadyExists) => {
                    tracing::debug!(%url, "Credential schema already imported");
                }
                Err(err) => tracing::warn!(%err, "Failed to import credential schema"),
            }
        }

        for url in proof_schema_urls {
            match self
                .proof_schema_importer
                .import_proof_schema_from_url(url, organisation)
                .await
            {
                Ok(_) => {}
                Err(ProofSchemaError::AlreadyExists) => {
                    tracing::debug!(%url, "Proof schema already imported");
                }
                Err(err) => tracing::warn!(%err, "Failed to import proof schema"),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use mockall::predicate::{always, eq};

    use super::{SchemaImporter, SchemaImporterProto};
    use crate::proto::credential_schema::Error as CredentialSchemaError;
    use crate::proto::credential_schema::url_importer::MockCredentialSchemaUrlImporter;
    use crate::proto::proof_schema::{Error as ProofSchemaError, MockProofSchemaImporter};
    use crate::service::test_utilities::{dummy_credential_schema, dummy_organisation};

    /// A provider re-advertises its schemas on every sync, so a schema that is already
    /// imported must neither fail the import nor stop the ones that follow it.
    #[tokio::test]
    async fn test_import_schemas_continues_past_already_imported_schemas() {
        let mut credential_schema_importer = MockCredentialSchemaUrlImporter::new();
        credential_schema_importer
            .expect_import_credential_schema_from_url()
            .once()
            .with(eq("https://provider.org/known-credential"), always())
            .returning(|_, _| Err(CredentialSchemaError::AlreadyExists));
        credential_schema_importer
            .expect_import_credential_schema_from_url()
            .once()
            .with(eq("https://provider.org/new-credential"), always())
            .returning(|_, _| Ok(dummy_credential_schema()));

        let mut proof_schema_importer = MockProofSchemaImporter::new();
        proof_schema_importer
            .expect_import_proof_schema_from_url()
            .once()
            .with(eq("https://provider.org/known-proof"), always())
            .returning(|_, _| Err(ProofSchemaError::AlreadyExists));
        proof_schema_importer
            .expect_import_proof_schema_from_url()
            .once()
            .with(eq("https://provider.org/new-proof"), always())
            .returning(|_, _| Ok(()));

        let importer = SchemaImporterProto::new(
            Arc::new(credential_schema_importer),
            Arc::new(proof_schema_importer),
        );

        importer
            .import_schemas(
                &[
                    "https://provider.org/known-credential".to_string(),
                    "https://provider.org/new-credential".to_string(),
                ],
                &[
                    "https://provider.org/known-proof".to_string(),
                    "https://provider.org/new-proof".to_string(),
                ],
                &dummy_organisation(None),
            )
            .await;
    }
}
