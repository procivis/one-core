use std::sync::Arc;

use crate::model::organisation::Organisation;
use crate::proto::credential_schema::url_importer::CredentialSchemaUrlImporter;
use crate::proto::proof_schema::ProofSchemaImporter;

/// Imports the credential and proof schemas published by a remote party.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait SchemaImporter: Send + Sync {
    /// Downloads and imports all credential and proof schemas published under the given URLs.
    ///
    /// Schemas which cannot be imported are skipped, the failure is only logged.
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
        for credential_schema_url in credential_schema_urls {
            if let Err(err) = self
                .credential_schema_url_importer
                .import_credential_schema_from_url(credential_schema_url, organisation.to_owned())
                .await
            {
                tracing::warn!(%err, "Failed to import credential schema");
            }
        }

        for proof_schema_url in proof_schema_urls {
            if let Err(err) = self
                .proof_schema_importer
                .import_proof_schema_from_url(proof_schema_url, organisation)
                .await
            {
                tracing::warn!(%err, "Failed to import proof schema");
            }
        }
    }
}
