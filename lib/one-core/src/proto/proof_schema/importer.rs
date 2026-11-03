use std::sync::Arc;

use futures::future;
use shared_types::ProofSchemaId;
use uuid::Uuid;

use super::mapper::proof_input_from_import_request;
use super::validator::{proof_schema_name_already_exists, validate_imported_proof_schema};
use super::{Error, ProofSchemaImporter};
use crate::config::core_config::CoreConfig;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::organisation::Organisation;
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::proto::credential_schema::dto::ImportCredentialSchemaV2RequestDTO;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::credential_schema::parser::CredentialSchemaImportParser;
use crate::proto::http_client::HttpClient;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::service::proof_schema::dto::ImportProofSchemaDTO;
use crate::validator::schema::validate_imported_source_url;

pub(crate) struct ProofSchemaImporterProto {
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    credential_schema_import_parser: Arc<dyn CredentialSchemaImportParser>,
    credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
    client: Arc<dyn HttpClient>,
    config: Arc<CoreConfig>,
    base_url: Option<String>,
}

impl ProofSchemaImporterProto {
    pub(crate) fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        credential_schema_import_parser: Arc<dyn CredentialSchemaImportParser>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
        client: Arc<dyn HttpClient>,
        config: Arc<CoreConfig>,
        base_url: Option<String>,
    ) -> Self {
        Self {
            proof_schema_repository,
            credential_schema_import_parser,
            credential_schema_importer,
            client,
            config,
            base_url,
        }
    }
}

#[async_trait::async_trait]
impl ProofSchemaImporter for ProofSchemaImporterProto {
    async fn import_proof_schema(
        &self,
        schema: ImportProofSchemaDTO,
        id: ProofSchemaId,
        organisation: &Organisation,
        imported_source_url: String,
    ) -> Result<(), Error> {
        let imported_source_url = if self.config.global_settings.rehost_imported_schemas
            && let Some(base_url) = self.base_url.as_deref()
        {
            format!("{base_url}/ssi/proof-schema/v1/{id}")
        } else {
            validate_imported_source_url(&imported_source_url)
                .error_while("validating imported source URL")?;
            imported_source_url
        };

        validate_imported_proof_schema(&schema, &self.config)?;

        proof_schema_name_already_exists(
            self.proof_schema_repository.as_ref(),
            &schema.name,
            organisation.id,
        )
        .await?;

        let now = crate::clock::now_utc();
        let input_schemas =
            schema
                .proof_input_schemas
                .into_iter()
                .map(|request_input_schema| async move {
                    let credential_schema = self
                        .credential_schema_import_parser
                        .parse_import_credential_schema_v2(ImportCredentialSchemaV2RequestDTO {
                            organisation: organisation.to_owned(),
                            schema: request_input_schema.credential_schema.clone().into(),
                        })
                        .error_while("parsing credential schema")?;

                    let credential_schema = match self
                        .credential_schema_importer
                        .import_credential_schema(credential_schema)
                        .await
                    {
                        Ok(schema) => schema,
                        Err(crate::proto::credential_schema::Error::AlreadyExists {
                            conflicting: Some(schema),
                        }) => *schema,
                        Err(err) => {
                            return Err(err.error_while("importing credential schema").into());
                        }
                    };

                    proof_input_from_import_request(request_input_schema, credential_schema).await
                });

        let input_schemas: Vec<ProofInputSchema> = future::try_join_all(input_schemas).await?;

        let proof_schema = ProofSchema {
            ecosystem: schema.ecosystem,
            id,
            created_date: now,
            last_modified: now,
            deleted_at: None,
            name: schema.name,
            expire_duration: schema.expire_duration,
            organisation: organisation.clone().into(),
            input_schemas: input_schemas.into(),
            imported_source_url: Some(imported_source_url),
        };
        self.proof_schema_repository
            .create_proof_schema(proof_schema)
            .await
            .error_while("creating proof schema")?;

        Ok(())
    }

    async fn import_proof_schema_from_url(
        &self,
        url: &str,
        organisation: &Organisation,
    ) -> Result<(), Error> {
        let schema = async {
            self.client
                .get(url)
                .send()
                .await?
                .error_for_status()?
                .json::<ImportProofSchemaDTO>()
        }
        .await
        .error_while("downloading proof schema")?;

        self.import_proof_schema(schema, Uuid::new_v4().into(), organisation, url.to_owned())
            .await
    }
}
