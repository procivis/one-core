use std::sync::Arc;

use futures::future;
use shared_types::ProofSchemaId;
use uuid::Uuid;

use super::mapper::proof_input_from_import_request;
use super::validator::{proof_schema_name_already_exists, validate_imported_proof_schema};
use super::{Error, ProofSchemaImporter};
use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::model::credential_schema::CredentialSchemaListQuery;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::organisation::Organisation;
use crate::model::proof_schema::{ProofInputSchema, ProofSchema};
use crate::proto::credential_schema::url_importer::CredentialSchemaUrlImporter;
use crate::proto::http_client::HttpClient;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;
use crate::service::proof_schema::dto::ImportProofSchemaDTO;

pub(crate) struct ProofSchemaImporterProto {
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    credential_schema_url_importer: Arc<dyn CredentialSchemaUrlImporter>,
    client: Arc<dyn HttpClient>,
    config: Arc<CoreConfig>,
}

impl ProofSchemaImporterProto {
    pub(crate) fn new(
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        credential_schema_url_importer: Arc<dyn CredentialSchemaUrlImporter>,
        client: Arc<dyn HttpClient>,
        config: Arc<CoreConfig>,
    ) -> Self {
        Self {
            proof_schema_repository,
            credential_schema_repository,
            credential_schema_url_importer,
            client,
            config,
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
        validate_imported_proof_schema(&schema, &self.config)?;

        proof_schema_name_already_exists(
            self.proof_schema_repository.as_ref(),
            &schema.name,
            organisation.id,
        )
        .await?;

        let now = crate::clock::now_utc();
        let input_schemas = schema
            .proof_input_schemas
            .into_iter()
            .map(|request_input_schema| {
                async move {
                    // check if the credential schema already exists
                    let maybe_credential_schema = self
                        .credential_schema_repository
                        .get_credential_schema_list(CredentialSchemaListQuery {
                            include_count: false,
                            pagination: Some(ListPagination {
                                page: 0,
                                page_size: 1,
                            }),
                            filtering: Some(
                                CredentialSchemaFilterValue::OrganisationId(organisation.id)
                                    .condition()
                                    & CredentialSchemaFilterValue::EcosystemSchemaId(
                                        StringMatch::equals(
                                            &request_input_schema.credential_schema.schema_id,
                                        ),
                                    )
                                    .condition(),
                            ),
                            ..Default::default()
                        })
                        .await
                        .error_while("getting credential schema")?
                        .values
                        .into_iter()
                        .next();

                    let credential_schema =
                        // if not exists (or deleted) create new credential schema
                        if let Some(credential_schema) = maybe_credential_schema
                            && credential_schema.deleted_at.is_none() {
                            credential_schema
                        } else {
                            self.credential_schema_url_importer
                                .import_credential_schema_from_url(
                                    &request_input_schema.credential_schema.imported_source_url,
                                    organisation.to_owned(),
                                )
                                .await
                                .error_while("importing referenced credential schema")?
                        };

                    proof_input_from_import_request(request_input_schema, credential_schema).await
                }
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
