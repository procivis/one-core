use std::sync::Arc;

use shared_types::OrganisationId;
use time::format_description::well_known::Iso8601;
use time::format_description::well_known::iso8601::{
    Config, EncodedConfig, FormattedComponents, TimePrecision,
};

use super::Error;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::credential_schema_claim::backfill_default_translations;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaListQuery};
use crate::model::list_filter::{ListFilterValue, StringMatch, StringMatchType};
use crate::model::list_query::ListPagination;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::CredentialSchemaFilterValue;

const DATE_TIME_NO_MILLIS: EncodedConfig = Config::DEFAULT
    .set_formatted_components(FormattedComponents::DateTime)
    .set_time_precision(TimePrecision::Second {
        decimal_digits: None,
    })
    .encode();

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait CredentialSchemaImporter: Send + Sync {
    async fn import_credential_schema(
        &self,
        credential_schema: CredentialSchema,
    ) -> Result<CredentialSchema, Error>;
}

pub struct CredentialSchemaImporterProto {
    repository: Arc<dyn CredentialSchemaRepository>,
    default_language: String,
}

impl CredentialSchemaImporterProto {
    pub(crate) fn new(
        repository: Arc<dyn CredentialSchemaRepository>,
        default_language: String,
    ) -> Self {
        Self {
            repository,
            default_language,
        }
    }
}

#[async_trait::async_trait]
impl CredentialSchemaImporter for CredentialSchemaImporterProto {
    // Errors are logged at `debug`, not `warn`: an already-imported schema is expected when
    // a provider re-advertises its schemas on every sync, and the API callers surface their
    // failures to the client, which the server logs on its own.
    #[tracing::instrument(level = "debug", skip_all, err(level = "debug"))]
    async fn import_credential_schema(
        &self,
        mut credential_schema: CredentialSchema,
    ) -> Result<CredentialSchema, Error> {
        let schema_ids: Vec<String> = {
            let formats = credential_schema.formats.as_ref().await?;
            formats
                .iter()
                .map(|f| f.ecosystem_schema_id.clone())
                .collect()
        };

        let conflicting_credential_schemas = self
            .get_credential_schemas_with_same_name_or_schema_ids(
                credential_schema.organisation.id(),
                credential_schema.name.clone(),
                schema_ids.clone(),
            )
            .await?;

        if credential_schema_with_any_schema_id_exists(&conflicting_credential_schemas, &schema_ids)
            .await?
        {
            return Err(Error::AlreadyExists);
        }

        if credential_schema_with_same_name_exists(
            &credential_schema,
            conflicting_credential_schemas,
        ) {
            credential_schema.name =
                self.generate_unique_credential_schema_name(&credential_schema)?;
        }

        let credential_schema =
            backfill_default_translations(credential_schema, &self.default_language)
                .await
                .error_while("backfilling default translations")?;

        self.repository
            .create_credential_schema(credential_schema.clone())
            .await
            .map_err(|e| {
                if matches!(e, DataLayerError::AlreadyExists) {
                    Error::AlreadyExists
                } else {
                    e.error_while("creating credential schema").into()
                }
            })?;

        Ok(credential_schema)
    }
}

impl CredentialSchemaImporterProto {
    async fn get_credential_schemas_with_same_name_or_schema_ids(
        &self,
        organisation_id: OrganisationId,
        name: String,
        schema_ids: Vec<String>,
    ) -> Result<Vec<CredentialSchema>, Error> {
        let query = CredentialSchemaListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                    & (CredentialSchemaFilterValue::Name(StringMatch {
                        r#match: StringMatchType::Equals,
                        value: name,
                    })
                    .condition()
                        | CredentialSchemaFilterValue::EcosystemSchemaIds(schema_ids)),
            ),
            ..Default::default()
        };
        Ok(self
            .repository
            .get_credential_schema_list(query)
            .await
            .error_while("getting credential schema list")?
            .values)
    }

    fn generate_unique_credential_schema_name(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<String, Error> {
        let formated_now = crate::clock::now_utc()
            .format(&Iso8601::<DATE_TIME_NO_MILLIS>)
            .map_err(|e| Error::MappingError(format!("Failed to format date: {e}")))?;
        Ok(format!("{}_{}", credential_schema.name, formated_now))
    }
}

fn credential_schema_with_same_name_exists(
    credential_schema: &CredentialSchema,
    conflicting_credential_schemas: Vec<CredentialSchema>,
) -> bool {
    conflicting_credential_schemas
        .iter()
        .any(|existing_cs| existing_cs.name == credential_schema.name)
}

async fn credential_schema_with_any_schema_id_exists(
    conflicting_credential_schemas: &[CredentialSchema],
    schema_ids: &[String],
) -> Result<bool, Error> {
    for existing_cs in conflicting_credential_schemas {
        if existing_cs.matches_schema_id(schema_ids).await? {
            return Ok(true);
        }
    }
    Ok(false)
}
