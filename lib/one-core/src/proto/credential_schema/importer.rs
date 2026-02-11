use std::sync::Arc;

use shared_types::OrganisationId;
use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;
use time::format_description::well_known::iso8601::{
    Config, EncodedConfig, FormattedComponents, TimePrecision,
};

use super::Error;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::credential_schema_claim::claim_schema_from_metadata_claim_schema;
use crate::model::credential_schema::CredentialSchema;
use crate::model::list_filter::{ListFilterValue, StringMatch, StringMatchType};
use crate::model::list_query::ListPagination;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, GetCredentialSchemaQueryDTO,
};
use crate::service::error::{BusinessLogicError, MissingProviderError};

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
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    repository: Arc<dyn CredentialSchemaRepository>,
}

impl CredentialSchemaImporterProto {
    pub(crate) fn new(
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        repository: Arc<dyn CredentialSchemaRepository>,
    ) -> Self {
        Self {
            formatter_provider,
            repository,
        }
    }
}

#[async_trait::async_trait]
impl CredentialSchemaImporter for CredentialSchemaImporterProto {
    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn import_credential_schema(
        &self,
        mut credential_schema: CredentialSchema,
    ) -> Result<CredentialSchema, Error> {
        let organisation = credential_schema
            .organisation
            .as_ref()
            .ok_or(Error::MappingError("Missing organisation".to_string()))?;

        let conflicting_credential_schemas = self
            .get_credential_schemas_with_same_name_and_id(
                organisation.id,
                credential_schema.name.clone(),
                credential_schema.schema_id.clone(),
            )
            .await?;

        if credential_schema_with_same_schema_id_exists(
            &credential_schema,
            &conflicting_credential_schemas,
        ) {
            return Err(BusinessLogicError::CredentialSchemaAlreadyExists
                .error_while("checking name conflict")
                .into());
        }

        if credential_schema_with_same_name_exists(
            &credential_schema,
            conflicting_credential_schemas,
        ) {
            credential_schema.name =
                self.generate_unique_credential_schema_name(&credential_schema)?;
        }

        let credential_schema = self.append_metadata_claims(credential_schema)?;

        self.repository
            .create_credential_schema(credential_schema.clone())
            .await
            .map_err(|e| {
                if matches!(e, DataLayerError::AlreadyExists) {
                    BusinessLogicError::CredentialSchemaAlreadyExists
                        .error_while("creating credential schema")
                } else {
                    e.error_while("creating credential schema")
                }
            })?;

        Ok(credential_schema)
    }
}

impl CredentialSchemaImporterProto {
    async fn get_credential_schemas_with_same_name_and_id(
        &self,
        organisation_id: OrganisationId,
        name: String,
        schema_id: String,
    ) -> Result<Vec<CredentialSchema>, Error> {
        let query = GetCredentialSchemaQueryDTO {
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
                        | CredentialSchemaFilterValue::SchemaId(StringMatch {
                            r#match: StringMatchType::Equals,
                            value: schema_id,
                        })),
            ),
            ..Default::default()
        };
        Ok(self
            .repository
            .get_credential_schema_list(query, &Default::default())
            .await
            .error_while("getting credential schema list")?
            .values)
    }

    fn generate_unique_credential_schema_name(
        &self,
        credential_schema: &CredentialSchema,
    ) -> Result<String, Error> {
        let formated_now = OffsetDateTime::now_utc()
            .format(&Iso8601::<DATE_TIME_NO_MILLIS>)
            .map_err(|e| Error::MappingError(format!("Failed to format date: {e}")))?;
        Ok(format!("{}_{}", credential_schema.name, formated_now))
    }

    fn append_metadata_claims(
        &self,
        mut credential_schema: CredentialSchema,
    ) -> Result<CredentialSchema, Error> {
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&credential_schema.format)
            .ok_or(MissingProviderError::Formatter(
                credential_schema.format.to_string(),
            ))
            .error_while("getting formatter")?;

        let claim_schemas = credential_schema
            .claim_schemas
            .as_mut()
            .ok_or(Error::MappingError("Missing claim schemas".to_string()))?;
        let metadata_claims = formatter
            .get_metadata_claims()
            .into_iter()
            .filter(|metadata_claim| {
                !claim_schemas
                    .iter()
                    .any(|cs| cs.schema.key == metadata_claim.key)
            })
            .map(|metadata_claim| {
                claim_schema_from_metadata_claim_schema(
                    metadata_claim,
                    credential_schema.created_date,
                )
            })
            .collect::<Vec<_>>();
        claim_schemas.extend(metadata_claims);
        Ok(credential_schema)
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

fn credential_schema_with_same_schema_id_exists(
    credential_schema: &CredentialSchema,
    conflicting_credential_schemas: &[CredentialSchema],
) -> bool {
    conflicting_credential_schemas
        .iter()
        .any(|existing_cs| existing_cs.schema_id == credential_schema.schema_id)
}
