use time::OffsetDateTime;
use time::format_description::well_known::Iso8601;
use time::format_description::well_known::iso8601::{
    Config, EncodedConfig, FormattedComponents, TimePrecision,
};
use uuid::Uuid;

use super::dto::ImportCredentialSchemaRequestSchemaDTO;
use super::mapper::{claim_schema_from_metadata_claim_schema, from_create_request_with_id};
use crate::config::core_config::CoreConfig;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::credential_schema::validator::UniquenessCheckResult;
use crate::service::error::{BusinessLogicError, MissingProviderError, ServiceError};

const DATE_TIME_NO_MILLIS: EncodedConfig = Config::DEFAULT
    .set_formatted_components(FormattedComponents::DateTime)
    .set_time_precision(TimePrecision::Second {
        decimal_digits: None,
    })
    .encode();

pub(crate) async fn import_credential_schema(
    request: ImportCredentialSchemaRequestSchemaDTO,
    organisation: Organisation,
    config: &CoreConfig,
    repository: &dyn CredentialSchemaRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
    revocation_method_provider: &dyn RevocationMethodProvider,
) -> Result<CredentialSchema, ServiceError> {
    let credential_schema_id = request.id.into();
    let mut create_request = request.to_owned().into();

    let formatter = formatter_provider
        .get_credential_formatter(&request.format)
        .ok_or(MissingProviderError::Formatter(request.format.to_owned()))?;
    super::validator::validate_create_request(
        &create_request,
        config,
        &*formatter,
        revocation_method_provider,
        true,
    )?;

    match super::validator::credential_schema_already_exists(
        repository,
        &create_request.name,
        create_request.schema_id.clone(),
        organisation.id,
    )
    .await?
    {
        UniquenessCheckResult::SchemaIdConflict => {
            return Err(BusinessLogicError::CredentialSchemaAlreadyExists.into());
        }
        UniquenessCheckResult::NameConflict => {
            create_request.name = format!(
                "{}_{}",
                create_request.name,
                OffsetDateTime::now_utc()
                    .format(&Iso8601::<DATE_TIME_NO_MILLIS>)
                    .map_err(|e| ServiceError::MappingError(format!(
                        "Failed to format date: {e}"
                    )))?
            );
        }
        UniquenessCheckResult::Ok => {}
    }

    super::validator::check_claims_presence_in_layout_properties(&create_request)?;
    super::validator::check_background_properties(&create_request)?;
    super::validator::check_logo_properties(&create_request)?;

    let format_type = &config.format.get_fields(&request.format)?.r#type;
    let mut credential_schema = from_create_request_with_id(
        credential_schema_id,
        create_request,
        organisation,
        format_type,
        Some(request.schema_type.to_owned().into()),
        request.schema_id,
        request.imported_source_url,
    )?;

    let metadata_claims = formatter
        .get_metadata_claims()
        .into_iter()
        .map(|metadata_claim| {
            claim_schema_from_metadata_claim_schema(metadata_claim, credential_schema.created_date)
        })
        .collect::<Vec<_>>();
    credential_schema
        .claim_schemas
        .as_mut()
        .ok_or(ServiceError::MappingError(
            "Missing claim schemas".to_string(),
        ))?
        .extend(metadata_claims);

    let credential_schema = regenerate_credential_schema_uuids(credential_schema);

    repository
        .create_credential_schema(credential_schema.to_owned())
        .await
        .map_err(ServiceError::from)?;

    Ok(credential_schema)
}

fn regenerate_credential_schema_uuids(mut credential_schema: CredentialSchema) -> CredentialSchema {
    credential_schema.id = Uuid::new_v4().into();
    if let Some(claim_schemas) = credential_schema.claim_schemas.as_mut() {
        claim_schemas.iter_mut().for_each(|schema| {
            schema.schema.id = Uuid::new_v4().into();
        })
    }

    credential_schema
}
