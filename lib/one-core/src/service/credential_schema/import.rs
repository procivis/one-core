use super::dto::ImportCredentialSchemaRequestSchemaDTO;
use super::mapper::from_create_request_with_id;
use crate::config::core_config::CoreConfig;
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::common_mapper::regenerate_credential_schema_uuids;
use crate::service::error::{MissingProviderError, ServiceError};

pub(crate) async fn import_credential_schema(
    request: ImportCredentialSchemaRequestSchemaDTO,
    organisation: Organisation,
    config: &CoreConfig,
    repository: &dyn CredentialSchemaRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
    revocation_method_provider: &dyn RevocationMethodProvider,
) -> Result<CredentialSchema, ServiceError> {
    let credential_schema_id = request.id.into();
    let create_request = request.to_owned().into();

    let formatter = formatter_provider
        .get_formatter(&request.format)
        .ok_or(MissingProviderError::Formatter(request.format.to_owned()))?;
    super::validator::validate_create_request(
        &create_request,
        config,
        &*formatter,
        revocation_method_provider,
        true,
    )?;

    super::validator::credential_schema_already_exists(
        repository,
        &create_request.name,
        create_request.schema_id.clone(),
        organisation.id,
    )
    .await?;

    super::validator::check_claims_presence_in_layout_properties(&create_request)?;
    super::validator::check_background_properties(&create_request)?;
    super::validator::check_logo_properties(&create_request)?;

    let format_type = &config.format.get_fields(&request.format)?.r#type;
    let credential_schema = from_create_request_with_id(
        credential_schema_id,
        create_request,
        organisation,
        format_type,
        Some(request.schema_type.to_owned().into()),
        request.schema_id,
        request.imported_source_url,
    )?;

    let credential_schema = regenerate_credential_schema_uuids(credential_schema);

    repository
        .create_credential_schema(credential_schema.to_owned())
        .await
        .map_err(ServiceError::from)?;

    Ok(credential_schema)
}
