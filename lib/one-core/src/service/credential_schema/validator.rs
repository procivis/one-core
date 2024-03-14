use shared_types::OrganisationId;

use crate::config::core_config::CoreConfig;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::service::credential_schema::mapper::create_unique_name_check_request;
use crate::service::error::{BusinessLogicError, ValidationError};
use crate::{
    config::validator::{
        datatype::validate_datatypes, format::validate_format, revocation::validate_revocation,
    },
    service::{credential_schema::dto::CreateCredentialSchemaRequestDTO, error::ServiceError},
};
use std::sync::Arc;

pub(crate) async fn credential_schema_already_exists(
    repository: &Arc<dyn CredentialSchemaRepository>,
    name: &str,
    organisation_id: OrganisationId,
) -> Result<(), ServiceError> {
    let credential_schemas = repository
        .get_credential_schema_list(create_unique_name_check_request(name, organisation_id)?)
        .await?;
    if credential_schemas.total_items > 0 {
        return Err(BusinessLogicError::CredentialSchemaAlreadyExists.into());
    }
    Ok(())
}

pub(crate) fn validate_create_request(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    // at least one claim must be declared
    if request.claims.is_empty() {
        return Err(ValidationError::CredentialSchemaMissingClaims.into());
    }

    validate_format(&request.format, &config.format)?;
    validate_revocation(&request.revocation_method, &config.revocation)?;
    validate_datatypes(
        &request
            .claims
            .iter()
            .map(|f| &f.datatype)
            .collect::<Vec<&String>>(),
        &config.datatype,
    )?;

    Ok(())
}
