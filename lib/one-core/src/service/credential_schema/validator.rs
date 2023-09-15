use crate::{
    config::{
        data_structure::CoreConfig,
        validator::{
            datatype::validate_datatypes, format::validate_format, revocation::validate_revocation,
        },
    },
    service::{credential_schema::dto::CreateCredentialSchemaRequestDTO, error::ServiceError},
};

pub(crate) fn validate_create_request(
    request: &CreateCredentialSchemaRequestDTO,
    config: &CoreConfig,
) -> Result<(), ServiceError> {
    validate_format(&request.format, &config.format)?;
    validate_revocation(&request.revocation_method, &config.revocation)?;
    validate_datatypes(
        &request
            .claims
            .iter()
            .map(|f| &f.datatype)
            .collect::<Vec<&String>>(),
        &config.datatype,
    )
    .map_err(ServiceError::ConfigValidationError)?;

    // at least one claim must be declared
    if request.claims.is_empty() {
        return Err(ServiceError::IncorrectParameters);
    }

    Ok(())
}
