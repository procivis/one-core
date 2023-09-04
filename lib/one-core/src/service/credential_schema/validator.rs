use crate::{
    config::{
        data_structure::CoreConfig,
        validator::{
            datatype::validate_datatypes, format::validate_format, revocation::validate_revocation,
        },
    },
    service::{credential_schema::dto::CreateCredentialSchemaRequestWithIds, error::ServiceError},
};

pub(crate) fn validate_create_request(
    request: &CreateCredentialSchemaRequestWithIds,
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

    Ok(())
}
