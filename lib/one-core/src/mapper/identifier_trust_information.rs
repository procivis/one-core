use crate::config::core_config::CoreConfig;
use crate::error::{ContextWithErrorCode, NestedError};
use crate::mapper::openid4vp::format_type_to_dcql_format;
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier_trust_information::SchemaFormat;
use crate::model::proof_schema::ProofSchema;

pub(crate) async fn credential_schema_to_schema_formats(
    schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<Vec<SchemaFormat>, NestedError> {
    let formats = schema.formats.as_ref().await?;
    formats
        .iter()
        .map(|format| {
            let format_type = config
                .format
                .get_type(&format.format)
                .error_while("retrieving credential schema format")?;
            Ok(SchemaFormat {
                format: format_type_to_dcql_format(&format_type),
                schema_id: format.ecosystem_schema_id.to_owned(),
            })
        })
        .collect()
}

pub(crate) async fn proof_schema_to_schema_formats(
    schema: &ProofSchema,
    config: &CoreConfig,
) -> Result<Vec<SchemaFormat>, NestedError> {
    let input_schemas = schema.input_schemas.as_ref().await?;
    let mut schema_formats = vec![];
    for input_schema in input_schemas.iter() {
        let credential_schema = input_schema.credential_schema.as_ref().await?;
        schema_formats
            .extend(credential_schema_to_schema_formats(&credential_schema, config).await?);
    }
    Ok(schema_formats)
}
