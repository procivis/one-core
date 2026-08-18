use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::ContextWithErrorCode;
use crate::mapper::openid4vp::format_type_to_dcql_format;
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier_trust_information::SchemaFormat;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::Features;
use crate::provider::ecosystem::error::EcosystemError;

pub(super) async fn credential_schema_to_schema_format(
    schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<(SchemaFormat, FormatType), EcosystemError> {
    let format_type = credential_schema_to_format_type(schema, config).await?;
    let schema_id = schema.schema_id().await?;
    Ok((
        SchemaFormat {
            format: format_type_to_dcql_format(&format_type),
            schema_id,
        },
        format_type,
    ))
}

pub(super) async fn credential_schema_to_format_type(
    schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<FormatType, EcosystemError> {
    let schema_format = schema.format().await?;
    let format_type = config
        .format
        .get_type(&schema_format)
        .error_while("retrieving credential schema format")?;
    Ok(format_type)
}

pub(super) fn formatter_requires_namespaces(formatter: &dyn CredentialFormatter) -> bool {
    formatter
        .get_capabilities()
        .features
        .contains(&Features::RequiresNamespaces)
}
