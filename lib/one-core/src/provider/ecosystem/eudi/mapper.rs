use standardized_types::etsi_119_475::Credential;
use standardized_types::openid4vp::dcql;

use crate::model::identifier_trust_information::SchemaFormat;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::Features;
use crate::provider::ecosystem::error::EcosystemError;

pub(super) fn formatter_requires_namespaces(formatter: &dyn CredentialFormatter) -> bool {
    formatter
        .get_capabilities()
        .features
        .contains(&Features::RequiresNamespaces)
}

/// Maps the DCQL-shaped credential list carried by a registration certificate (or national
/// registry response) into the schema formats an identifier's trust information allows.
pub(super) fn map_dcql_credentials(
    credentials: Vec<Credential>,
) -> Result<Vec<SchemaFormat>, EcosystemError> {
    let schema_formats = credentials
        .into_iter()
        .map(credential_to_schema_formats)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(schema_formats.into_iter().flatten().collect())
}

fn credential_to_schema_formats(value: Credential) -> Result<Vec<SchemaFormat>, EcosystemError> {
    let dcql_format = value.format.dcql_format().to_owned();
    let schema_ids = match value.format {
        dcql::CredentialFormat::MsoMdoc(meta) => vec![meta.doctype_value],
        dcql::CredentialFormat::SdJwtVc(meta) => meta.vct_values,
        _ => {
            return Err(EcosystemError::InvalidTrustInformation(
                "W3C credentials are not supported in trust information".to_string(),
            ));
        }
    };
    Ok(schema_ids
        .into_iter()
        .map(|c| SchemaFormat {
            format: dcql_format.to_owned(),
            schema_id: c,
        })
        .collect())
}
