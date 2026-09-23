use std::collections::HashSet;

use shared_types::{CredentialFormat, CredentialSchemaId};

use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::proof_schema::ProofInputSchema;

/// Resolves the concrete formats selected by a proof input, in selection order.
pub(crate) async fn resolve_proof_input_schema_formats(
    input: &ProofInputSchema,
) -> Result<Vec<CredentialSchemaFormat>, ProofInputFormatsError> {
    let schema = input.credential_schema.as_ref().await?;
    let formats = schema.formats.as_ref().await?;
    input
        .formats
        .iter()
        .map(|selected| {
            formats
                .iter()
                .find(|format| &format.format == selected)
                .cloned()
                .ok_or_else(|| ProofInputFormatsError::FormatNotInSchema {
                    format: selected.clone(),
                    schema_id: schema.id,
                })
        })
        .collect()
}

#[derive(Debug, thiserror::Error)]
pub enum ProofInputFormatsError {
    #[error("Proof input schema must specify at least one format")]
    MissingFormats,
    #[error("Duplicate proof input format: `{0}`")]
    DuplicateFormat(CredentialFormat),
    #[error("Proof input format `{format}` is not part of credential schema `{schema_id}`")]
    FormatNotInSchema {
        format: CredentialFormat,
        schema_id: CredentialSchemaId,
    },
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for ProofInputFormatsError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingFormats => ErrorCode::BR_0508,
            Self::DuplicateFormat(_) => ErrorCode::BR_0509,
            Self::FormatNotInSchema { .. } => ErrorCode::BR_0510,
            Self::Nested(error) => error.error_code(),
        }
    }
}

/// Ensures that a selection is nonempty and contains no duplicate formats.
pub fn validate_proof_input_formats(
    formats: &[CredentialFormat],
) -> Result<(), ProofInputFormatsError> {
    if formats.is_empty() {
        return Err(ProofInputFormatsError::MissingFormats);
    }
    let mut unique = HashSet::with_capacity(formats.len());
    for format in formats {
        if !unique.insert(format) {
            return Err(ProofInputFormatsError::DuplicateFormat(format.clone()));
        }
    }
    Ok(())
}

pub(crate) async fn resolve_proof_input_formats(
    requested: Option<Vec<CredentialFormat>>,
    credential_schema: &CredentialSchema,
) -> Result<Vec<CredentialFormat>, ProofInputFormatsError> {
    let schema_formats = credential_schema.formats.as_ref().await?;
    let formats = match requested {
        None => {
            let mut formats: Vec<_> = schema_formats.iter().map(|f| f.format.clone()).collect();
            formats.sort();
            formats
        }
        Some(formats) => {
            validate_proof_input_formats(&formats)?;
            for format in &formats {
                if !schema_formats.iter().any(|f| &f.format == format) {
                    return Err(ProofInputFormatsError::FormatNotInSchema {
                        format: format.clone(),
                        schema_id: credential_schema.id,
                    });
                }
            }
            formats
        }
    };
    Ok(formats)
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;
    use crate::service::test_utilities::dummy_credential_schema_with_format;

    #[tokio::test]
    async fn resolves_all_formats_or_preserves_explicit_selection() {
        let mut schema = dummy_credential_schema_with_format("SD_JWT_VC");
        let mut formats = schema.formats.as_ref().await.unwrap().to_vec();
        let mut jwt = formats[0].clone();
        jwt.format = "JWT".into();
        formats.push(jwt);
        schema.formats = formats.into();

        assert_eq!(
            resolve_proof_input_formats(None, &schema).await.unwrap(),
            vec!["JWT".into(), "SD_JWT_VC".into()]
        );
        for requested in [
            vec!["SD_JWT_VC".into()],
            vec!["SD_JWT_VC".into(), "JWT".into()],
        ] {
            assert_eq!(
                resolve_proof_input_formats(Some(requested.clone()), &schema)
                    .await
                    .unwrap(),
                requested
            );
        }
    }

    #[tokio::test]
    async fn rejects_invalid_selections() {
        let schema = dummy_credential_schema_with_format("JWT");
        for (formats, code) in [
            (vec![], ErrorCode::BR_0508),
            (vec!["JWT", "JWT"], ErrorCode::BR_0509),
            (vec!["JWT", "SD_JWT_VC"], ErrorCode::BR_0510),
            (vec![" JWT"], ErrorCode::BR_0510),
            (vec!["jwt"], ErrorCode::BR_0510),
        ] {
            let error = resolve_proof_input_formats(
                Some(formats.into_iter().map(Into::into).collect()),
                &schema,
            )
            .await
            .unwrap_err();
            assert_eq!(error.error_code(), code);
        }
    }
}
