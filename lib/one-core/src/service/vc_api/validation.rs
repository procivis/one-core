use std::sync::LazyLock;

use url::Url;

use crate::provider::credential_formatter::json_ld::model::{
    ContextType, LdCredential, LdPresentation,
};
use crate::provider::credential_formatter::model::Context;
use crate::service::error::ServiceError;

static V1: LazyLock<ContextType> =
    LazyLock::new(|| ContextType::Url(Context::CredentialsV1.to_url()));
static V2: LazyLock<ContextType> =
    LazyLock::new(|| ContextType::Url(Context::CredentialsV2.to_url()));

#[derive(Debug, thiserror::Error)]
pub enum VcValidationError {
    #[error("Provided credential is missing the credential context")]
    MissingContext,

    #[error("Provided credential doesn't contain context as first element in the `@context` set")]
    ContextNotInFirstPosition,

    #[error("Provided credential is missing the specified `type` property")]
    MissingVerifiableCredentialType,

    #[error("Provided credential contains an empty `credentialSubject`")]
    EmptyCredentialSubject,

    #[error("Invalid validity period, `validUntil` before its `validFrom`")]
    ValidUntilBeforeValidFrom,

    #[error("VC contains invalid credentialSchema id. Must be a URL")]
    InvalidCredentialSchemaId,

    #[error("Related resource MUST contain digestSRI or digestMultibase")]
    InvalidRelatedResource,
}

#[derive(Debug, thiserror::Error)]
pub enum VpValidationError {
    #[error("Provided presentation is missing the context")]
    MissingContext,

    #[error("Provided presentation doesn't contain any VCs")]
    MissingVerifiableCredential,

    #[error(
        "Provided presentation doesn't contain context as first element in the `@context` set"
    )]
    ContextNotInFirstPosition,

    #[error("Provided presentation is missing the specified `type` property")]
    MissingVerifiablePresentationType,

    #[error("Failed parsing VC")]
    InvalidVc,

    #[error(transparent)]
    Vc(#[from] VcValidationError),
}

pub(super) fn validate_verifiable_credential(
    credential: &LdCredential,
) -> Result<(), VcValidationError> {
    match credential
        .context
        .iter()
        .position(|ctx| ctx == &*V1 || ctx == &*V2)
    {
        None => return Err(VcValidationError::MissingContext),
        Some(ix) if ix != 0 => return Err(VcValidationError::ContextNotInFirstPosition),
        _ => {}
    };

    if !credential
        .r#type
        .iter()
        .any(|c| c == "VerifiableCredential" || c == "EnvelopedVerifiableCredential")
    {
        return Err(VcValidationError::MissingVerifiableCredentialType);
    }

    if credential.credential_subject.is_empty() {
        return Err(VcValidationError::EmptyCredentialSubject);
    }

    for credential_subject in &credential.credential_subject {
        if credential_subject.id.is_none() && credential_subject.subject.is_empty() {
            return Err(VcValidationError::EmptyCredentialSubject);
        }
    }

    match (credential.valid_from, credential.valid_until) {
        (Some(valid_from), Some(valid_until)) if valid_until < valid_from => {
            return Err(VcValidationError::ValidUntilBeforeValidFrom);
        }
        _ => {}
    }

    if credential
        .credential_schema
        .as_ref()
        .is_some_and(|schemas| {
            schemas
                .iter()
                .any(|schema| schema.id.parse::<Url>().is_err())
        })
    {
        return Err(VcValidationError::InvalidCredentialSchemaId);
    }

    match &credential.related_resource {
        None => {}
        Some(resource) => {
            if resource
                .iter()
                .any(|r| r.digest_sri.is_none() && r.digest_multibase.is_none())
            {
                return Err(VcValidationError::InvalidRelatedResource);
            }
        }
    }

    Ok(())
}

pub(super) fn validate_verifiable_presentation(
    presentation: &LdPresentation,
) -> Result<(), VpValidationError> {
    if presentation.verifiable_credential.is_empty() {
        return Err(VpValidationError::MissingVerifiableCredential);
    }

    for vc in &presentation.verifiable_credential {
        let vc =
            serde_json::from_value(vc.clone().into()).map_err(|_| VpValidationError::InvalidVc)?;
        validate_verifiable_credential(&vc)?;
    }

    match presentation
        .context
        .iter()
        .position(|ctx| ctx == &*V1 || ctx == &*V2)
    {
        None => return Err(VpValidationError::MissingContext),
        Some(ix) if ix != 0 => return Err(VpValidationError::ContextNotInFirstPosition),
        _ => {}
    };

    if !presentation
        .r#type
        .iter()
        .any(|t| t == "VerifiablePresentation" || t == "EnvelopedVerifiablePresentation")
    {
        return Err(VpValidationError::MissingVerifiablePresentationType);
    }

    Ok(())
}

impl From<VcValidationError> for ServiceError {
    fn from(value: VcValidationError) -> Self {
        ServiceError::ValidationError(value.to_string())
    }
}

impl From<VpValidationError> for ServiceError {
    fn from(value: VpValidationError) -> Self {
        ServiceError::ValidationError(value.to_string())
    }
}
