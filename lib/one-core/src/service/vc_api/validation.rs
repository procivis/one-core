use std::cell::LazyCell;

use one_providers::credential_formatter::{
    imp::json_ld::model::{ContextType, LdCredential, LdPresentation},
    model::Context,
};
use url::Url;

use crate::service::error::ServiceError;

const V1: LazyCell<ContextType> =
    LazyCell::new(|| ContextType::Url(Context::CredentialsV1.to_string().parse().unwrap()));
const V2: LazyCell<ContextType> =
    LazyCell::new(|| ContextType::Url(Context::CredentialsV2.to_string().parse().unwrap()));

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

    let credential_subject = &credential.credential_subject;
    if credential_subject.id.is_none() && credential_subject.subject.is_empty() {
        return Err(VcValidationError::EmptyCredentialSubject);
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
        .is_some_and(|cs| !cs.id.parse::<Url>().is_ok())
    {
        return Err(VcValidationError::InvalidCredentialSchemaId);
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

    if !["VerifiablePresentation", "EnvelopedVerifiablePresentation"]
        .iter()
        .any(|t| presentation.r#type.contains(t))
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
