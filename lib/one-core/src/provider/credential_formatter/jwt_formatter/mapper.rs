use anyhow::Context;
use shared_types::DidValue;

use super::model::{VCContent, VerifiableCredential, VC, VP};
use crate::provider::credential_formatter::common::nest_claims;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, CredentialSchemaData, CredentialSubject, DetailCredential,
    Issuer, Presentation,
};

impl From<CredentialSchemaData> for Option<CredentialSchema> {
    fn from(credential_schema: CredentialSchemaData) -> Self {
        match credential_schema {
            CredentialSchemaData {
                id: Some(id),
                r#type: Some(r#type),
                metadata,
                ..
            } => Some(CredentialSchema::new(id, r#type, metadata)),
            _ => None,
        }
    }
}

pub(super) fn format_vc(
    credential: CredentialData,
    issuer: Issuer,
    additional_context: Vec<ContextType>,
    additional_types: Vec<String>,
    embed_layout_properties: bool,
) -> Result<VC, FormatterError> {
    let types = vec!["VerifiableCredential".to_owned()]
        .into_iter()
        .chain(additional_types)
        .collect();

    // Strip layout (whole metadata as it only contains layout)
    let mut credential_schema: Option<CredentialSchema> = credential.schema.into();
    if let Some(schema) = &mut credential_schema {
        if !embed_layout_properties {
            schema.metadata = None;
        }
    }

    Ok(VC {
        vc: VCContent {
            context: additional_context,
            r#type: types,
            id: credential.id,
            issuer: Some(issuer),
            credential_subject: CredentialSubject {
                values: nest_claims(credential.claims)?.into_iter().collect(),
            },
            credential_status: credential.status,
            credential_schema,
            valid_from: None,
            valid_until: None,
        },
    })
}

impl TryFrom<Jwt<VC>> for DetailCredential {
    type Error = anyhow::Error;

    fn try_from(jwt: Jwt<VC>) -> Result<Self, Self::Error> {
        Ok(Self {
            id: jwt.payload.jwt_id,
            valid_from: jwt.payload.issued_at,
            valid_until: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: jwt.payload.issuer.map(|did| did.parse()).transpose()?,
            subject: jwt
                .payload
                .subject
                .and_then(|did| DidValue::from_did_url(did).ok()),
            claims: jwt.payload.custom.vc.credential_subject,
            status: jwt.payload.custom.vc.credential_status,
            credential_schema: jwt.payload.custom.vc.credential_schema,
        })
    }
}

impl TryFrom<Jwt<VP>> for Presentation {
    type Error = FormatterError;

    fn try_from(jwt: Jwt<VP>) -> Result<Self, Self::Error> {
        let credentials = jwt
            .payload
            .custom
            .vp
            .verifiable_credential
            .into_iter()
            .map(|vc| match vc {
                VerifiableCredential::Enveloped(enveloped) => {
                    let (_type, token) = enveloped.id.split_once(',').ok_or(
                        FormatterError::CouldNotExtractPresentation(
                            "Enveloped VP id missing delimiter".to_string(),
                        ),
                    )?;
                    Ok(token.to_string())
                }
                VerifiableCredential::Token(token) => Ok(token),
            })
            .collect::<Result<Vec<_>, FormatterError>>()?;

        Ok(Presentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt
                .payload
                .issuer
                .map(|did| did.parse().context("did parsing error"))
                .transpose()
                .map_err(|e| Self::Error::Failed(e.to_string()))?,
            nonce: jwt.payload.custom.nonce,
            credentials,
        })
    }
}
