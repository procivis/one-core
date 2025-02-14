use std::collections::HashMap;

use anyhow::Context;
use shared_types::DidValue;

use super::model::{VcClaim, VerifiableCredential, VP};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    CredentialSchema, CredentialSchemaData, CredentialSubject, DetailCredential, Presentation,
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

impl TryFrom<Jwt<VcClaim>> for DetailCredential {
    type Error = anyhow::Error;

    fn try_from(jwt: Jwt<VcClaim>) -> Result<Self, Self::Error> {
        let credential_subject = jwt
            .payload
            .custom
            .vc
            .credential_subject
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("JWT missing credential subject"))?;

        // credential subject id should be present in the payload or the vcdm
        let subject = jwt
            .payload
            .subject
            .as_deref()
            .or(credential_subject.id.as_ref().map(|url| url.as_str()))
            .and_then(|did| DidValue::from_did_url(did).ok());

        Ok(Self {
            id: jwt.payload.jwt_id,
            valid_from: jwt.payload.issued_at,
            valid_until: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: jwt.payload.issuer.map(|did| did.parse()).transpose()?,
            subject,
            claims: CredentialSubject {
                id: credential_subject.id,
                claims: HashMap::from_iter(credential_subject.claims),
            },
            status: jwt.payload.custom.vc.credential_status,
            credential_schema: jwt
                .payload
                .custom
                .vc
                .credential_schema
                .and_then(|s| s.into_iter().next()),
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
