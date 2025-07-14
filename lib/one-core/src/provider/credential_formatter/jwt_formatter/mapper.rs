use std::collections::HashMap;

use shared_types::DidValue;

use super::model::VcClaim;
use crate::provider::credential_formatter::model::{
    CredentialSchema, CredentialSchemaData, CredentialSubject, DetailCredential, IdentifierDetails,
};
use crate::util::jwt::Jwt;

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

        // credential subject id should be present in "sub" claim or "credentialSubject.id"
        let subject = jwt
            .payload
            .subject
            .as_deref()
            .or(credential_subject.id.as_ref().map(|url| url.as_str()))
            .and_then(|did| DidValue::from_did_url(did).ok())
            .map(IdentifierDetails::Did);

        let did = jwt
            .payload
            .issuer
            .ok_or(anyhow::anyhow!("JWT missing credential issuer"))?
            .parse()?;

        Ok(Self {
            id: jwt.payload.jwt_id,
            valid_from: jwt.payload.issued_at,
            valid_until: jwt.payload.expires_at,
            update_at: None,
            invalid_before: jwt.payload.invalid_before,
            issuer: IdentifierDetails::Did(did),
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
