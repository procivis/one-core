use std::collections::HashMap;

use crate::{
    provider::credential_formatter::{
        jwt::Jwt,
        model::{CredentialStatus, CredentialSubject, DetailCredential},
    },
    service::credential::dto::CredentialDetailResponseDTO,
};

use super::model::{VCContent, VC};

pub(super) fn format_vc(
    credential: &CredentialDetailResponseDTO,
    credential_status: Option<CredentialStatus>,
    additional_context: Vec<String>,
    additional_types: Vec<String>,
) -> VC {
    let claims: HashMap<String, String> = credential
        .claims
        .iter()
        .map(|c| (c.schema.key.clone(), c.value.clone()))
        .collect();

    let context = vec!["https://www.w3.org/2018/credentials/v1".to_owned()]
        .into_iter()
        .chain(additional_context)
        .collect();

    let types = vec!["VerifiableCredential".to_owned()]
        .into_iter()
        .chain(additional_types)
        .collect();

    VC {
        vc: VCContent {
            context,
            r#type: types,
            credential_subject: CredentialSubject { values: claims },
            credential_status,
        },
    }
}

impl From<Jwt<VC>> for DetailCredential {
    fn from(jwt: Jwt<VC>) -> Self {
        DetailCredential {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            invalid_before: jwt.payload.invalid_before,
            issuer_did: jwt.payload.issuer,
            subject: jwt.payload.subject,
            claims: jwt.payload.custom.vc.credential_subject,
            status: jwt.payload.custom.vc.credential_status,
        }
    }
}
