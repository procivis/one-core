use std::collections::HashMap;

use anyhow::Context;
use rand::seq::SliceRandom;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::json_ld::model::ContextType;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialSchema, Presentation, PublishedClaim,
};
use crate::provider::credential_formatter::sdjwt::model::{
    SDCredentialSubject, Sdvc, Sdvp, VCContent,
};

pub(crate) fn vc_from_credential(
    credential: CredentialData,
    digests: Vec<String>,
    additional_context: Vec<ContextType>,
    additional_types: Vec<String>,
    algorithm: &str,
    embed_layout_properties: bool,
) -> Result<Sdvc, FormatterError> {
    let digests: Vec<String> = {
        let mut digests = digests;
        let mut rng = rand::thread_rng();
        digests.shuffle(&mut rng);
        digests
    };

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

    Ok(Sdvc {
        digests: vec![],
        vc: VCContent {
            context: additional_context,
            r#type: types,
            id: credential.id,
            credential_subject: SDCredentialSubject {
                digests,
                public_claims: HashMap::new(),
            },
            credential_status: credential.status,
            credential_schema,
            issuer: Some(credential.issuer_did),
            valid_from: None,
            valid_until: None,
        },
        hash_alg: Some(algorithm.to_owned()),
    })
}

// Build JSON object from claim paths which are similar to JSON pointers without the "/" prefix
// ex. claim with key=a/b/c, value=10 => { "a": {"b": {"c": 10}}}
//     claim with key=a/0/c, value=10 => { "a": [{"c": 10}]}
pub(crate) fn claims_to_json_object(
    claims: &[PublishedClaim],
) -> Result<serde_json::Value, FormatterError> {
    let mut data = serde_json::Value::Object(Default::default());

    for claim in claims {
        let path = format!("/{}", claim.key);
        let pointer = jsonptr::Pointer::parse(&path)?;
        let value: serde_json::Value = claim.value.to_owned().try_into()?;
        pointer.assign(&mut data, value)?;
    }

    Ok(data)
}

impl TryFrom<Jwt<Sdvp>> for Presentation {
    type Error = anyhow::Error;

    fn try_from(jwt: Jwt<Sdvp>) -> Result<Self, Self::Error> {
        Ok(Presentation {
            id: jwt.payload.jwt_id,
            issued_at: jwt.payload.issued_at,
            expires_at: jwt.payload.expires_at,
            issuer_did: jwt
                .payload
                .issuer
                .map(|did| did.parse().context("did parsing error"))
                .transpose()
                .map_err(|e| FormatterError::Failed(e.to_string()))?,
            nonce: jwt.payload.custom.nonce,
            credentials: jwt.payload.custom.vp.verifiable_credential,
        })
    }
}
