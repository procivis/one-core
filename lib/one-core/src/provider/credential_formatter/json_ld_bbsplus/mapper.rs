use std::collections::HashMap;

use shared_types::DidValue;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialSubject, DetailCredential, IdentifierDetails,
};
use crate::provider::credential_formatter::vcdm::VcdmCredential;

pub(super) fn convert_to_detail_credential(
    mut vcdm: VcdmCredential,
    mandatory_pointers: Option<Vec<String>>,
    metadata_claim_keys: &[String],
) -> Result<DetailCredential, FormatterError> {
    let Some(credential_subject) = vcdm.credential_subject.pop() else {
        return Err(FormatterError::Failed(
            "Missing credential subject".to_string(),
        ));
    };

    if !vcdm.credential_subject.is_empty() {
        return Err(FormatterError::Failed(
            "We currently don't support multiple credential subjects".to_string(),
        ));
    }

    let metadata_claims =
        metadata_claims_with_sd_flags(&vcdm, &mandatory_pointers, metadata_claim_keys)?;

    let credential_schema = vcdm
        .credential_schema
        .map(|mut schemas| {
            let Some(credential_schema) = schemas.pop() else {
                return Err(FormatterError::Failed(
                    "Missing credential schema".to_string(),
                ));
            };

            if !schemas.is_empty() {
                return Err(FormatterError::Failed(
                    "We currently don't support multiple credential schemas".to_string(),
                ));
            }

            Ok(credential_schema)
        })
        .transpose()?;

    let mut claims = HashMap::from_iter(credential_subject.claims);

    if let Some(mandatory_pointers) = mandatory_pointers {
        let mandatory_claim_paths: Vec<_> = mandatory_pointers
            .iter()
            .filter_map(|pointer| pointer.strip_prefix("/credentialSubject"))
            .collect();
        mark_object_claims_selectively_disclosable(&mut claims, &mandatory_claim_paths);
    }
    claims.extend(metadata_claims);

    let claims = CredentialSubject {
        id: credential_subject.id.clone(),
        claims,
    };

    // this is not always DID, for example LVVC credentials use URN schema as and id
    let subject = credential_subject
        .id
        .and_then(|id| DidValue::from_did_url(id).ok())
        .map(IdentifierDetails::Did);

    Ok(DetailCredential {
        id: vcdm.id.map(|url| url.to_string()),
        issuance_date: vcdm.proof.and_then(|proof| proof.created),
        valid_from: vcdm.valid_from.or(vcdm.issuance_date),
        valid_until: vcdm.valid_until.or(vcdm.expiration_date),
        update_at: None,
        invalid_before: None,
        issuer: IdentifierDetails::Did(vcdm.issuer.to_did_value()?),
        subject,
        claims,
        status: vcdm.credential_status,
        credential_schema,
    })
}

fn metadata_claims_with_sd_flags(
    vcdm: &VcdmCredential,
    mandatory_pointers: &Option<Vec<String>>,
    metadata_claim_keys: &[String],
) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
    let (plain_metadata, sd_metadata): (Vec<_>, Vec<_>) =
        if let Some(mandatory_pointers) = &mandatory_pointers {
            metadata_claim_keys
                .iter()
                .cloned()
                .partition(|key| mandatory_pointers.contains(key))
        } else {
            (metadata_claim_keys.to_vec(), vec![])
        };
    let metadata_claims = vcdm.get_metadata_claims(&plain_metadata, &sd_metadata)?;
    Ok(metadata_claims)
}

fn mark_object_claims_selectively_disclosable(
    obj: &mut HashMap<String, CredentialClaim>,
    mandatory_claim_paths: &[&str],
) {
    if mandatory_claim_paths.contains(&"") {
        // If the whole object is marked as mandatory pointer, it means all underlying claims must be disclosed.
        // That is the default state after automatic conversion.
        return;
    }

    for (key, claim) in obj.iter_mut() {
        let mandatory_paths: Vec<_> = mandatory_claim_paths
            .iter()
            .filter_map(|path| path.strip_prefix(&format!("/{key}")))
            .collect();

        mark_subclaim_selectively_disclosable(claim, &mandatory_paths)
    }
}

fn mark_array_claims_selectively_disclosable(
    claims: &mut [CredentialClaim],
    mandatory_claim_paths: &[&str],
) {
    if mandatory_claim_paths.contains(&"") {
        // If the whole array is marked as mandatory pointer, it means all underlying claims must be disclosed.
        // That is the default state after automatic conversion.
        return;
    }

    for (index, claim) in claims.iter_mut().enumerate() {
        let mandatory_paths: Vec<_> = mandatory_claim_paths
            .iter()
            .filter_map(|path| path.strip_prefix(&format!("/{index}")))
            .collect();

        mark_subclaim_selectively_disclosable(claim, &mandatory_paths)
    }
}

fn mark_subclaim_selectively_disclosable(claim: &mut CredentialClaim, mandatory_paths: &[&str]) {
    claim.selectively_disclosable = mandatory_paths.is_empty();

    match &mut claim.value {
        CredentialClaimValue::Object(obj) => {
            mark_object_claims_selectively_disclosable(obj, mandatory_paths)
        }
        CredentialClaimValue::Array(claims) => {
            mark_array_claims_selectively_disclosable(claims, mandatory_paths)
        }
        CredentialClaimValue::Bool(_)
        | CredentialClaimValue::Number(_)
        | CredentialClaimValue::String(_) => {
            // nothing else needed for simple types
        }
    }
}
