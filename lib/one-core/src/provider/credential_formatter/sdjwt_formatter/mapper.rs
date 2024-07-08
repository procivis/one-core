use crate::provider::credential_formatter::{
    Context, CredentialData, FormatterError, PublishedClaim,
};

use super::model::{SDCredentialSubject, Sdvc, VCContent};

pub(super) fn vc_from_credential(
    credential: CredentialData,
    sd_section: &[String],
    additional_context: Vec<String>,
    additional_types: Vec<String>,
    algorithm: &str,
) -> Sdvc {
    let mut hashed_claims: Vec<String> = sd_section.to_vec();
    hashed_claims.sort_unstable();

    let context = vec![Context::CredentialsV1.to_string()]
        .into_iter()
        .chain(additional_context)
        .collect();

    let types = vec!["VerifiableCredential".to_owned()]
        .into_iter()
        .chain(additional_types)
        .collect();

    Sdvc {
        vc: VCContent {
            context,
            r#type: types,
            id: Some(credential.id),
            credential_subject: SDCredentialSubject {
                claims: hashed_claims,
            },
            credential_status: credential.status,
            credential_schema: credential.schema.into(),
        },
        hash_alg: Some(algorithm.to_owned()),
    }
}

pub(super) fn tokenize_claims(disclosures: Vec<String>) -> Result<String, FormatterError> {
    let mut token = String::new();

    for disclosure in disclosures {
        token.push('~');
        token.push_str(&disclosure);
    }

    Ok(token)
}

pub(super) fn nest_claims_to_json(
    claims: &[PublishedClaim],
) -> Result<serde_json::Value, FormatterError> {
    let mut data = serde_json::Value::Object(Default::default());

    for claim in claims {
        let pointer = jsonptr::Pointer::try_from(format!("/{}", claim.key))?;
        pointer.assign(&mut data, claim.value.to_owned())?;
    }

    Ok(data)
}

pub(super) fn unpack_arrays(
    value: &serde_json::Value,
) -> Result<serde_json::Value, FormatterError> {
    let mut result = serde_json::Value::Object(Default::default());

    let result_obj = result.as_object_mut().ok_or(FormatterError::JsonMapping(
        "freshly created object is not an Object".to_string(),
    ))?;

    value
        .as_object()
        .ok_or(FormatterError::JsonMapping(
            "value is not an Object".to_string(),
        ))?
        .into_iter()
        .try_for_each(|(k, v)| {
            match v.as_str() {
                None => {
                    result_obj.insert(k.to_owned(), unpack_arrays(v)?);
                }
                Some(v_str) => {
                    match serde_json::from_str::<serde_json::Value>(v_str) {
                        Ok(parsed) => match parsed.as_array() {
                            None => {
                                if parsed.is_object() {
                                    result_obj.insert(k.to_owned(), unpack_arrays(&parsed)?);
                                } else {
                                    result_obj.insert(k.to_owned(), v.to_owned());
                                }
                            }
                            Some(array) => {
                                let mut inner = serde_json::Value::Array(vec![]);
                                let inner_array =
                                    inner.as_array_mut().ok_or(FormatterError::JsonMapping(
                                        "freshly created array is not an Array".to_string(),
                                    ))?;

                                array.iter().for_each(|element| {
                                    inner_array.push(element.to_owned());
                                });
                                result_obj.insert(k.to_owned(), inner);
                            }
                        },
                        Err(_) => {
                            result_obj.insert(k.to_owned(), v.to_owned());
                        }
                    };
                }
            }

            Ok::<(), FormatterError>(())
        })?;

    Ok(result)
}
