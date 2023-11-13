use serde::{Deserialize, Deserializer};
use std::collections::{HashMap, HashSet};

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::Credential,
        credential_schema::{CredentialSchema, CredentialSchemaClaim, CredentialSchemaId},
        interaction::InteractionId,
        proof::Proof,
    },
    provider::transport_protocol::{
        openid4vc::dto::{
            OpenID4VCICredentialDefinition, OpenID4VCICredentialSubject, OpenID4VCIGrant,
            OpenID4VCIGrants, OpenID4VPClientMetadata, OpenID4VPFormat,
            OpenID4VPPresentationDefinition, OpenID4VPPresentationDefinitionConstraint,
            OpenID4VPPresentationDefinitionConstraintField,
            OpenID4VPPresentationDefinitionInputDescriptors,
        },
        TransportProtocolError,
    },
    util::oidc::map_core_to_oidc_format,
};

use super::dto::{
    OpenID4VCICredentialOffer, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialValueDetails,
};

pub(crate) fn create_open_id_for_vp_sharing_url_encoded(
    base_url: Option<String>,
    interaction_id: InteractionId,
    nonce: String,
    proof: Proof,
) -> Result<String, TransportProtocolError> {
    let client_metadata = serde_json::to_string(&create_open_id_for_vp_client_metadata()?)
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
    let presentation_definition = serde_json::to_string(
        &create_open_id_for_vp_presentation_definition(interaction_id, proof)?,
    )
    .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;
    let callback_url = format!("{}/ssi/oidc-verifier/v1/response", get_url(base_url)?);
    let encoded_params = serde_urlencoded::to_string([
        ("response_type", "vp_token"),
        ("state", &interaction_id.to_string()),
        ("nonce", &nonce),
        ("client_id_scheme", "redirect_uri"),
        ("client_id", &callback_url),
        ("client_metadata", &client_metadata),
        ("response_mode", "direct_post"),
        ("response_uri", &callback_url),
        ("presentation_definition", &presentation_definition),
    ])
    .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    Ok(encoded_params)
}

pub(crate) fn create_open_id_for_vp_presentation_definition(
    interaction_id: InteractionId,
    proof: Proof,
) -> Result<OpenID4VPPresentationDefinition, TransportProtocolError> {
    let mut requested_credentials = HashSet::new();
    let claim_schemas = proof
        .clone()
        .schema
        .ok_or(TransportProtocolError::Failed(
            "Proof schema not found".to_string(),
        ))?
        .claim_schemas
        .ok_or(TransportProtocolError::Failed(
            "Proof claim schemas not found".to_string(),
        ))?;
    for claim_schema in claim_schemas {
        let credential_schema =
            claim_schema
                .clone()
                .credential_schema
                .ok_or(TransportProtocolError::Failed(
                    "Credential schema not found".to_string(),
                ))?;
        requested_credentials.insert(credential_schema.id);
    }

    Ok(OpenID4VPPresentationDefinition {
        id: interaction_id,
        input_descriptors: requested_credentials
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                create_open_id_for_vp_presentation_definition_input_descriptor(i, &v, proof.clone())
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) fn create_open_id_for_vp_presentation_definition_input_descriptor(
    index: usize,
    credential_schema_id: &CredentialSchemaId,
    proof: Proof,
) -> Result<OpenID4VPPresentationDefinitionInputDescriptors, TransportProtocolError> {
    let proof_claims = proof
        .schema
        .ok_or(TransportProtocolError::Failed(
            "Schema not found".to_string(),
        ))?
        .claim_schemas
        .ok_or(TransportProtocolError::Failed(
            "Claim schemas not found".to_string(),
        ))?;
    let claims_for_credential: Vec<_> = proof_claims
        .iter()
        .filter(|claim| {
            if let Some(schema) = claim.credential_schema.as_ref() {
                credential_schema_id == &schema.id
            } else {
                false
            }
        })
        .collect();

    Ok(OpenID4VPPresentationDefinitionInputDescriptors {
        id: format!("input_{}", index),
        constraints: OpenID4VPPresentationDefinitionConstraint {
            fields: claims_for_credential
                .iter()
                .map(|claim| OpenID4VPPresentationDefinitionConstraintField {
                    id: claim.schema.id,
                    path: vec![format!("$.vc.credentialSubject.{}", claim.schema.key)],
                    optional: !claim.required,
                })
                .collect(),
        },
    })
}

pub(crate) fn create_open_id_for_vp_client_metadata(
) -> Result<OpenID4VPClientMetadata, TransportProtocolError> {
    Ok(OpenID4VPClientMetadata {
        vp_formats: create_open_id_for_vp_formats()?,
        client_id_scheme: "redirect_uri".to_string(),
    })
}
// TODO: This method needs to be refactored as soon as we have a new config value access and remove the static values from this method
pub(crate) fn create_open_id_for_vp_formats(
) -> Result<HashMap<String, OpenID4VPFormat>, TransportProtocolError> {
    let mut formats = HashMap::new();
    let algorithms = OpenID4VPFormat {
        alg: vec!["EdDSA".to_owned()],
    };
    formats.insert("jwt_vp_json".to_owned(), algorithms.clone());
    formats.insert("jwt_vc_json".to_owned(), algorithms.clone());
    formats.insert("vc+sd-jwt".to_owned(), algorithms);
    Ok(formats)
}

fn get_url(base_url: Option<String>) -> Result<String, TransportProtocolError> {
    base_url.ok_or(TransportProtocolError::Failed(
        "Missing base_url".to_owned(),
    ))
}

pub(super) fn create_credential_offer_encoded(
    base_url: Option<String>,
    interaction_id: &InteractionId,
    credential: &Credential,
) -> Result<String, TransportProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;

    let claims = credential
        .claims
        .as_ref()
        .ok_or(TransportProtocolError::Failed("Missing claims".to_owned()))?;

    let url = get_url(base_url)?;

    let offer = OpenID4VCICredentialOffer {
        credential_issuer: format!("{}/ssi/oidc-issuer/v1/{}", url, credential_schema.id),
        credentials: vec![OpenID4VCICredentialOfferCredentialDTO {
            format: map_core_to_oidc_format(&credential_schema.format)
                .map_err(|e| TransportProtocolError::Failed(e.to_string()))?,
            credential_definition: OpenID4VCICredentialDefinition {
                r#type: vec!["VerifiableCredential".to_string()],
                credential_subject: Some(OpenID4VCICredentialSubject {
                    keys: HashMap::from_iter(claims.iter().filter_map(|claim| {
                        claim.schema.as_ref().map(|schema| {
                            (
                                schema.key.clone(),
                                OpenID4VCICredentialValueDetails {
                                    value: claim.value.clone(),
                                    value_type: schema.data_type.clone(),
                                },
                            )
                        })
                    })),
                }),
            },
        }],
        grants: OpenID4VCIGrants {
            code: OpenID4VCIGrant {
                pre_authorized_code: interaction_id.to_string(),
            },
        },
    };

    let offer_string =
        serde_json::to_string(&offer).map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    let offer_encoded = serde_urlencoded::to_string([("credential_offer", offer_string)])
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    Ok(offer_encoded)
}

pub(super) fn create_claims_from_credential_definition(
    credential_definition: &OpenID4VCICredentialDefinition,
    credential_schema: &Option<CredentialSchema>,
) -> Result<Vec<(CredentialSchemaClaim, Claim)>, TransportProtocolError> {
    let credential_subject =
        credential_definition
            .credential_subject
            .as_ref()
            .ok_or(TransportProtocolError::Failed(
                "Missing credential_subject".to_string(),
            ))?;

    let schema_claims = credential_schema
        .as_ref()
        .and_then(|schema| schema.claim_schemas.to_owned());

    let now = OffsetDateTime::now_utc();
    let mut result: Vec<(CredentialSchemaClaim, Claim)> = vec![];
    for (key, value_details) in credential_subject.keys.iter() {
        let schema_claim = if let Some(current_claims) = &schema_claims {
            current_claims
                .iter()
                .find(|claim| &claim.schema.key == key)
                .ok_or(TransportProtocolError::Failed(format!(
                    "Missing key `{key}` in current credential schema"
                )))?
                .to_owned()
        } else {
            CredentialSchemaClaim {
                schema: ClaimSchema {
                    id: Uuid::new_v4(),
                    key: key.to_string(),
                    data_type: value_details.value_type.to_string(),
                    created_date: now,
                    last_modified: now,
                },
                required: false,
            }
        };

        let claim = Claim {
            id: Uuid::new_v4(),
            created_date: now,
            last_modified: now,
            value: value_details.value.to_string(),
            schema: Some(schema_claim.schema.to_owned()),
        };

        result.push((schema_claim, claim));
    }

    Ok(result)
}

pub(super) fn deserialize_with_serde_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Deserialize<'a>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value.as_str() {
        None => serde_json::from_value(value).map_err(serde::de::Error::custom),
        Some(buffer) => serde_json::from_str(buffer).map_err(serde::de::Error::custom),
    }
}
