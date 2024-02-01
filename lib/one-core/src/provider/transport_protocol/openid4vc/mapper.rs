use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential::CredentialId;
use crate::model::proof::ProofId;
use crate::provider::transport_protocol::dto::{
    CredentialGroup, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, PresentedCredential,
};
use crate::provider::transport_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::service::oidc::dto::{
    NestedPresentationSubmissionDescriptorDTO, PresentationSubmissionDescriptorDTO,
    PresentationSubmissionMappingDTO,
};
use crate::{
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential::Credential,
        credential_schema::{CredentialSchemaClaim, CredentialSchemaId},
        interaction::InteractionId,
        proof::Proof,
    },
    provider::transport_protocol::{
        openid4vc::dto::{
            OpenID4VCICredentialDefinition, OpenID4VCICredentialOfferCredentialDTO,
            OpenID4VCICredentialOfferDTO, OpenID4VCICredentialSubject,
            OpenID4VCICredentialValueDetails, OpenID4VCIGrant, OpenID4VCIGrants,
            OpenID4VPClientMetadata, OpenID4VPFormat, OpenID4VPInteractionData,
            OpenID4VPPresentationDefinition, OpenID4VPPresentationDefinitionConstraint,
            OpenID4VPPresentationDefinitionConstraintField,
            OpenID4VPPresentationDefinitionInputDescriptor,
        },
        TransportProtocolError,
    },
    util::oidc::map_core_to_oidc_format,
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
        &create_open_id_for_vp_presentation_definition(interaction_id, &proof)?,
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

pub(super) fn presentation_definition_from_interaction_data(
    proof_id: ProofId,
    credentials: Vec<Credential>,
    credential_groups: Vec<CredentialGroup>,
) -> Result<PresentationDefinitionResponseDTO, TransportProtocolError> {
    Ok(PresentationDefinitionResponseDTO {
        request_groups: vec![PresentationDefinitionRequestGroupResponseDTO {
            id: proof_id.to_string(),
            name: None,
            purpose: None,
            rule: PresentationDefinitionRuleDTO {
                r#type: PresentationDefinitionRuleTypeEnum::All,
                min: None,
                max: None,
                count: None,
            },
            requested_credentials: credential_groups
                .into_iter()
                .map(|group| {
                    Ok(PresentationDefinitionRequestedCredentialResponseDTO {
                        id: group.id,
                        name: None,
                        purpose: None,
                        fields: group
                            .claims
                            .into_iter()
                            .map(|field| {
                                create_presentation_definition_field(
                                    field,
                                    &group.applicable_credentials,
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()?,
                        applicable_credentials: group
                            .applicable_credentials
                            .into_iter()
                            .map(|credential| credential.id.to_string())
                            .collect(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        }],
        credentials: credential_model_to_credential_dto(credentials)?,
    })
}

pub(crate) fn get_claim_name_by_json_path(
    path: &[String],
) -> Result<String, TransportProtocolError> {
    Ok(path
        .first()
        .ok_or(TransportProtocolError::Failed("No path".to_string()))?
        .split('.')
        .last()
        .ok_or(TransportProtocolError::Failed(
            "Invalid json path".to_string(),
        ))?
        .to_string())
}

pub(crate) fn create_open_id_for_vp_presentation_definition(
    interaction_id: InteractionId,
    proof: &Proof,
) -> Result<OpenID4VPPresentationDefinition, TransportProtocolError> {
    // using vec to keep the original order of claims/credentials in the proof request
    let mut requested_credentials: Vec<CredentialSchemaId> = vec![];
    let claim_schemas = proof
        .schema
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "Proof schema not found".to_string(),
        ))?
        .claim_schemas
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "Proof claim schemas not found".to_string(),
        ))?;
    for claim_schema in claim_schemas {
        let credential_schema_id = claim_schema
            .credential_schema
            .as_ref()
            .ok_or(TransportProtocolError::Failed(
                "Credential schema not found".to_string(),
            ))?
            .id;
        if !requested_credentials.contains(&credential_schema_id) {
            requested_credentials.push(credential_schema_id);
        }
    }

    Ok(OpenID4VPPresentationDefinition {
        id: interaction_id,
        input_descriptors: requested_credentials
            .into_iter()
            .enumerate()
            .map(|(index, credential_schema_id)| {
                create_open_id_for_vp_presentation_definition_input_descriptor(
                    index,
                    &credential_schema_id,
                    proof,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub(crate) fn create_open_id_for_vp_presentation_definition_input_descriptor(
    index: usize,
    credential_schema_id: &CredentialSchemaId,
    proof: &Proof,
) -> Result<OpenID4VPPresentationDefinitionInputDescriptor, TransportProtocolError> {
    let proof_claims = proof
        .schema
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "Schema not found".to_string(),
        ))?
        .claim_schemas
        .as_ref()
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

    Ok(OpenID4VPPresentationDefinitionInputDescriptor {
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
    formats.insert("ldp_vp".to_owned(), algorithms.clone());
    formats.insert("ldp_vc".to_owned(), algorithms.clone());
    formats.insert("vc+sd-jwt".to_owned(), algorithms);
    Ok(formats)
}

fn get_url(base_url: Option<String>) -> Result<String, TransportProtocolError> {
    base_url.ok_or(TransportProtocolError::Failed(
        "Missing base_url".to_owned(),
    ))
}

pub(crate) fn create_credential_offer(
    base_url: Option<String>,
    interaction_id: &InteractionId,
    credential: &Credential,
) -> Result<OpenID4VCICredentialOfferDTO, TransportProtocolError> {
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

    Ok(OpenID4VCICredentialOfferDTO {
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
    })
}

pub(super) fn get_credential_offer_url(
    base_url: Option<String>,
    credential: &Credential,
) -> Result<String, TransportProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;
    let base_url = get_url(base_url)?;
    Ok(format!(
        "{base_url}/ssi/oidc-issuer/v1/{}/offer/{}",
        credential_schema.id, credential.id
    ))
}

pub(super) fn create_claims_from_credential_definition(
    credential_id: CredentialId,
    credential_definition: &OpenID4VCICredentialDefinition,
) -> Result<Vec<(CredentialSchemaClaim, Claim)>, TransportProtocolError> {
    let credential_subject =
        credential_definition
            .credential_subject
            .as_ref()
            .ok_or(TransportProtocolError::Failed(
                "Missing credential_subject".to_string(),
            ))?;

    let now = OffsetDateTime::now_utc();
    let mut result: Vec<(CredentialSchemaClaim, Claim)> = vec![];
    for (key, value_details) in credential_subject.keys.iter() {
        let new_schema_claim = CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4(),
                key: key.to_string(),
                data_type: value_details.value_type.to_string(),
                created_date: now,
                last_modified: now,
            },
            required: false,
        };

        let claim = Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: value_details.value.to_string(),
            schema: Some(new_schema_claim.schema.to_owned()),
        };

        result.push((new_schema_claim, claim));
    }

    Ok(result)
}

pub(super) fn create_presentation_submission(
    interaction_data: &OpenID4VPInteractionData,
    credential_presentations: Vec<PresentedCredential>,
    format: &str,
) -> Result<PresentationSubmissionMappingDTO, TransportProtocolError> {
    Ok(PresentationSubmissionMappingDTO {
        id: Uuid::new_v4().to_string(),
        definition_id: interaction_data.presentation_definition.id.to_string(),
        descriptor_map: credential_presentations
            .into_iter()
            .enumerate()
            .map(|(index, presented_credential)| {
                Ok(PresentationSubmissionDescriptorDTO {
                    id: presented_credential.request.id,
                    format: format.to_owned(),
                    path: "$".to_string(),
                    path_nested: Some(NestedPresentationSubmissionDescriptorDTO {
                        format: map_core_to_oidc_format(
                            &presented_credential.credential_schema.format,
                        )
                        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?,
                        path: format!("$.vp.verifiableCredential[{index}]"),
                    }),
                })
            })
            .collect::<Result<_, _>>()?,
    })
}
