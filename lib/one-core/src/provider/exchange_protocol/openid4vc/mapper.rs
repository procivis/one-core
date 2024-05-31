use std::collections::HashMap;
use std::sync::Arc;

use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm,
};
use crate::common_mapper::{
    get_encryption_key_jwk_from_proof, remove_first_nesting_layer, PublicKeyWithJwk,
    NESTED_CLAIM_MARKER,
};
use crate::config::core_config::{CoreConfig, DatatypeType, FormatType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::interaction::InteractionId;
use crate::model::proof::{Proof, ProofId};
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, PresentedCredential,
};
use crate::provider::exchange_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::provider::exchange_protocol::openid4vc::dto::{
    OpenID4VCICredentialDefinition, OpenID4VCICredentialOfferClaim,
    OpenID4VCICredentialOfferClaimValue, OpenID4VCICredentialOfferCredentialDTO,
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialSubject, OpenID4VCICredentialValueDetails,
    OpenID4VCIGrant, OpenID4VCIGrants, OpenID4VPClientMetadata, OpenID4VPClientMetadataJwkDTO,
    OpenID4VPFormat, OpenID4VPInteractionData, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionInputDescriptorFormat,
};
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
};
use crate::service::oidc::dto::{
    NestedPresentationSubmissionDescriptorDTO, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO,
    PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO,
};
use crate::util::oidc::map_core_to_oidc_format;

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_open_id_for_vp_sharing_url_encoded(
    base_url: Option<String>,
    interaction_id: InteractionId,
    nonce: String,
    proof: Proof,
    client_metadata_by_value: bool,
    presentation_definition_by_value: bool,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    config: &CoreConfig,
) -> Result<String, ExchangeProtocolError> {
    let encryption_key_jwk = get_encryption_key_jwk_from_proof(&proof, key_algorithm_provider)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    let client_metadata =
        serde_json::to_string(&create_open_id_for_vp_client_metadata(encryption_key_jwk))
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    let presentation_definition = serde_json::to_string(
        &create_open_id_for_vp_presentation_definition(interaction_id, &proof, config)?,
    )
    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    let base_url = get_url(base_url)?;
    let callback_url = format!("{}/ssi/oidc-verifier/v1/response", base_url);

    let mut params: Vec<(&str, String)> = vec![
        ("response_type", "vp_token".to_string()),
        ("state", interaction_id.to_string()),
        ("nonce", nonce),
        ("client_id_scheme", "redirect_uri".to_string()),
        ("client_id", callback_url.to_owned()),
        ("response_mode", "direct_post".to_string()),
        ("response_uri", callback_url),
    ];

    match client_metadata_by_value {
        true => params.push(("client_metadata", client_metadata)),
        false => params.push((
            "client_metadata_uri",
            format!(
                "{}/ssi/oidc-verifier/v1/{}/client-metadata",
                base_url, proof.id
            ),
        )),
    }

    match presentation_definition_by_value {
        true => params.push(("presentation_definition", presentation_definition)),
        false => params.push((
            "presentation_definition_uri",
            format!(
                "{}/ssi/oidc-verifier/v1/{}/presentation-definition",
                base_url, proof.id
            ),
        )),
    }

    let encoded_params = serde_urlencoded::to_string(params)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    Ok(encoded_params)
}

pub(super) fn presentation_definition_from_interaction_data(
    proof_id: ProofId,
    credentials: Vec<Credential>,
    credential_groups: Vec<CredentialGroup>,
) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
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
                        validity_credential_nbf: group.validity_credential_nbf,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        }],
        credentials: credential_model_to_credential_dto(credentials)?,
    })
}

pub(crate) fn get_claim_name_by_json_path(
    path: &[String],
) -> Result<String, ExchangeProtocolError> {
    const VC_CREDENTIAL_PREFIX: &str = "$.vc.credentialSubject.";

    match path.first() {
        Some(vc) if vc.starts_with(VC_CREDENTIAL_PREFIX) => {
            Ok(vc[VC_CREDENTIAL_PREFIX.len()..].to_owned())
        }

        Some(subscript_path) if subscript_path.starts_with("$['") => {
            let path: Vec<&str> = subscript_path
                .split(['$', '[', ']', '\''])
                .filter(|s| !s.is_empty())
                .collect();

            let json_pointer_path = path.join("/");

            if json_pointer_path.is_empty() {
                return Err(ExchangeProtocolError::Failed(format!(
                    "Invalid json path: {subscript_path}"
                )));
            }

            Ok(json_pointer_path)
        }
        Some(other) => Err(ExchangeProtocolError::Failed(format!(
            "Invalid json path: {other}"
        ))),

        None => Err(ExchangeProtocolError::Failed("No path".to_string())),
    }
}

pub(crate) fn create_open_id_for_vp_presentation_definition(
    interaction_id: InteractionId,
    proof: &Proof,
    config: &CoreConfig,
) -> Result<OpenID4VPPresentationDefinition, ExchangeProtocolError> {
    let proof_schema = proof.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
        "Proof schema not found".to_string(),
    ))?;
    // using vec to keep the original order of claims/credentials in the proof request
    let requested_credentials: Vec<(CredentialSchema, Option<Vec<ProofInputClaimSchema>>)> =
        match proof_schema.input_schemas.as_ref() {
            Some(proof_input) if !proof_input.is_empty() => proof_input
                .iter()
                .filter_map(|input| {
                    let credential_schema = input.credential_schema.as_ref()?;

                    let claims = input.claim_schemas.as_ref().map(|schemas| {
                        schemas
                            .iter()
                            .map(|claim_schema| ProofInputClaimSchema {
                                order: claim_schema.order,
                                required: claim_schema.required,
                                schema: claim_schema.schema.to_owned(),
                            })
                            .collect()
                    });

                    Some((credential_schema.to_owned(), claims))
                })
                .collect(),

            _ => {
                return Err(ExchangeProtocolError::Failed(
                    "Missing proof input schemas".to_owned(),
                ))
            }
        };

    Ok(OpenID4VPPresentationDefinition {
        id: interaction_id,
        input_descriptors: requested_credentials
            .into_iter()
            .enumerate()
            .map(|(index, (credential_schema, claim_schemas))| {
                create_open_id_for_vp_presentation_definition_input_descriptor(
                    index,
                    credential_schema,
                    claim_schemas.unwrap_or_default(),
                    config,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn is_min_level_two(claim_schema_key: &str) -> bool {
    claim_schema_key.matches(NESTED_CLAIM_MARKER).count() >= 1
}

pub(crate) fn create_open_id_for_vp_presentation_definition_input_descriptor(
    index: usize,
    credential_schema: CredentialSchema,
    claim_schemas: Vec<ProofInputClaimSchema>,
    config: &CoreConfig,
) -> Result<OpenID4VPPresentationDefinitionInputDescriptor, ExchangeProtocolError> {
    let schema_id_field = OpenID4VPPresentationDefinitionConstraintField {
        id: None,
        path: vec!["$.credentialSchema.id".to_string()],
        optional: None,
        filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
            r#type: "string".to_string(),
            r#const: credential_schema.schema_id,
        }),
        intent_to_retain: None,
    };

    let format_type = config
        .format
        .get_fields(&credential_schema.format)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
        .r#type;

    let intent_to_retain = match format_type {
        FormatType::Mdoc => Some(true),
        _ => None,
    };

    let constraint_fields = claim_schemas
        .iter()
        .filter(|claim| format_type != FormatType::Mdoc || is_min_level_two(&claim.schema.key))
        .map(|claim| {
            Ok(OpenID4VPPresentationDefinitionConstraintField {
                id: Some(claim.schema.id),
                path: vec![format_path(&claim.schema.key, format_type)?],
                optional: Some(!claim.required),
                filter: None,
                intent_to_retain,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut fields = vec![schema_id_field];
    fields.extend(constraint_fields);

    Ok(OpenID4VPPresentationDefinitionInputDescriptor {
        format: create_format_map(format_type)?,
        id: format!("input_{index}"),
        constraints: OpenID4VPPresentationDefinitionConstraint {
            fields,
            validity_credential_nbf: None,
        },
    })
}

fn format_path(claim_key: &str, format_type: FormatType) -> Result<String, ExchangeProtocolError> {
    match format_type {
        FormatType::Mdoc => match claim_key.split_once(NESTED_CLAIM_MARKER) {
            None => Ok(format!("$['{claim_key}']")),
            Some((namespace, key)) => Ok(format!("$['{namespace}']['{key}']")),
        },
        _ => Ok(format!("$.vc.credentialSubject.{}", claim_key)),
    }
}

fn create_format_map(
    format_type: FormatType,
) -> Result<
    HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
    ExchangeProtocolError,
> {
    match format_type {
        FormatType::Jwt | FormatType::Sdjwt | FormatType::Mdoc => {
            let key = map_core_to_oidc_format(&format_type.to_string())
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
            Ok(HashMap::from([(
                key,
                OpenID4VPPresentationDefinitionInputDescriptorFormat {
                    alg: vec!["EdDSA".to_string(), "ES256".to_string()],
                    proof_type: vec![],
                },
            )]))
        }
        FormatType::JsonLdClassic | FormatType::JsonLdBbsplus => Ok(HashMap::from([(
            "ldp_vc".to_string(),
            OpenID4VPPresentationDefinitionInputDescriptorFormat {
                alg: vec![],
                proof_type: vec!["DataIntegrityProof".to_string()],
            },
        )])),
    }
}

pub fn create_open_id_for_vp_client_metadata(key: PublicKeyWithJwk) -> OpenID4VPClientMetadata {
    OpenID4VPClientMetadata {
        jwks: vec![OpenID4VPClientMetadataJwkDTO {
            key_id: key.key_id,
            jwk: key.jwk,
        }],
        vp_formats: create_open_id_for_vp_formats(),
        client_id_scheme: "redirect_uri".to_string(),
        authorization_encrypted_response_alg: Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs),
        authorization_encrypted_response_enc: Some(
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM,
        ),
    }
}
// TODO: This method needs to be refactored as soon as we have a new config value access and remove the static values from this method
pub(crate) fn create_open_id_for_vp_formats() -> HashMap<String, OpenID4VPFormat> {
    let mut formats = HashMap::new();
    let algorithms = OpenID4VPFormat {
        alg: vec!["EdDSA".to_owned(), "ES256".to_owned()],
    };
    formats.insert("jwt_vp_json".to_owned(), algorithms.clone());
    formats.insert("jwt_vc_json".to_owned(), algorithms.clone());
    formats.insert("ldp_vp".to_owned(), algorithms.clone());
    formats.insert(
        "ldp_vc".to_owned(),
        OpenID4VPFormat {
            alg: vec![
                "EdDSA".to_owned(),
                "ES256".to_owned(),
                "BLS12-381G1-SHA256".to_owned(),
            ],
        },
    );
    formats.insert("vc+sd-jwt".to_owned(), algorithms.clone());
    formats.insert("mso_mdoc".to_owned(), algorithms);
    formats
}

fn get_url(base_url: Option<String>) -> Result<String, ExchangeProtocolError> {
    base_url.ok_or(ExchangeProtocolError::Failed("Missing base_url".to_owned()))
}

pub(crate) fn create_credential_offer(
    base_url: Option<String>,
    interaction_id: &InteractionId,
    credential: &Credential,
    config: &CoreConfig,
) -> Result<OpenID4VCICredentialOfferDTO, ExchangeProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;

    let claims = credential
        .claims
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed("Missing claims".to_owned()))?;

    let url = get_url(base_url)?;

    let format_type = config
        .format
        .get_fields(&credential_schema.format)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
        .r#type;

    let credentials = match format_type {
        FormatType::Mdoc => credentials_format_mdoc(credential_schema, claims, config),
        _ => credentials_format_others(credential_schema, claims),
    }?;

    Ok(OpenID4VCICredentialOfferDTO {
        credential_issuer: format!("{}/ssi/oidc-issuer/v1/{}", url, credential_schema.id),
        credentials,
        grants: OpenID4VCIGrants {
            code: OpenID4VCIGrant {
                pre_authorized_code: interaction_id.to_string(),
            },
        },
    })
}

fn credentials_format_mdoc(
    credential_schema: &CredentialSchema,
    claims: &[Claim],
    config: &CoreConfig,
) -> Result<Vec<OpenID4VCICredentialOfferCredentialDTO>, ExchangeProtocolError> {
    let claims = prepare_claims(credential_schema, claims, config)?;

    Ok(vec![OpenID4VCICredentialOfferCredentialDTO {
        wallet_storage_type: credential_schema.wallet_storage_type.clone(),
        format: map_core_to_oidc_format(&credential_schema.format)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
        credential_definition: None,
        doctype: Some(credential_schema.schema_id.to_owned()),
        claims: Some(claims),
    }])
}

pub(super) fn prepare_claims(
    credential_schema: &CredentialSchema,
    claims: &[Claim],
    config: &CoreConfig,
) -> Result<HashMap<String, OpenID4VCICredentialOfferClaim>, ExchangeProtocolError> {
    let object_types = config
        .datatype
        .iter()
        .filter_map(|(name, fields)| {
            if fields.r#type == DatatypeType::Object {
                Some(name)
            } else {
                None
            }
        })
        .collect::<Vec<&str>>();

    // Copy value claims to result
    let mut result = claims
        .iter()
        .map(|claim| {
            let schema = claim.schema.as_ref().ok_or(ExchangeProtocolError::Failed(
                "claim_schema is None".to_string(),
            ))?;
            Ok((
                schema.key.to_owned(),
                OpenID4VCICredentialOfferClaim {
                    value: OpenID4VCICredentialOfferClaimValue::String(claim.value.to_owned()),
                    value_type: schema.data_type.to_owned(),
                },
            ))
        })
        .collect::<Result<HashMap<String, OpenID4VCICredentialOfferClaim>, ExchangeProtocolError>>(
        )?;

    // Copy object claims from credential schema
    let object_claims = credential_schema
        .claim_schemas
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "claim_schemas is None".to_string(),
        ))?
        .iter()
        .filter_map(|schema| {
            let is_object = object_types.contains(&schema.schema.data_type.as_str());
            if is_object {
                Some(Ok((
                    schema.schema.key.to_owned(),
                    OpenID4VCICredentialOfferClaim {
                        value: OpenID4VCICredentialOfferClaimValue::Nested(Default::default()),
                        value_type: schema.schema.data_type.to_owned(),
                    },
                )))
            } else {
                None
            }
        })
        .collect::<Result<HashMap<String, OpenID4VCICredentialOfferClaim>, ExchangeProtocolError>>(
        )?;
    result.extend(object_claims);

    nest_claims(result)
}

fn nest_claims(
    claims: HashMap<String, OpenID4VCICredentialOfferClaim>,
) -> Result<HashMap<String, OpenID4VCICredentialOfferClaim>, ExchangeProtocolError> {
    // Copy unnested claims
    let mut result = claims
        .iter()
        .filter_map(|(key, value)| {
            if key.find(NESTED_CLAIM_MARKER).is_none() {
                Some((key.to_owned(), value.to_owned()))
            } else {
                None
            }
        })
        .collect::<HashMap<String, OpenID4VCICredentialOfferClaim>>();

    // Copy nested claims into parent claims
    claims.into_iter().try_for_each(|(key, value)| {
        if let Some(index) = key.find(NESTED_CLAIM_MARKER) {
            let prefix = &key[0..index];
            let entry = result.get_mut(prefix).ok_or(ExchangeProtocolError::Failed(
                "failed to find parent claim".to_string(),
            ))?;
            match &mut entry.value {
                OpenID4VCICredentialOfferClaimValue::Nested(map) => {
                    map.insert(remove_first_nesting_layer(&key), value);
                }
                OpenID4VCICredentialOfferClaimValue::String(_) => {
                    return Err(ExchangeProtocolError::Failed(
                        "found parent OBJECT claim of String value type".to_string(),
                    ));
                }
            }
        }

        Ok::<(), ExchangeProtocolError>(())
    })?;

    // Repeat for each nested claim
    result
        .into_iter()
        .map(|(key, value)| match value.value {
            OpenID4VCICredentialOfferClaimValue::Nested(map) => Ok((
                key,
                OpenID4VCICredentialOfferClaim {
                    value: OpenID4VCICredentialOfferClaimValue::Nested(nest_claims(map)?),
                    value_type: value.value_type,
                },
            )),
            OpenID4VCICredentialOfferClaimValue::String(_) => Ok((key, value)),
        })
        .collect::<Result<HashMap<_, _>, _>>()
}

fn credentials_format_others(
    credential_schema: &CredentialSchema,
    claims: &[Claim],
) -> Result<Vec<OpenID4VCICredentialOfferCredentialDTO>, ExchangeProtocolError> {
    Ok(vec![OpenID4VCICredentialOfferCredentialDTO {
        wallet_storage_type: credential_schema.wallet_storage_type.clone(),
        format: map_core_to_oidc_format(&credential_schema.format)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
        credential_definition: Some(OpenID4VCICredentialDefinition {
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
        }),
        doctype: None,
        claims: Default::default(),
    }])
}

pub(super) fn get_credential_offer_url(
    base_url: Option<String>,
    credential: &Credential,
) -> Result<String, ExchangeProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
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
    claim_keys: &HashMap<String, OpenID4VCICredentialValueDetails>,
) -> Result<(Vec<CredentialSchemaClaim>, Vec<Claim>), ExchangeProtocolError> {
    let now = OffsetDateTime::now_utc();
    let mut claim_schemas: Vec<CredentialSchemaClaim> = vec![];
    let mut claims: Vec<Claim> = vec![];
    let mut object_claim_schemas: Vec<&str> = vec![];

    for (key, value_details) in claim_keys {
        let new_schema_claim = CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
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

        claim_schemas.push(new_schema_claim);
        claims.push(claim);

        if key.contains(NESTED_CLAIM_MARKER) {
            for parent_claim in get_parent_claim_paths(key) {
                if !object_claim_schemas.contains(&parent_claim) {
                    object_claim_schemas.push(parent_claim);
                }
            }
        }
    }

    for object_claim in object_claim_schemas {
        claim_schemas.push(CredentialSchemaClaim {
            schema: ClaimSchema {
                id: Uuid::new_v4().into(),
                key: object_claim.into(),
                data_type: DatatypeType::Object.to_string(),
                created_date: now,
                last_modified: now,
            },
            required: false,
        })
    }

    Ok((claim_schemas, claims))
}

pub(super) fn create_presentation_submission(
    interaction_data: &OpenID4VPInteractionData,
    credential_presentations: Vec<PresentedCredential>,
    format: &str,
) -> Result<PresentationSubmissionMappingDTO, ExchangeProtocolError> {
    let presentation_definition_id = &interaction_data
        .presentation_definition
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "presentation_definition is None".to_string(),
        ))?
        .id;

    Ok(PresentationSubmissionMappingDTO {
        id: Uuid::new_v4().to_string(),
        definition_id: presentation_definition_id.to_string(),
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
                        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
                        path: format!("$.vp.verifiableCredential[{index}]"),
                    }),
                })
            })
            .collect::<Result<_, _>>()?,
    })
}

pub(super) fn get_parent_claim_paths(path: &str) -> Vec<&str> {
    path.char_indices()
        .filter_map(|(index, value)| {
            if value == NESTED_CLAIM_MARKER {
                Some(index)
            } else {
                None
            }
        })
        .map(|index| &path[0..index])
        .collect::<Vec<&str>>()
}

pub(super) fn parse_procivis_schema_claim(
    claim: CredentialClaimSchemaDTO,
) -> CredentialClaimSchemaRequestDTO {
    CredentialClaimSchemaRequestDTO {
        key: claim.key,
        datatype: claim.datatype,
        required: claim.required,
        claims: claim
            .claims
            .into_iter()
            .map(parse_procivis_schema_claim)
            .collect(),
    }
}

pub(super) fn parse_mdoc_schema_claims(
    values: HashMap<String, HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>>,
    element_order: Option<Vec<String>>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut claims_by_namespace: Vec<_> = values
        .into_iter()
        .map(|(namespace, elements)| CredentialClaimSchemaRequestDTO {
            key: namespace,
            datatype: DatatypeType::Object.to_string(),
            required: true,
            claims: parse_mdoc_schema_elements(elements),
        })
        .collect();

    if let Some(order) = element_order {
        claims_by_namespace.iter_mut().for_each(|namespace| {
            namespace.claims.sort_by_key(|claim| {
                order
                    .iter()
                    .position(|element| element == &format!("{}~{}", namespace.key, claim.key))
                    .unwrap_or_default()
            })
        });

        claims_by_namespace.sort_by_key(|claim| {
            order
                .iter()
                .position(|element| element.starts_with(&format!("{}~", claim.key)))
                .unwrap_or_default()
        });
    }

    claims_by_namespace
}

fn parse_mdoc_schema_elements(
    values: HashMap<String, OpenID4VCIIssuerMetadataMdocClaimsValuesDTO>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    values
        .into_iter()
        .map(|(key, claim)| {
            let mut claims = parse_mdoc_schema_elements(claim.value);

            if let Some(order) = claim.order {
                claims.sort_by_key(|claim| {
                    order
                        .iter()
                        .position(|item| item == &claim.key)
                        .unwrap_or_default()
                });
            }

            CredentialClaimSchemaRequestDTO {
                key,
                datatype: claim.value_type,
                required: claim.mandatory.unwrap_or(false),
                claims,
            }
        })
        .collect()
}

pub(super) fn map_offered_claims_to_credential_schema(
    credential_schema: &CredentialSchema,
    credential_id: CredentialId,
    claim_keys: &HashMap<String, OpenID4VCICredentialValueDetails>,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Missing claim schemas for existing credential schema".to_string(),
            ))?;

    let now = OffsetDateTime::now_utc();
    let mut claims = vec![];
    for claim_schema in claim_schemas
        .iter()
        .filter(|claim| claim.schema.data_type != DatatypeType::Object.to_string())
    {
        let credential_value_details = &claim_keys.get(&claim_schema.schema.key);
        match credential_value_details {
            Some(value_details) => {
                let claim = Claim {
                    id: Uuid::new_v4(),
                    credential_id,
                    created_date: now,
                    last_modified: now,
                    value: value_details.value.to_owned(),
                    schema: Some(claim_schema.schema.to_owned()),
                };

                claims.push(claim);
            }
            None if claim_schema.required => {
                return Err(ExchangeProtocolError::Failed(format!(
                    "Validation Error. Claim key {} missing",
                    &claim_schema.schema.key
                )))
            }
            _ => {
                // skip non-required claims that aren't matching
            }
        }
    }

    Ok(claims)
}
