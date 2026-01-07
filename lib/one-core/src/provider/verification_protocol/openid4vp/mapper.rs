use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use one_dto_mapper::convert_inner;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use shared_types::ProofId;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::model::{
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, JwePayload, LdpVcAlgs,
    OpenID4VCVerifierAttestationPayload, OpenID4VPAlgs, OpenID4VPClientMetadataJwkDTO,
    OpenID4VPHolderInteractionData, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionLimitDisclosurePreference, OpenID4VPVcSdJwtAlgs,
    OpenID4VPVerifierInteractionContent, ProvedCredential, VpSubmissionData,
};
use super::{JWTSigner, get_jwt_signer, jwe_presentation};
use crate::config::core_config::{CoreConfig, FormatType, VerificationProtocolType};
use crate::mapper::oidc::map_to_openid4vp_format;
use crate::mapper::x509::pem_chain_into_x5c;
use crate::mapper::{
    NESTED_CLAIM_MARKER, get_encryption_key_jwk_from_proof, value_to_model_claims,
};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaClaim};
use crate::model::identifier::IdentifierType;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{JWTHeader, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey};
use crate::provider::credential_formatter::mdoc_formatter::util::MobileSecurityObject;
use crate::provider::credential_formatter::model::{CredentialClaim, IdentifierDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;
use crate::provider::verification_protocol::dto::{
    CredentialGroup, FormattedCredentialPresentation,
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::verification_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::final1_0::model::OpenID4VPFinal1_0ClientMetadata;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VPClientMetadata, OpenID4VPDraftClientMetadata, OpenID4VpPresentationFormat,
};
use crate::provider::verification_protocol::openid4vp::service::create_open_id_for_vp_client_metadata_draft;
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocolError,
};
use crate::service::error::{BusinessLogicError, ServiceError};

pub(super) fn presentation_definition_from_interaction_data(
    proof_id: ProofId,
    credentials: Vec<Credential>,
    credential_groups: Vec<CredentialGroup>,
    config: &CoreConfig,
) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
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
                        name: group.name,
                        multiple: None,
                        purpose: group.purpose,
                        fields: convert_inner(
                            group
                                .claims
                                .into_iter()
                                .map(|field| {
                                    create_presentation_definition_field(
                                        field,
                                        &convert_inner(
                                            group
                                                .applicable_credentials
                                                .iter()
                                                .chain(group.inapplicable_credentials.iter())
                                                .cloned()
                                                .collect::<Vec<_>>(),
                                        ),
                                    )
                                })
                                .collect::<Result<Vec<_>, _>>()?,
                        ),
                        applicable_credentials: group
                            .applicable_credentials
                            .into_iter()
                            .map(|credential| credential.id)
                            .collect(),
                        inapplicable_credentials: group
                            .inapplicable_credentials
                            .into_iter()
                            .map(|credential| credential.id)
                            .collect(),
                        validity_credential_nbf: group.validity_credential_nbf,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        }],
        credentials: credential_model_to_credential_dto(convert_inner(credentials), config)?,
    })
}

pub(crate) fn get_claim_name_by_json_path(
    path: &[String],
) -> Result<String, VerificationProtocolError> {
    const VC_CREDENTIAL_PREFIX: &str = "$.vc.credentialSubject.";
    const SD_JWT_VC_CREDENTIAL_PREFIX: &str = "$.";

    match path.first() {
        Some(vc) if vc.starts_with(VC_CREDENTIAL_PREFIX) => {
            Ok(vc[VC_CREDENTIAL_PREFIX.len()..].to_owned())
        }
        Some(vc) if vc.starts_with(SD_JWT_VC_CREDENTIAL_PREFIX) => {
            Ok(vc[SD_JWT_VC_CREDENTIAL_PREFIX.len()..].to_owned())
        }
        Some(subscript_path) if subscript_path.starts_with("$['") => {
            let path: Vec<&str> = subscript_path
                .split(['$', '[', ']', '\''])
                .filter(|s| !s.is_empty())
                .collect();

            let json_pointer_path = path.join("/");

            if json_pointer_path.is_empty() {
                return Err(VerificationProtocolError::Failed(format!(
                    "Invalid json path: {subscript_path}"
                )));
            }

            Ok(json_pointer_path)
        }
        Some(other) => Err(VerificationProtocolError::Failed(format!(
            "Invalid json path: {other}"
        ))),

        None => Err(VerificationProtocolError::Failed("No path".to_string())),
    }
}

// TODO: This method needs to be refactored as soon as we have a new config value access and remove the static values from this method
// only for use with Draft implementations
pub(crate) fn create_open_id_for_vp_formats() -> HashMap<String, OpenID4VpPresentationFormat> {
    let mut formats = HashMap::new();
    let algorithms = OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
        alg: vec!["EdDSA".to_owned(), "ES256".to_owned()],
    });

    let sd_jwt_algorithms = OpenID4VpPresentationFormat::SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs {
        sd_jwt_alg_values: vec!["EdDSA".to_owned(), "ES256".to_owned()],
        kb_jwt_alg_values: vec!["EdDSA".to_owned(), "ES256".to_owned()],
    });

    formats.insert("jwt_vp_json".to_owned(), algorithms.clone());
    formats.insert("jwt_vc_json".to_owned(), algorithms.clone());
    formats.insert(
        "ldp_vp".to_owned(),
        OpenID4VpPresentationFormat::LdpVcAlgs(LdpVcAlgs {
            proof_type: vec!["DataIntegrityProof".to_owned()],
        }),
    );
    formats.insert("vc+sd-jwt".to_owned(), sd_jwt_algorithms.clone());
    formats.insert("dc+sd-jwt".to_owned(), sd_jwt_algorithms);
    formats.insert("mso_mdoc".to_owned(), algorithms);
    formats
}

pub fn create_format_map(
    format_type: &FormatType,
) -> Result<HashMap<String, OpenID4VpPresentationFormat>, VerificationProtocolError> {
    match format_type {
        FormatType::Jwt | FormatType::Mdoc => {
            let key = map_to_openid4vp_format(format_type)
                .map_err(|error| VerificationProtocolError::Failed(error.to_string()))?
                .to_string();
            Ok(HashMap::from([(
                key,
                OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
                    alg: vec!["EdDSA".to_string(), "ES256".to_string()],
                }),
            )]))
        }
        FormatType::SdJwt | FormatType::SdJwtVc => {
            let key = map_to_openid4vp_format(format_type)
                .map_err(|error| VerificationProtocolError::Failed(error.to_string()))?
                .to_string();
            Ok(HashMap::from([(
                key,
                OpenID4VpPresentationFormat::SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs {
                    sd_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                    kb_jwt_alg_values: vec!["EdDSA".to_string(), "ES256".to_string()],
                }),
            )]))
        }
        FormatType::PhysicalCard => {
            unimplemented!()
        }
        FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => Ok(HashMap::from([(
            "ldp_vc".to_string(),
            OpenID4VpPresentationFormat::LdpVcAlgs(LdpVcAlgs {
                proof_type: vec!["DataIntegrityProof".to_string()],
            }),
        )])),
    }
}

pub(crate) fn create_open_id_for_vp_presentation_definition(
    interaction_id: InteractionId,
    proof_schema: &ProofSchema,
    format_type_to_input_descriptor_format: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<OpenID4VPPresentationDefinition, VerificationProtocolError> {
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
                return Err(VerificationProtocolError::Failed(
                    "Missing proof input schemas".to_owned(),
                ));
            }
        };

    Ok(OpenID4VPPresentationDefinition {
        id: interaction_id.to_string(),
        input_descriptors: requested_credentials
            .into_iter()
            .enumerate()
            .map(|(index, (credential_schema, claim_schemas))| {
                let format_type = format_to_type_mapper(&credential_schema.format)?;
                create_open_id_for_vp_presentation_definition_input_descriptor(
                    index,
                    credential_schema,
                    claim_schemas.unwrap_or_default(),
                    &format_type,
                    &format_type_to_input_descriptor_format,
                    formatter_provider,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn create_open_id_for_vp_presentation_definition_input_descriptor(
    index: usize,
    credential_schema: CredentialSchema,
    claim_schemas: Vec<ProofInputClaimSchema>,
    presentation_format_type: &FormatType,
    format_to_type_mapper: &TypeToDescriptorMapper,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<OpenID4VPPresentationDefinitionInputDescriptor, VerificationProtocolError> {
    let (id, schema_fields, intent_to_retain) = match presentation_format_type {
        FormatType::Mdoc => (credential_schema.schema_id, vec![], Some(true)),
        format_type => {
            let path = match format_type {
                FormatType::SdJwtVc => ["$.vct".to_string()],
                _ => ["$.credentialSchema.id".to_string()],
            }
            .to_vec();

            let schema_id_field = OpenID4VPPresentationDefinitionConstraintField {
                id: None,
                name: None,
                purpose: None,
                path,
                optional: None,
                filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
                    r#type: "string".to_string(),
                    r#const: credential_schema.schema_id.clone(),
                }),
                intent_to_retain: None,
            };

            (format!("input_{index}"), vec![schema_id_field], None)
        }
    };

    let selectively_disclosable = !formatter_provider
        .get_credential_formatter(&credential_schema.format)
        .ok_or(VerificationProtocolError::Failed(
            "missing provider".to_string(),
        ))?
        .get_capabilities()
        .selective_disclosure
        .is_empty();

    let limit_disclosure = if selectively_disclosable {
        Some(OpenID4VPPresentationDefinitionLimitDisclosurePreference::Required)
    } else {
        None
    };

    let claim_fields = claim_schemas
        .iter()
        .map(|claim| {
            Ok(OpenID4VPPresentationDefinitionConstraintField {
                id: Some(claim.schema.id),
                name: None,
                purpose: None,
                path: vec![format_path(&claim.schema.key, presentation_format_type)?],
                optional: Some(!claim.required),
                filter: None,
                intent_to_retain,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(OpenID4VPPresentationDefinitionInputDescriptor {
        id,
        name: Some(credential_schema.name),
        purpose: None,
        format: format_to_type_mapper(presentation_format_type)?,
        constraints: OpenID4VPPresentationDefinitionConstraint {
            fields: [schema_fields, claim_fields].concat(),
            validity_credential_nbf: None,
            limit_disclosure,
        },
    })
}

fn format_path(
    claim_key: &str,
    format_type: &FormatType,
) -> Result<String, VerificationProtocolError> {
    match format_type {
        FormatType::Mdoc => match claim_key.split_once(NESTED_CLAIM_MARKER) {
            None => Ok(format!("$['{claim_key}']")),
            Some((namespace, key)) => Ok(format!("$['{namespace}']['{key}']")),
        },
        FormatType::SdJwtVc => Ok(format!("$.{claim_key}")),
        _ => Ok(format!("$.vc.credentialSubject.{claim_key}")),
    }
}

pub(crate) fn cred_to_presentation_format_type(credential_format_type: FormatType) -> FormatType {
    match credential_format_type {
        FormatType::Jwt | FormatType::PhysicalCard => FormatType::Jwt,
        FormatType::SdJwt => FormatType::SdJwt,
        FormatType::SdJwtVc => FormatType::SdJwtVc,
        FormatType::JsonLdClassic | FormatType::JsonLdBbsPlus => FormatType::JsonLdClassic,
        FormatType::Mdoc => FormatType::Mdoc,
    }
}

pub(crate) async fn encrypted_params(
    interaction_data: &OpenID4VPHolderInteractionData,
    submission_data: VpSubmissionData,
    holder_nonce: &str,
    verifier_key: OpenID4VPClientMetadataJwkDTO,
    encryption_algorithm: AuthorizationEncryptedResponseContentEncryptionAlgorithm,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<HashMap<String, String>, VerificationProtocolError> {
    let aud = interaction_data
        .response_uri
        .clone()
        .ok_or(VerificationProtocolError::Failed(
            "response_uri is None".to_string(),
        ))?;
    let verifier_nonce =
        interaction_data
            .nonce
            .clone()
            .ok_or(VerificationProtocolError::Failed(
                "nonce is None".to_string(),
            ))?;
    let payload = JwePayload {
        aud: Some(aud),
        exp: Some(OffsetDateTime::now_utc() + Duration::minutes(10)),
        submission_data,
        state: interaction_data.state.clone(),
    };

    let response = jwe_presentation::build_jwe(
        payload,
        verifier_key.jwk.into(),
        verifier_key.key_id,
        holder_nonce,
        &verifier_nonce,
        encryption_algorithm,
        key_algorithm_provider,
    )
    .await
    .map_err(|err| {
        VerificationProtocolError::Failed(format!("Failed to build response jwe: {err}"))
    })?;
    Ok(HashMap::from_iter([("response".to_owned(), response)]))
}

pub(crate) fn deserialize_with_serde_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
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

pub(crate) fn vec_last_position_from_token_path(path: &str) -> Result<usize, OpenID4VCError> {
    // Find the position of '[' and ']'
    if let Some(open_bracket) = path.rfind('[') {
        if let Some(close_bracket) = path.rfind(']') {
            // Extract the substring between '[' and ']'
            let value = &path[open_bracket + 1..close_bracket];

            let parsed_value = value.parse().map_err(|_| {
                OpenID4VCError::MappingError("Could not parse vec position".to_string())
            })?;

            Ok(parsed_value)
        } else {
            Err(OpenID4VCError::MappingError(
                "Credential path is incorrect".to_string(),
            ))
        }
    } else {
        Ok(0)
    }
}

pub fn extract_presentation_ctx_from_interaction_content(
    content: OpenID4VPVerifierInteractionContent,
    verification_protocol_type: VerificationProtocolType,
) -> ExtractPresentationCtx {
    ExtractPresentationCtx {
        nonce: Some(content.nonce),
        client_id: Some(content.client_id),
        response_uri: content.response_uri,
        verification_protocol_type,
        format_nonce: None,
        issuance_date: None,
        expiration_date: None,
        mdoc_session_transcript: None,
        verifier_key: content.encryption_key.map(|k| k.jwk.into()),
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(CredentialClaim, ClaimSchema)>,
    issuer_details: IdentifierDetails,
    holder_details: IdentifierDetails,
    mdoc_mso: Option<MobileSecurityObject>,
    verification_protocol: &str,
    profile: &Option<String>,
    issuance_date: Option<OffsetDateTime>,
) -> Result<ProvedCredential, OpenID4VCError> {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        model_claims.extend(
            value_to_model_claims(
                credential_id,
                claim_schemas,
                value,
                now,
                &claim_schema,
                &claim_schema.key,
            )
            .map_err(|e| match e {
                ServiceError::MappingError(message) => OpenID4VCError::MappingError(message),
                ServiceError::BusinessLogic(BusinessLogicError::MissingClaimSchemas) => {
                    OpenID4VCError::MissingClaimSchemas
                }
                _ => OpenID4VCError::Other(e.to_string()),
            })?,
        );
    }

    Ok(ProvedCredential {
        credential: Credential {
            id: credential_id,
            created_date: now,
            issuance_date,
            last_modified: now,
            deleted_at: None,
            protocol: verification_protocol.to_string(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            profile: profile.clone(),
            claims: Some(model_claims.to_owned()),
            issuer_identifier: None,
            issuer_certificate: None,
            holder_identifier: None,
            schema: Some(credential_schema),
            redirect_uri: None,
            key: None,
            role: CredentialRole::Verifier,
            interaction: None,
            credential_blob_id: None,
            wallet_unit_attestation_blob_id: None,
            wallet_app_attestation_blob_id: None,
        },
        issuer_details,
        holder_details,
        mdoc_mso,
    })
}

pub(crate) fn format_to_type(
    presented_credential: &FormattedCredentialPresentation,
    config: &CoreConfig,
) -> Result<FormatType, VerificationProtocolError> {
    config
        .format
        .get_type(&presented_credential.credential_schema.format)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

pub(crate) fn unencrypted_params(
    submission_data: &VpSubmissionData,
    state: Option<String>,
) -> Result<HashMap<String, String>, VerificationProtocolError> {
    let mut result = serde_json::to_value(submission_data).map_err(|err| {
        VerificationProtocolError::Failed(format!(
            "Failed to serialize presentation submission params: {err}"
        ))
    })?;

    if let Some(state) = state {
        result
            .as_object_mut()
            .ok_or(VerificationProtocolError::Failed(
                "unsupported submission data".to_string(),
            ))?
            .insert("state".to_string(), Value::String(state));
    }

    let params = result
        .as_object()
        .ok_or(VerificationProtocolError::Failed(format!(
            "unsupported submission data: {result}"
        )))?
        .into_iter()
        .map(|(k, v)| {
            let value = if let Some(string) = v.as_str() {
                string.to_string()
            } else {
                serde_json::to_string(v).map_err(|err| {
                    VerificationProtocolError::Failed(format!(
                        "failed to serialize submission data: {err}"
                    ))
                })?
            };
            Ok((k.clone(), value))
        })
        .collect::<Result<Vec<_>, VerificationProtocolError>>()?;
    let map = HashMap::from_iter(params);
    Ok(map)
}

pub(super) mod unix_timestamp_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use time::OffsetDateTime;

    pub(crate) fn serialize<S>(
        datetime: &Option<OffsetDateTime>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        datetime
            .map(|datetime| datetime.unix_timestamp())
            .serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<i64>::deserialize(deserializer)?;
        Ok(value.and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok()))
    }
}

impl From<OpenID4VPDraftClientMetadata> for OpenID4VPClientMetadata {
    fn from(value: OpenID4VPDraftClientMetadata) -> Self {
        Self::Draft(value)
    }
}

impl From<OpenID4VPFinal1_0ClientMetadata> for OpenID4VPClientMetadata {
    fn from(value: OpenID4VPFinal1_0ClientMetadata) -> Self {
        Self::Final1_0(value)
    }
}

pub(crate) async fn format_authorization_request_client_id_scheme_x509<T: Serialize>(
    proof: &Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let JWTSigner {
        auth_fn,
        jose_algorithm,
        ..
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let verifier_identifier =
        proof
            .verifier_identifier
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "verifier_identifier is None".to_string(),
            ))?;

    let x5c =
        match verifier_identifier.r#type {
            IdentifierType::Certificate => {
                let verifier_certificate = proof.verifier_certificate.as_ref().ok_or(
                    VerificationProtocolError::Failed("verifier_certificate is None".to_string()),
                )?;

                pem_chain_into_x5c(&verifier_certificate.chain)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
            }
            IdentifierType::Did | IdentifierType::Key => {
                return Err(VerificationProtocolError::Failed(
                    "invalid verifier identifier type".to_string(),
                ));
            }
        };

    let expires_at = Some(OffsetDateTime::now_utc().add(Duration::hours(1)));

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: Some(x5c),
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: None,
            subject: None,
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-aud-of-a-request-object
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    request_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

/*
 * TODO(ONE-3846): this needs to be issued and obtained from external authority,
 *     holder needs to know the authority and should check if it's signed by it
 */
pub(crate) async fn format_authorization_request_client_id_scheme_verifier_attestation<
    T: Serialize,
>(
    proof: &Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    client_id_without_prefix: String,
    response_uri: String,
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let JWTSigner {
        auth_fn,
        verifier_key,
        key_algorithm,
        jose_algorithm,
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let jwk = key_algorithm
        .reconstruct_key(&verifier_key.public_key, None, None)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .public_key_as_jwk()
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
    let proof_of_possession_key = Some(ProofOfPossessionKey {
        key_id: None,
        jwk: ProofOfPossessionJwk::Jwk { jwk: jwk.into() },
    });

    let verifier_did = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .did
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_did is None".to_string(),
        ))?;

    let key = verifier_did
        .find_key(&verifier_key.id, &Default::default())
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .ok_or(VerificationProtocolError::Failed(
            "verifier key not found".to_string(),
        ))?;

    let key_id = verifier_did.verification_method_id(key);

    let expires_at = Some(OffsetDateTime::now_utc().add(Duration::hours(1)));

    let custom = OpenID4VCVerifierAttestationPayload {
        redirect_uris: vec![response_uri],
    };

    let attestation_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm.to_owned(),
            key_id: Some(key_id),
            r#type: Some("verifier-attestation+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
        },
        payload: JWTPayload {
            expires_at,
            issuer: Some(verifier_did.did.to_string()),

            // ... the original Client Identifier (the part without the verifier_attestation: prefix) MUST equal the sub claim value in the Verifier attestation JWT
            // <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3-3.4.1>
            subject: Some(client_id_without_prefix.clone()),
            custom,
            proof_of_possession_key,
            ..Default::default()
        },
    }
    .tokenize(Some(&*auth_fn))
    .await
    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let auth_fn = key_provider
        .get_signature_provider(verifier_key, None, key_algorithm_provider.clone())
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: Some(attestation_jwt),
            key_attestation: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            subject: Some(client_id_without_prefix),
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    request_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

pub(crate) async fn format_authorization_request_client_id_scheme_did<T: Serialize>(
    proof: &Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let JWTSigner {
        auth_fn,
        jose_algorithm,
        verifier_key,
        ..
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let verifier_did = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .did
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_did is None".to_string(),
        ))?;

    let key = verifier_did
        .find_key(&verifier_key.id, &Default::default())
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .ok_or(VerificationProtocolError::Failed(
            "verifier key not found".to_string(),
        ))?;

    let key_id = verifier_did.verification_method_id(key);

    let expires_at = Some(OffsetDateTime::now_utc().add(Duration::hours(1)));

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: Some(key_id),
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    request_jwt
        .tokenize(Some(&*auth_fn))
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

pub(crate) async fn format_authorization_request_client_id_scheme_redirect_uri<T: Serialize>(
    authorization_request: T,
) -> Result<String, VerificationProtocolError> {
    let unsigned_jwt = Jwt {
        header: JWTHeader {
            algorithm: "none".to_string(),
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            key_attestation: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    unsigned_jwt
        .tokenize(None)
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

pub(crate) fn generate_client_metadata_draft(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    config: &CoreConfig,
) -> Result<OpenID4VPDraftClientMetadata, VerificationProtocolError> {
    let vp_formats = create_open_id_for_vp_formats();
    let jwk = get_encryption_key_jwk_from_proof(proof, key_algorithm_provider, config)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(create_open_id_for_vp_client_metadata_draft(jwk, vp_formats))
}
