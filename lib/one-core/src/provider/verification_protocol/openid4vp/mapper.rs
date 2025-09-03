use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use serde::{Deserialize, Deserializer, Serialize};
use shared_types::{DidValue, ProofId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::draft20::model::OpenID4VP20AuthorizationRequest;
use super::model::{
    LdpVcAlgs, OpenID4VCVerifierAttestationPayload, OpenID4VPAlgs, OpenID4VPPresentationDefinition,
    OpenID4VPPresentationDefinitionConstraint, OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionLimitDisclosurePreference, OpenID4VPVcSdJwtAlgs,
    OpenID4VPVerifierInteractionContent, ProvedCredential,
};
use super::{JWTSigner, get_jwt_signer};
use crate::common_mapper::{
    IdentifierRole, NESTED_CLAIM_MARKER, RemoteIdentifierRelation,
    get_encryption_key_jwk_from_proof, get_or_create_identifier, value_to_model_claims,
};
use crate::config::core_config::{CoreConfig, FormatType, VerificationProtocolType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, CredentialSchemaType,
};
use crate::model::identifier::IdentifierType;
use crate::model::interaction::InteractionId;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CredentialClaim, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::ExtractPresentationCtx;
use crate::provider::verification_protocol::dto::{
    CredentialGroup, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum, PresentedCredential,
};
use crate::provider::verification_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::provider::verification_protocol::openid4vp::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp::final1_0::model::OpenID4VPFinal1_0ClientMetadata;
use crate::provider::verification_protocol::openid4vp::model::{
    NestedPresentationSubmissionDescriptorDTO, OpenID4VPClientMetadata,
    OpenID4VPDraftClientMetadata, OpenID4VpPresentationFormat, PresentationSubmissionDescriptorDTO,
    PresentationSubmissionMappingDTO,
};
use crate::provider::verification_protocol::openid4vp::service::create_open_id_for_vp_client_metadata_draft;
use crate::provider::verification_protocol::openid4vp::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocolError,
};
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::util::jwt::Jwt;
use crate::util::jwt::model::{JWTHeader, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey};
use crate::util::mdoc::MobileSecurityObject;
use crate::util::oidc::map_to_openid4vp_format;
use crate::util::x509::pem_chain_into_x5c;

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
        _ => {
            let path = match credential_schema.schema_type {
                CredentialSchemaType::SdJwtVc => ["$.vct".to_string()],
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

pub(crate) fn create_presentation_submission(
    presentation_definition_id: String,
    credential_presentations: Vec<PresentedCredential>,
    format: &str,
) -> Result<PresentationSubmissionMappingDTO, VerificationProtocolError> {
    let path_nested_supported = format == "jwt_vp_json" || format == "ldp_vp";
    Ok(PresentationSubmissionMappingDTO {
        id: Uuid::new_v4().to_string(),
        definition_id: presentation_definition_id,
        descriptor_map: credential_presentations
            .into_iter()
            .enumerate()
            .map(|(index, presented_credential)| {
                Ok(PresentationSubmissionDescriptorDTO {
                    id: presented_credential.request.id,
                    format: format.to_owned(),
                    path: "$".to_string(),
                    path_nested: if path_nested_supported {
                        let credential_format = presented_credential
                            .credential_schema
                            .format
                            .parse()
                            .map_err(|_| {
                                VerificationProtocolError::Failed("format not found".to_string())
                            })?;
                        Some(NestedPresentationSubmissionDescriptorDTO {
                            format: map_to_openid4vp_format(&credential_format)
                                .map_err(|error| {
                                    VerificationProtocolError::Failed(error.to_string())
                                })?
                                .to_string(),
                            path: format!("$.vp.verifiableCredential[{index}]"),
                        })
                    } else {
                        None
                    },
                })
            })
            .collect::<Result<_, _>>()?,
    })
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

#[allow(clippy::too_many_arguments)]
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
            revocation_list: None,
            credential_blob_id: None,
        },
        issuer_details,
        holder_details,
        mdoc_mso,
    })
}

impl OpenID4VP20AuthorizationRequest {
    pub async fn as_signed_jwt(
        &self,
        did: &DidValue,
        auth_fn: AuthenticationFn,
    ) -> Result<String, ServiceError> {
        let unsigned_jwt = Jwt {
            header: JWTHeader {
                algorithm: auth_fn.jose_alg().ok_or(KeyAlgorithmError::Failed(
                    "No JOSE alg specified".to_string(),
                ))?,
                key_id: auth_fn.get_key_id(),
                r#type: Some("oauth-authz-req+jwt".to_string()),
                jwk: None,
                jwt: None,
                x5c: None,
            },
            payload: JWTPayload {
                issued_at: None,
                expires_at: Some(OffsetDateTime::now_utc().add(Duration::hours(1))),
                invalid_before: None,
                issuer: Some(did.to_string()),
                subject: None,
                audience: None,
                jwt_id: None,
                proof_of_possession_key: None,
                custom: self.clone(),
            },
        };
        Ok(unsigned_jwt.tokenize(Some(auth_fn)).await?)
    }
}

pub(crate) fn map_presented_credentials_to_presentation_format_type(
    presented: &[PresentedCredential],
    config: &CoreConfig,
) -> Result<FormatType, VerificationProtocolError> {
    // MDOC credential(s) are sent as a MDOC presentation, using the MDOC formatter
    if presented.len() == 1 && matches_format_types(presented, &[FormatType::Mdoc], config) {
        return Ok(FormatType::Mdoc);
    }

    // The SD-JWT VC presentations can contain only one credential
    if presented.len() == 1 && matches_format_types(presented, &[FormatType::SdJwtVc], config) {
        return Ok(FormatType::SdJwtVc);
    }

    if matches_format_types(
        presented,
        &[FormatType::JsonLdClassic, FormatType::JsonLdBbsPlus],
        config,
    ) {
        return Ok(FormatType::JsonLdClassic);
    }

    // Fallback, handle all other formats via enveloped JWT
    Ok(FormatType::Jwt)
}

fn matches_format_types(
    presented: &[PresentedCredential],
    types: &[FormatType],
    config: &CoreConfig,
) -> bool {
    presented.iter().all(|cred| {
        format_to_type(cred, config).is_ok_and(|format_type| types.contains(&format_type))
    })
}

pub(crate) fn format_to_type(
    presented_credential: &PresentedCredential,
    config: &CoreConfig,
) -> Result<FormatType, VerificationProtocolError> {
    Ok(config
        .format
        .get_fields(&presented_credential.credential_schema.format)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .r#type)
}

/// Expands the list of credentials to have the validity credential be their own independent entry
/// in the list. This is done to preserve legacy behaviour that heavily depends on the length of the
/// list.
pub(crate) fn explode_validity_credentials(
    credential_presentations: Vec<PresentedCredential>,
) -> Vec<PresentedCredential> {
    credential_presentations
        .into_iter()
        .flat_map(|cred| {
            if let Some(validity_cred) = cred.validity_credential_presentation {
                let validity_credential_presentation = PresentedCredential {
                    presentation: validity_cred,
                    validity_credential_presentation: None,
                    credential_schema: cred.credential_schema.clone(),
                    request: cred.request.clone(),
                };
                vec![
                    PresentedCredential {
                        validity_credential_presentation: None,
                        ..cred
                    },
                    validity_credential_presentation,
                ]
            } else {
                vec![cred]
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn credential_from_proved(
    proved_credential: ProvedCredential,
    organisation: &Organisation,
    did_repository: &dyn DidRepository,
    certificate_repository: &dyn CertificateRepository,
    identifier_repository: &dyn IdentifierRepository,
    certificate_validator: &dyn CertificateValidator,
    did_method_provider: &dyn DidMethodProvider,
    key_repository: &dyn KeyRepository,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<Credential, ServiceError> {
    let (issuer_identifier, issuer_relation) = get_or_create_identifier(
        did_method_provider,
        did_repository,
        certificate_repository,
        certificate_validator,
        key_repository,
        key_algorithm_provider,
        identifier_repository,
        &Some(organisation.to_owned()),
        &proved_credential.issuer_details,
        IdentifierRole::Issuer,
    )
    .await?;

    let issuer_certificate =
        if let RemoteIdentifierRelation::Certificate(certificate) = issuer_relation {
            Some(certificate)
        } else {
            None
        };

    let (holder_identifier, ..) = get_or_create_identifier(
        did_method_provider,
        did_repository,
        certificate_repository,
        certificate_validator,
        key_repository,
        key_algorithm_provider,
        identifier_repository,
        &Some(organisation.to_owned()),
        &proved_credential.holder_details,
        IdentifierRole::Holder,
    )
    .await?;

    Ok(Credential {
        id: proved_credential.credential.id,
        created_date: proved_credential.credential.created_date,
        issuance_date: proved_credential.credential.issuance_date,
        last_modified: proved_credential.credential.last_modified,
        deleted_at: proved_credential.credential.deleted_at,
        protocol: proved_credential.credential.protocol,
        redirect_uri: proved_credential.credential.redirect_uri,
        role: proved_credential.credential.role,
        state: proved_credential.credential.state,
        claims: convert_inner_of_inner(proved_credential.credential.claims),
        issuer_identifier: Some(issuer_identifier),
        issuer_certificate,
        holder_identifier: Some(holder_identifier),
        schema: proved_credential
            .credential
            .schema
            .map(|schema| from_provider_schema(schema, organisation.to_owned())),
        interaction: None,
        revocation_list: None,
        key: proved_credential.credential.key,
        suspend_end_date: convert_inner(proved_credential.credential.suspend_end_date),
        profile: proved_credential.credential.profile,
        credential_blob_id: proved_credential.credential.credential_blob_id,
    })
}

fn from_provider_schema(schema: CredentialSchema, organisation: Organisation) -> CredentialSchema {
    CredentialSchema {
        id: schema.id,
        deleted_at: schema.deleted_at,
        created_date: schema.created_date,
        last_modified: schema.last_modified,
        name: schema.name,
        external_schema: schema.external_schema,
        format: schema.format,
        revocation_method: schema.revocation_method,
        wallet_storage_type: convert_inner(schema.wallet_storage_type),
        layout_type: schema.layout_type,
        layout_properties: convert_inner(schema.layout_properties),
        imported_source_url: schema.imported_source_url,
        schema_id: schema.schema_id,
        schema_type: schema.schema_type,
        claim_schemas: convert_inner_of_inner(schema.claim_schemas),
        organisation: organisation.into(),
        allow_suspension: schema.allow_suspension,
    }
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

pub(crate) async fn format_authorization_request_client_id_scheme_x509_san_dns<T: Serialize>(
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

    let (x5c, issuer) =
        match verifier_identifier.r#type {
            IdentifierType::Did => {
                return Err(VerificationProtocolError::Failed(
                    "invalid verifier identifier type".to_string(),
                ));
            }
            IdentifierType::Certificate => {
                let verifier_certificate = proof.verifier_certificate.as_ref().ok_or(
                    VerificationProtocolError::Failed("verifier_certificate is None".to_string()),
                )?;

                let x5c = pem_chain_into_x5c(&verifier_certificate.chain)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

                (x5c, None)
            }
            IdentifierType::Key => {
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
            x5c: Some(x5c),
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer,
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-aud-of-a-request-object
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: authorization_request,
        },
    };

    request_jwt
        .tokenize(Some(auth_fn))
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
    .tokenize(Some(auth_fn))
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
        .tokenize(Some(auth_fn))
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
        .tokenize(Some(auth_fn))
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
    key_provider: &dyn KeyProvider,
) -> Result<OpenID4VPDraftClientMetadata, VerificationProtocolError> {
    let vp_formats = create_open_id_for_vp_formats();
    let jwk = get_encryption_key_jwk_from_proof(proof, key_algorithm_provider, key_provider)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(create_open_id_for_vp_client_metadata_draft(jwk, vp_formats))
}
