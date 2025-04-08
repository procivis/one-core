use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use one_dto_mapper::convert_inner;
use serde::{Deserialize, Deserializer};
use shared_types::{DidValue, KeyId, ProofId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::model::{
    ClientIdScheme, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    DidListItemResponseDTO, LdpVcAlgs, OpenID4VPAlgs, OpenID4VPAuthorizationRequestParams,
    OpenID4VPAuthorizationRequestQueryParams, OpenID4VPHolderInteractionData,
    OpenID4VPPresentationDefinition, OpenID4VPPresentationDefinitionConstraint,
    OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionLimitDisclosurePreference, OpenID4VPVcSdJwtAlgs,
    OpenID4VPVerifierInteractionContent, OpenID4VpParams, ProvedCredential,
};
use super::service::create_open_id_for_vp_client_metadata;
use crate::common_mapper::{value_to_model_claims, NESTED_CLAIM_MARKER};
use crate::config::core_config::{CoreConfig, FormatType};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema, CredentialSchemaClaim,
    CredentialSchemaType, LayoutProperties, LogoProperties,
};
use crate::model::did::Did;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::provider::credential_formatter::jwt::model::{JWTHeader, JWTPayload};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::model::{AuthenticationFn, ExtractPresentationCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::dto::{
    CredentialGroup, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::verification_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::provider::verification_protocol::openid4vp_draft20::error::OpenID4VCError;
use crate::provider::verification_protocol::openid4vp_draft20::model::{
    NestedPresentationSubmissionDescriptorDTO, OpenID4VpPresentationFormat,
    PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO, PresentedCredential,
};
use crate::provider::verification_protocol::openid4vp_draft20::{
    FormatMapper, TypeToDescriptorMapper, VerificationProtocolError,
};
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::oid4vp_draft20::proof_request::{
    generate_authorization_request_client_id_scheme_did,
    generate_authorization_request_client_id_scheme_verifier_attestation,
    generate_authorization_request_client_id_scheme_x509_san_dns,
};
use crate::util::oidc::{determine_response_mode, map_to_openid4vp_format};

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
                            .map(|credential| credential.id.to_string())
                            .collect(),
                        inapplicable_credentials: group
                            .inapplicable_credentials
                            .into_iter()
                            .map(|credential| credential.id.to_string())
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
pub(crate) fn create_open_id_for_vp_formats() -> HashMap<String, OpenID4VpPresentationFormat> {
    let mut formats = HashMap::new();
    let algorithms = OpenID4VpPresentationFormat::GenericAlgList(OpenID4VPAlgs {
        alg: vec!["EdDSA".to_owned(), "ES256".to_owned()],
    });

    let sd_jwt_algorithms = OpenID4VpPresentationFormat::SdJwtVcAlgs(OpenID4VPVcSdJwtAlgs {
        sd_jwt_algorithms: vec!["EdDSA".to_owned(), "ES256".to_owned()],
        kb_jwt_algorithms: vec!["EdDSA".to_owned(), "ES256".to_owned()],
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
                    sd_jwt_algorithms: vec!["EdDSA".to_string(), "ES256".to_string()],
                    kb_jwt_algorithms: vec!["EdDSA".to_string(), "ES256".to_string()],
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
    proof: &Proof,
    format_type_to_input_descriptor_format: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<OpenID4VPPresentationDefinition, VerificationProtocolError> {
    let proof_schema = proof
        .schema
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
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
                return Err(VerificationProtocolError::Failed(
                    "Missing proof input schemas".to_owned(),
                ))
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
        .get_formatter(&credential_schema.format)
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
        FormatType::SdJwtVc => Ok(format!("$.{}", claim_key)),
        _ => Ok(format!("$.vc.credentialSubject.{}", claim_key)),
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_open_id_for_vp_sharing_url_encoded(
    base_url: &str,
    openidvc_params: &OpenID4VpParams,
    client_id: String,
    interaction_id: InteractionId,
    interaction_data: &OpenID4VPVerifierInteractionContent,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    client_id_scheme: ClientIdScheme,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, VerificationProtocolError> {
    let params = if openidvc_params.use_request_uri {
        get_params_with_request_uri(base_url, proof.id, client_id, client_id_scheme)
    } else {
        match client_id_scheme {
            ClientIdScheme::RedirectUri => get_params_for_redirect_uri(
                base_url,
                openidvc_params,
                client_id,
                interaction_id,
                nonce,
                proof,
                key_id,
                encryption_key_jwk,
                vp_formats,
                interaction_data,
            )?,
            ClientIdScheme::X509SanDns => {
                let token = generate_authorization_request_client_id_scheme_x509_san_dns(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                )
                .await?;
                get_params_with_request(token, client_id, client_id_scheme)
            }
            ClientIdScheme::VerifierAttestation => {
                let token = generate_authorization_request_client_id_scheme_verifier_attestation(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                    did_method_provider,
                )
                .await?;
                get_params_with_request(token, client_id, client_id_scheme)
            }
            ClientIdScheme::Did => {
                let token = generate_authorization_request_client_id_scheme_did(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                    did_method_provider,
                )
                .await?;
                get_params_with_request(token, client_id, client_id_scheme)
            }
        }
    };

    let encoded_params = serde_urlencoded::to_string(params)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(encoded_params)
}

fn get_params_with_request_uri(
    base_url: &str,
    proof_id: ProofId,
    client_id: String,
    client_id_scheme: ClientIdScheme,
) -> OpenID4VPAuthorizationRequestQueryParams {
    OpenID4VPAuthorizationRequestQueryParams {
        client_id,
        request_uri: Some(format!(
            "{base_url}/ssi/openid4vp/draft-20/{}/client-request",
            proof_id
        )),
        client_id_scheme: Some(client_id_scheme),
        state: None,
        nonce: None,
        response_type: None,
        response_mode: None,
        response_uri: None,
        client_metadata: None,
        client_metadata_uri: None,
        presentation_definition: None,
        presentation_definition_uri: None,
        request: None,
        redirect_uri: None,
    }
}

fn get_params_with_request(
    request: String,
    client_id: String,
    client_id_scheme: ClientIdScheme,
) -> OpenID4VPAuthorizationRequestQueryParams {
    OpenID4VPAuthorizationRequestQueryParams {
        client_id,
        request: Some(request),
        client_id_scheme: Some(client_id_scheme),
        state: None,
        nonce: None,
        response_type: None,
        response_mode: None,
        response_uri: None,
        client_metadata: None,
        client_metadata_uri: None,
        presentation_definition: None,
        presentation_definition_uri: None,
        request_uri: None,
        redirect_uri: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn get_params_for_redirect_uri(
    base_url: &str,
    openidvc_params: &OpenID4VpParams,
    client_id: String,
    interaction_id: InteractionId,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    interaction_data: &OpenID4VPVerifierInteractionContent,
) -> Result<OpenID4VPAuthorizationRequestQueryParams, VerificationProtocolError> {
    let mut presentation_definition = None;
    let mut presentation_definition_uri = None;
    if openidvc_params.presentation_definition_by_value {
        let pd = serde_json::to_string(&interaction_data.presentation_definition)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        presentation_definition = Some(pd);
    } else {
        presentation_definition_uri = Some(format!(
            "{base_url}/ssi/openid4vp/draft-20/{}/presentation-definition",
            proof.id
        ));
    }

    let mut client_metadata = None;
    let mut client_metadata_uri = None;
    if openidvc_params.client_metadata_by_value {
        let metadata = serde_json::to_string(&create_open_id_for_vp_client_metadata(
            key_id,
            encryption_key_jwk,
            vp_formats,
        ))
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        client_metadata = Some(metadata);
    } else {
        client_metadata_uri = Some(format!(
            "{base_url}/ssi/openid4vp/draft-20/{}/client-metadata",
            proof.id
        ));
    }

    Ok(OpenID4VPAuthorizationRequestQueryParams {
        client_id: client_id.to_string(),
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
        response_type: Some("vp_token".to_string()),
        state: Some(interaction_id.to_string()),
        nonce: Some(nonce),
        response_mode: Some(determine_response_mode(proof)?),
        response_uri: Some(client_id),
        client_metadata,
        client_metadata_uri,
        presentation_definition,
        presentation_definition_uri,
        request: None,
        request_uri: None,
        redirect_uri: None,
    })
}

impl TryFrom<OpenID4VPAuthorizationRequestQueryParams> for OpenID4VPHolderInteractionData {
    type Error = VerificationProtocolError;

    fn try_from(value: OpenID4VPAuthorizationRequestQueryParams) -> Result<Self, Self::Error> {
        let url_parse = |uri: String| {
            Url::parse(&uri).map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        };

        fn json_parse<T: for<'a> Deserialize<'a>>(
            input: String,
        ) -> Result<T, VerificationProtocolError> {
            serde_json::from_str(&input)
                .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        }

        Ok(Self {
            client_id: value.client_id,
            client_id_scheme: value
                .client_id_scheme
                .unwrap_or(ClientIdScheme::RedirectUri),
            response_type: value.response_type,
            response_mode: value.response_mode,
            response_uri: value.response_uri.map(url_parse).transpose()?,
            state: value.state,
            nonce: value.nonce,
            client_metadata: value.client_metadata.map(json_parse).transpose()?,
            client_metadata_uri: value.client_metadata_uri.map(url_parse).transpose()?,
            presentation_definition: value.presentation_definition.map(json_parse).transpose()?,
            presentation_definition_uri: value
                .presentation_definition_uri
                .map(url_parse)
                .transpose()?,
            redirect_uri: value.redirect_uri,
            verifier_did: None,
        })
    }
}

impl From<OpenID4VPAuthorizationRequestParams> for OpenID4VPHolderInteractionData {
    fn from(value: OpenID4VPAuthorizationRequestParams) -> Self {
        Self {
            client_id: value.client_id,
            client_id_scheme: value
                .client_id_scheme
                .unwrap_or(ClientIdScheme::RedirectUri),
            response_type: value.response_type,
            response_mode: value.response_mode,
            response_uri: value.response_uri,
            state: value.state,
            nonce: value.nonce,
            client_metadata: value.client_metadata,
            client_metadata_uri: value.client_metadata_uri,
            presentation_definition: value.presentation_definition,
            presentation_definition_uri: value.presentation_definition_uri,
            redirect_uri: value.redirect_uri,
            verifier_did: None,
        }
    }
}

pub fn deserialize_with_serde_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
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

pub(super) fn parse_interaction_content(
    data: &[u8],
) -> Result<OpenID4VPVerifierInteractionContent, OpenID4VCError> {
    serde_json::from_slice(data).map_err(|e| OpenID4VCError::MappingError(e.to_string()))
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
) -> ExtractPresentationCtx {
    ExtractPresentationCtx {
        nonce: Some(content.nonce),
        client_id: Some(content.client_id),
        response_uri: content.response_uri,
        ..Default::default()
    }
}

pub fn extracted_credential_to_model(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema: CredentialSchema,
    claims: Vec<(serde_json::Value, ClaimSchema)>,
    issuer_did: &DidValue,
    holder_did: &DidValue,
    mdoc_mso: Option<MobileSecurityObject>,
) -> Result<ProvedCredential, OpenID4VCError> {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();

    let mut model_claims = vec![];
    for (value, claim_schema) in claims {
        model_claims.extend(
            value_to_model_claims(
                credential_id,
                claim_schemas,
                &value,
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
            issuance_date: now,
            last_modified: now,
            deleted_at: None,
            credential: vec![],
            exchange: "OPENID4VCI_DRAFT13".to_string(),
            state: CredentialStateEnum::Accepted,
            suspend_end_date: None,
            claims: Some(model_claims.to_owned()),
            issuer_did: None,
            holder_did: None,
            schema: Some(credential_schema),
            redirect_uri: None,
            key: None,
            role: CredentialRole::Verifier,
            interaction: None,
            revocation_list: None,
        },
        issuer_did_value: issuer_did.to_owned(),
        holder_did_value: holder_did.to_owned(),
        mdoc_mso,
    })
}

impl From<CredentialSchemaBackgroundPropertiesRequestDTO> for BackgroundProperties {
    fn from(value: CredentialSchemaBackgroundPropertiesRequestDTO) -> Self {
        Self {
            color: value.color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaLogoPropertiesRequestDTO> for LogoProperties {
    fn from(value: CredentialSchemaLogoPropertiesRequestDTO) -> Self {
        Self {
            font_color: value.font_color,
            background_color: value.background_color,
            image: value.image,
        }
    }
}

impl From<CredentialSchemaCodePropertiesRequestDTO> for CodeProperties {
    fn from(value: CredentialSchemaCodePropertiesRequestDTO) -> Self {
        Self {
            attribute: value.attribute,
            r#type: value.r#type.into(),
        }
    }
}

impl From<CredentialSchemaCodeTypeEnum> for CodeTypeEnum {
    fn from(value: CredentialSchemaCodeTypeEnum) -> Self {
        match value {
            CredentialSchemaCodeTypeEnum::Barcode => Self::Barcode,
            CredentialSchemaCodeTypeEnum::Mrz => Self::Mrz,
            CredentialSchemaCodeTypeEnum::QrCode => Self::QrCode,
        }
    }
}

impl From<Did> for DidListItemResponseDTO {
    fn from(value: Did) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            did: value.did,
            did_type: value.did_type,
            did_method: value.did_method,
            deactivated: value.deactivated,
        }
    }
}

impl From<LayoutProperties> for CredentialSchemaLayoutPropertiesRequestDTO {
    fn from(value: LayoutProperties) -> Self {
        Self {
            background: value.background.map(|value| {
                CredentialSchemaBackgroundPropertiesRequestDTO {
                    color: value.color,
                    image: value.image,
                }
            }),
            logo: value
                .logo
                .map(|v| CredentialSchemaLogoPropertiesRequestDTO {
                    font_color: v.font_color,
                    background_color: v.background_color,
                    image: v.image,
                }),
            primary_attribute: value.primary_attribute,
            secondary_attribute: value.secondary_attribute,
            picture_attribute: value.picture_attribute,
            code: value
                .code
                .map(|v| CredentialSchemaCodePropertiesRequestDTO {
                    attribute: v.attribute,
                    r#type: match v.r#type {
                        CodeTypeEnum::Barcode => CredentialSchemaCodeTypeEnum::Barcode,
                        CodeTypeEnum::Mrz => CredentialSchemaCodeTypeEnum::Mrz,
                        CodeTypeEnum::QrCode => CredentialSchemaCodeTypeEnum::QrCode,
                    },
                }),
        }
    }
}

impl OpenID4VPAuthorizationRequestParams {
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
                vc_type: None,
                proof_of_possession_key: None,
                custom: self.clone(),
            },
        };
        Ok(unsigned_jwt.tokenize(Some(auth_fn)).await?)
    }
}
