use std::collections::HashMap;
use std::ops::Add;
use std::sync::Arc;

use indexmap::map::Entry;
use indexmap::IndexMap;
use one_dto_mapper::convert_inner;
use serde::{Deserialize, Deserializer};
use shared_types::{ClaimSchemaId, CredentialId, CredentialSchemaId, DidValue, KeyId, ProofId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::error::OpenID4VCIError;
use super::model::{
    ClientIdSchemaType, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLogoPropertiesRequestDTO,
    DidListItemResponseDTO, OpenID4VCICredentialConfigurationData, OpenID4VCICredentialSubjectItem,
    OpenID4VCIInteractionDataDTO, OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCITokenResponseDTO, OpenID4VCParams, OpenID4VPAuthorizationRequestParams,
    OpenID4VPAuthorizationRequestQueryParams, OpenID4VPHolderInteractionData,
    OpenID4VPPresentationDefinition, OpenID4VPPresentationDefinitionConstraint,
    OpenID4VPPresentationDefinitionConstraintField,
    OpenID4VPPresentationDefinitionConstraintFieldFilter,
    OpenID4VPPresentationDefinitionInputDescriptor,
    OpenID4VPPresentationDefinitionLimitDisclosurePreference, OpenID4VPVerifierInteractionContent,
    ProvedCredential, Timestamp,
};
use super::service::create_open_id_for_vp_client_metadata;
use crate::common_mapper::{value_to_model_claims, NESTED_CLAIM_MARKER};
use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    Arrayed, BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema,
    CredentialSchemaClaim, CredentialSchemaClaimsNestedObjectView,
    CredentialSchemaClaimsNestedTypeView, CredentialSchemaClaimsNestedView, LayoutProperties,
    LogoProperties,
};
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::model::proof_schema::ProofInputClaimSchema;
use crate::provider::credential_formatter::jwt::model::{JWTHeader, JWTPayload};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::MobileSecurityObject;
use crate::provider::credential_formatter::model::{AuthenticationFn, ExtractPresentationCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::dto::{
    CredentialGroup, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::exchange_protocol::mapper::{
    create_presentation_definition_field, credential_model_to_credential_dto,
};
use crate::provider::exchange_protocol::openid4vc::error::OpenID4VCError;
use crate::provider::exchange_protocol::openid4vc::model::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, NestedPresentationSubmissionDescriptorDTO,
    OpenID4VCICredentialValueDetails, OpenID4VPFormat,
    OpenID4VPPresentationDefinitionInputDescriptorFormat, PresentationSubmissionDescriptorDTO,
    PresentationSubmissionMappingDTO, PresentedCredential,
};
use crate::provider::exchange_protocol::openid4vc::{
    ExchangeProtocolError, FormatMapper, TypeToDescriptorMapper,
};
use crate::provider::http_client;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::service::credential::dto::DetailCredentialSchemaResponseDTO;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::oidc::proof_request::{
    generate_authorization_request_client_id_scheme_verifier_attestation,
    generate_authorization_request_client_id_scheme_x509_san_dns,
};
use crate::util::oidc::{determine_response_mode, map_core_to_oidc_format};

pub(super) fn presentation_definition_from_interaction_data(
    proof_id: ProofId,
    credentials: Vec<Credential>,
    credential_groups: Vec<CredentialGroup>,
    config: &CoreConfig,
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

pub(crate) fn prepare_nested_representation(
    credential_schema: &CredentialSchema,
    config: &CoreConfig,
) -> Result<OpenID4VCICredentialSubjectItem, OpenID4VCIError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(OpenID4VCIError::RuntimeError(
                "claim_schema is None".to_string(),
            ))?;

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

    claim_schemas
        .iter()
        .try_fold(Default::default(), |state, claim_schema| {
            insert_claim_schema(state, claim_schema, claim_schemas, &object_types)
        })
}

fn insert_claim_schema(
    mut root: OpenID4VCICredentialSubjectItem,
    claim_schema: &CredentialSchemaClaim,
    claim_schemas: &[CredentialSchemaClaim],
    object_types: &Vec<&str>,
) -> Result<OpenID4VCICredentialSubjectItem, OpenID4VCIError> {
    let (parent_claim, tail) = match claim_schema.schema.key.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((head, tail)) => (
            get_or_insert(&mut root, head, claim_schemas, object_types)?,
            tail,
        ),
        None => (&mut root, claim_schema.schema.key.as_str()),
    };

    match (
        claim_schema.schema.array,
        object_types.contains(&claim_schema.schema.data_type.as_str()),
    ) {
        // Array of object descriptions goes like this:
        //"array of objects": [
        //   {
        //     "field1": {
        //       "mandatory": true,
        //     },
        //     "field2": {
        //       "mandatory": true,
        //     }
        //   }
        // ],
        (true, true) => {
            let parent_arrays = parent_claim.arrays.get_or_insert(IndexMap::default());
            parent_arrays.insert(
                tail.to_owned(),
                vec![OpenID4VCICredentialSubjectItem {
                    ..Default::default()
                }],
            );
        }

        // Array of e.g strings goes like this:
        // "array of strings": {
        //   "value_type": "string[]"
        // }
        (true, false) => {
            let parent_claims = parent_claim.claims.get_or_insert(IndexMap::default());
            parent_claims.insert(
                tail.to_owned(),
                OpenID4VCICredentialSubjectItem {
                    value_type: Some(format!(
                        "{}[]",
                        claim_schema.schema.data_type.to_lowercase()
                    )),
                    mandatory: Some(claim_schema.required),
                    ..Default::default()
                },
            );
        }

        // Regular claims
        (false, is_object) => {
            let parent_claims = parent_claim.claims.get_or_insert(IndexMap::default());
            let (value_type, mandatory) = if is_object {
                (None, None)
            } else {
                (
                    Some(claim_schema.schema.data_type.to_lowercase()),
                    Some(claim_schema.required),
                )
            };

            parent_claims.insert(
                tail.to_owned(),
                OpenID4VCICredentialSubjectItem {
                    value_type,
                    mandatory,
                    ..Default::default()
                },
            );
        }
    }

    Ok(root)
}

fn get_or_insert<'a>(
    root: &'a mut OpenID4VCICredentialSubjectItem,
    path: &str,
    claim_schemas: &[CredentialSchemaClaim],
    object_types: &Vec<&str>,
) -> Result<&'a mut OpenID4VCICredentialSubjectItem, OpenID4VCIError> {
    let item_schema = claim_schemas
        .iter()
        .find(|schema| schema.schema.key == path)
        .ok_or_else(|| OpenID4VCIError::RuntimeError("missing claim schema".into()))?;

    let (parent_claim, tail) = match path.rsplit_once(NESTED_CLAIM_MARKER) {
        Some((head, tail)) => (
            get_or_insert(root, head, claim_schemas, object_types)?,
            tail,
        ),
        None => (root, item_schema.schema.key.as_str()),
    };

    let result = match (
        item_schema.schema.array,
        object_types.contains(&item_schema.schema.data_type.as_str()),
    ) {
        // Array of objects
        (true, true) => {
            let parent_arrays = parent_claim.arrays.get_or_insert(IndexMap::new());

            match parent_arrays.entry(tail.to_string()) {
                Entry::Occupied(occupied_entry) => {
                    let array_items = occupied_entry.into_mut();
                    array_items.first_mut().ok_or(OpenID4VCIError::RuntimeError(
                        "object array is empty".to_string(),
                    ))
                }
                Entry::Vacant(vacant_entry) => {
                    let array_items =
                        vacant_entry.insert(vec![OpenID4VCICredentialSubjectItem::default()]);
                    array_items.first_mut().ok_or(OpenID4VCIError::RuntimeError(
                        "object array is empty".to_string(),
                    ))
                }
            }
        }

        // Array of e.g. strings
        (true, false) => {
            let parent_claims = parent_claim.claims.get_or_insert(IndexMap::new());
            match parent_claims.entry(tail.to_string()) {
                Entry::Occupied(occupied_entry) => Ok(occupied_entry.into_mut()),
                Entry::Vacant(vacant_entry) => {
                    Ok(vacant_entry.insert(OpenID4VCICredentialSubjectItem::default()))
                }
            }
        }

        //Just typical claim schema
        (false, is_object) => {
            let parent_claims = parent_claim.claims.get_or_insert(IndexMap::new());
            match parent_claims.entry(tail.to_string()) {
                Entry::Occupied(occupied_entry) => Ok(occupied_entry.into_mut()),
                Entry::Vacant(vacant_entry) => {
                    if is_object {
                        Ok(vacant_entry.insert(OpenID4VCICredentialSubjectItem::default()))
                    } else {
                        Ok(vacant_entry.insert(OpenID4VCICredentialSubjectItem {
                            value_type: Some(item_schema.schema.data_type.to_lowercase()),
                            mandatory: Some(item_schema.required),
                            order: None,
                            ..Default::default()
                        }))
                    }
                }
            }
        }
    }?;

    Ok(result)
}

pub(super) fn create_claims_from_credential_definition(
    credential_id: CredentialId,
    claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
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
                array: false,
            },
            required: false,
        };

        let claim = Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: value_details.value.to_string(),
            path: new_schema_claim.schema.key.to_owned(),
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
                array: false,
            },
            required: false,
        })
    }

    Ok((claim_schemas, claims))
}

pub(crate) fn get_parent_claim_paths(path: &str) -> Vec<&str> {
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

pub(crate) fn parse_procivis_schema_claim(
    claim: CredentialClaimSchemaDTO,
) -> CredentialClaimSchemaRequestDTO {
    CredentialClaimSchemaRequestDTO {
        key: claim.key,
        datatype: claim.datatype,
        required: claim.required,
        array: Some(claim.array),
        claims: claim
            .claims
            .into_iter()
            .map(parse_procivis_schema_claim)
            .collect(),
    }
}

fn parse_schema_element(
    key: &str,
    item: &OpenID4VCICredentialSubjectItem,
    is_array: bool,
) -> CredentialClaimSchemaRequestDTO {
    let mut collected_claims = Vec::new();

    if let Some(claims) = item.claims.as_ref() {
        for (key, item) in claims {
            collected_claims.push(parse_schema_element(key, item, false));
        }
    }

    if let Some(arrays) = item.arrays.as_ref() {
        for (key, elements) in arrays {
            if let Some(first_element) = elements.first() {
                collected_claims.push(parse_schema_element(key, first_element, true));
            }
        }
    }

    // Item doesn't have an order. It's defined for the whole collection and separated with `~`
    if let Some(order) = item.order.as_ref() {
        collected_claims.sort_by_key(|claim| {
            order
                .iter()
                .position(|order_entry| order_entry == &claim.key)
                .unwrap_or_default()
        });
    }

    let datatype = if item.claims.is_some() || item.arrays.is_some() {
        "OBJECT".to_string()
    } else {
        item.value_type
            .as_ref()
            .map(|dt| dt.to_uppercase())
            .unwrap_or("OBJECT".to_string())
    };

    CredentialClaimSchemaRequestDTO {
        key: key.to_owned(),
        datatype,
        required: item.mandatory.unwrap_or(false),
        array: Some(is_array),
        claims: collected_claims,
    }
}

pub(crate) fn parse_mdoc_schema_claims(
    values: IndexMap<String, OpenID4VCICredentialSubjectItem>,
    element_order: Option<Vec<String>>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut claims_by_namespace: Vec<_> = values
        .into_iter()
        .map(|(namespace, subject)| parse_schema_element(&namespace, &subject, false))
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

fn from_jwt_request_claim_schema(
    now: OffsetDateTime,
    id: ClaimSchemaId,
    key: String,
    datatype: String,
    required: bool,
    array: Option<bool>,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id,
            key,
            data_type: datatype,
            created_date: now,
            last_modified: now,
            array: array.unwrap_or(false),
        },
        required,
    }
}

pub(crate) async fn fetch_procivis_schema(
    schema_id: &str,
    http_client: &dyn HttpClient,
) -> Result<CredentialSchemaDetailResponseDTO, http_client::Error> {
    http_client
        .get(schema_id)
        .send()
        .await?
        .error_for_status()?
        .json()
}

pub fn from_create_request(
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    format_type: &str,
    schema_type: Option<String>,
) -> Result<CredentialSchema, ExchangeProtocolError> {
    from_create_request_with_id(
        Uuid::new_v4().into(),
        request,
        organisation,
        core_base_url,
        format_type,
        schema_type,
    )
}

pub fn from_create_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    format_type: &str,
    schema_type: Option<String>,
) -> Result<CredentialSchema, ExchangeProtocolError> {
    if request.claims.is_empty() {
        return Err(ExchangeProtocolError::Failed(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    let url = format!("{core_base_url}/ssi/schema/v1/{id}");
    let schema_id = request.schema_id.unwrap_or(url.clone());
    let schema_type = schema_type.unwrap_or(match format_type {
        "MDOC" => "mdoc".to_owned(),
        _ => "ProcivisOneSchema2024".to_owned(),
    });

    Ok(CredentialSchema {
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name,
        format: request.format,
        wallet_storage_type: request.wallet_storage_type,
        revocation_method: request.revocation_method,
        claim_schemas: Some(
            claim_schemas
                .into_iter()
                .map(|claim_schema| {
                    from_jwt_request_claim_schema(
                        now,
                        Uuid::new_v4().into(),
                        claim_schema.key,
                        claim_schema.datatype,
                        claim_schema.required,
                        claim_schema.array,
                    )
                })
                .collect(),
        ),
        layout_type: request.layout_type,
        layout_properties: request.layout_properties.map(Into::into),
        schema_type: schema_type.into(),
        imported_source_url: url,
        schema_id,
        organisation: Some(organisation),
        allow_suspension: false,
    })
}

pub(crate) fn unnest_claim_schemas(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    unnest_claim_schemas_inner(claim_schemas, "".to_string())
}

fn unnest_claim_schemas_inner(
    claim_schemas: Vec<CredentialClaimSchemaRequestDTO>,
    prefix: String,
) -> Vec<CredentialClaimSchemaRequestDTO> {
    let mut result = vec![];

    for claim_schema in claim_schemas {
        let key = format!("{prefix}{}", claim_schema.key);

        let nested =
            unnest_claim_schemas_inner(claim_schema.claims, format!("{key}{NESTED_CLAIM_MARKER}"));

        result.push(CredentialClaimSchemaRequestDTO {
            key,
            claims: vec![],
            ..claim_schema
        });

        result.extend(nested);
    }

    result
}

pub fn create_format_map(
    format_type: &str,
) -> Result<
    HashMap<String, OpenID4VPPresentationDefinitionInputDescriptorFormat>,
    ExchangeProtocolError,
> {
    match format_type {
        "JWT" | "SD_JWT" | "MDOC" | "SD_JWT_VC" => {
            let key = map_core_to_oidc_format(format_type)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
            Ok(HashMap::from([(
                key,
                OpenID4VPPresentationDefinitionInputDescriptorFormat {
                    alg: vec!["EdDSA".to_string(), "ES256".to_string()],
                    proof_type: vec![],
                },
            )]))
        }
        "PHYSICAL_CARD" => {
            unimplemented!()
        }
        "JSON_LD_CLASSIC" | "JSON_LD_BBSPLUS" => Ok(HashMap::from([(
            "ldp_vc".to_string(),
            OpenID4VPPresentationDefinitionInputDescriptorFormat {
                alg: vec![],
                proof_type: vec!["DataIntegrityProof".to_string()],
            },
        )])),
        _ => unimplemented!(),
    }
}

pub fn map_offered_claims_to_credential_schema(
    credential_schema: &CredentialSchema,
    credential_id: CredentialId,
    claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "Missing claim schemas for existing credential schema".to_string(),
            ))?;

    let now = OffsetDateTime::now_utc();

    let nested_schema_claim_view: CredentialSchemaClaimsNestedView = claim_schemas
        .clone()
        .try_into()
        .map_err(|err: ServiceError| ExchangeProtocolError::Other(err.into()))?;

    let nested_claim_view: ClaimsNestedView = claim_keys.clone().try_into()?;

    validate_and_collect_claims(
        credential_id,
        now,
        &nested_schema_claim_view,
        &nested_claim_view,
    )
}

fn validate_and_collect_claims(
    credential_id: CredentialId,
    now: OffsetDateTime,
    nested_schema_claim_view: &CredentialSchemaClaimsNestedView,
    nested_claim_view: &ClaimsNestedView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    nested_schema_claim_view
        .fields
        .iter()
        .try_fold(vec![], |claims, (key, field)| {
            let nested_claim = nested_claim_view.claims.get(key);
            visit_nested_claim(credential_id, now, claims, field, nested_claim)
        })
}

fn visit_nested_field_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    claim: &CredentialSchemaClaim,
    nested_claim_view: &ClaimsNestedFieldView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    match nested_claim_view {
        ClaimsNestedFieldView::Leaf { key, value } => Ok(vec![Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: value.value.clone(),
            path: key.clone(),
            schema: Some(claim.schema.clone()),
        }]),
        ClaimsNestedFieldView::Nodes(_) => Err(ExchangeProtocolError::Failed(format!(
            "Validation Error. Claim key {} has wrong type",
            claim.schema.key,
        ))),
    }
}

fn visit_nested_object_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    object: &CredentialSchemaClaimsNestedObjectView,
    nested_claim_view: &ClaimsNestedFieldView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(ExchangeProtocolError::Failed(format!(
                "Validation Error. Claim key {} has wrong type",
                object.claim.schema.key,
            )))
        }
        ClaimsNestedFieldView::Nodes(claims) => claims,
    };

    object
        .fields
        .iter()
        .try_fold(vec![], |claims, (key, field)| {
            let claim = claims_view.get(key);
            visit_nested_claim(credential_id, now, claims, field, claim)
        })
}

fn visit_nested_claim(
    credential_id: CredentialId,
    now: OffsetDateTime,
    claims: Vec<Claim>,
    field: &Arrayed<CredentialSchemaClaimsNestedTypeView>,
    claim: Option<&ClaimsNestedFieldView>,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    match claim {
        Some(nested_claim) => {
            let nested_claims = match field {
                Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Field(claim)) => {
                    visit_nested_field_field(credential_id, now, claim, nested_claim)
                }
                Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Object(object)) => {
                    visit_nested_object_field(credential_id, now, object, nested_claim)
                }
                Arrayed::InArray(array) => {
                    visit_nested_array_field(credential_id, now, array, nested_claim)
                }
            }?;
            Ok([claims, nested_claims].concat())
        }
        None if field.required() => Err(ExchangeProtocolError::Failed(format!(
            "Validation Error. Claim key {} missing",
            field.key(),
        ))),
        None => Ok(claims),
    }
}

fn visit_nested_array_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    array: &CredentialSchemaClaimsNestedTypeView,
    nested_claim_view: &ClaimsNestedFieldView,
) -> Result<Vec<Claim>, ExchangeProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(ExchangeProtocolError::Failed(format!(
                "Validation Error. Claim key {} has wrong type",
                array.key(),
            )))
        }
        ClaimsNestedFieldView::Nodes(claims) => claims,
    };

    if claims_view.is_empty() && array.required() {
        return Err(ExchangeProtocolError::Failed(format!(
            "Validation Error. Required array claim key {} has no elements",
            array.key(),
        )));
    }

    (0..claims_view.len()).try_fold(vec![], |claims, index| {
        let claim = claims_view
            .get(&index.to_string())
            .ok_or(ExchangeProtocolError::Failed(format!(
                "Validation Error. Index {index} is missing for claim key {}",
                array.key(),
            )))?;

        let nested_claims = match array {
            CredentialSchemaClaimsNestedTypeView::Field(field) => {
                visit_nested_field_field(credential_id, now, field, claim)
            }
            CredentialSchemaClaimsNestedTypeView::Object(object) => {
                visit_nested_object_field(credential_id, now, object, claim)
            }
        }?;
        Ok([claims, nested_claims].concat())
    })
}

#[derive(Debug)]
struct ClaimsNestedView {
    claims: IndexMap<String, ClaimsNestedFieldView>,
}

#[derive(Debug)]
enum ClaimsNestedFieldView {
    Leaf {
        key: String,
        value: OpenID4VCICredentialValueDetails,
    },
    Nodes(IndexMap<String, ClaimsNestedFieldView>),
}

impl TryFrom<IndexMap<String, OpenID4VCICredentialValueDetails>> for ClaimsNestedView {
    type Error = ExchangeProtocolError;

    fn try_from(
        value: IndexMap<String, OpenID4VCICredentialValueDetails>,
    ) -> Result<Self, Self::Error> {
        let mut claims = IndexMap::<String, ClaimsNestedFieldView>::new();

        for (key, value) in value {
            match key.rsplit_once(NESTED_CLAIM_MARKER) {
                Some((head, tail)) => {
                    let parent = get_or_insert_view(&mut claims, head)?;
                    let ClaimsNestedFieldView::Nodes(nodes) = parent else {
                        return Err(ExchangeProtocolError::Failed(
                            "Parent claim should be nested".into(),
                        ));
                    };

                    nodes.insert(tail.to_owned(), ClaimsNestedFieldView::Leaf { key, value });
                }
                None => {
                    claims.insert(key.clone(), ClaimsNestedFieldView::Leaf { key, value });
                }
            }
        }

        Ok(ClaimsNestedView { claims })
    }
}

fn get_or_insert_view<'a>(
    root: &'a mut IndexMap<String, ClaimsNestedFieldView>,
    path: &str,
) -> Result<&'a mut ClaimsNestedFieldView, ExchangeProtocolError> {
    match path.split_once(NESTED_CLAIM_MARKER) {
        Some((head, tail)) => {
            let value = root
                .entry(head.to_owned())
                .or_insert_with(|| ClaimsNestedFieldView::Nodes(Default::default()));

            let ClaimsNestedFieldView::Nodes(nodes) = value else {
                return Err(ExchangeProtocolError::Failed(
                    "Parent claim should be nested".into(),
                ));
            };

            get_or_insert_view(nodes, tail)
        }
        None => Ok(root
            .entry(path.to_owned())
            .or_insert_with(|| ClaimsNestedFieldView::Nodes(Default::default()))),
    }
}

pub fn create_credential(
    credential_id: CredentialId,
    credential_schema: CredentialSchema,
    claims: Vec<Claim>,
    interaction: Interaction,
    redirect_uri: Option<String>,
    issuer_did: Option<Did>,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        exchange: "OPENID4VC".to_string(),
        redirect_uri,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        claims: Some(claims),
        issuer_did,
        holder_did: None,
        schema: Some(credential_schema),
        key: None,
        interaction: Some(interaction),
        revocation_list: None,
    }
}

pub(crate) fn get_credential_offer_url(
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

fn get_url(base_url: Option<String>) -> Result<String, ExchangeProtocolError> {
    base_url.ok_or(ExchangeProtocolError::Failed("Missing base_url".to_owned()))
}

pub fn create_open_id_for_vp_presentation_definition(
    interaction_id: InteractionId,
    proof: &Proof,
    format_type_to_input_descriptor_format: TypeToDescriptorMapper,
    format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
    formatter_provider: &dyn CredentialFormatterProvider,
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
                let format_type = format_to_type_mapper(&credential_schema.format)?;
                create_open_id_for_vp_presentation_definition_input_descriptor(
                    index,
                    credential_schema,
                    claim_schemas.unwrap_or_default(),
                    &format_type,
                    format_type_to_input_descriptor_format.clone(),
                    formatter_provider,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

pub fn create_open_id_for_vp_presentation_definition_input_descriptor(
    index: usize,
    credential_schema: CredentialSchema,
    claim_schemas: Vec<ProofInputClaimSchema>,
    presentation_format_type: &str,
    format_to_type_mapper: TypeToDescriptorMapper,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<OpenID4VPPresentationDefinitionInputDescriptor, ExchangeProtocolError> {
    let schema_id_field = OpenID4VPPresentationDefinitionConstraintField {
        id: None,
        name: None,
        purpose: None,
        path: vec!["$.credentialSchema.id".to_string()],
        optional: None,
        filter: Some(OpenID4VPPresentationDefinitionConstraintFieldFilter {
            r#type: "string".to_string(),
            r#const: credential_schema.schema_id.clone(),
        }),
        intent_to_retain: None,
    };

    let (id, intent_to_retain) = match presentation_format_type {
        "MDOC" => (credential_schema.schema_id, Some(true)),
        _ => (format!("input_{index}"), None),
    };

    let selectively_disclosable = !formatter_provider
        .get_formatter(&credential_schema.format)
        .ok_or(ExchangeProtocolError::Failed(
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

    let constraint_fields = claim_schemas
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

    let mut fields = vec![schema_id_field];
    fields.extend(constraint_fields);

    Ok(OpenID4VPPresentationDefinitionInputDescriptor {
        id,
        name: Some(credential_schema.name),
        purpose: None,
        format: format_to_type_mapper(presentation_format_type)?,
        constraints: OpenID4VPPresentationDefinitionConstraint {
            fields,
            validity_credential_nbf: None,
            limit_disclosure,
        },
    })
}

fn format_path(claim_key: &str, format_type: &str) -> Result<String, ExchangeProtocolError> {
    match format_type {
        "MDOC" => match claim_key.split_once(NESTED_CLAIM_MARKER) {
            None => Ok(format!("$['{claim_key}']")),
            Some((namespace, key)) => Ok(format!("$['{namespace}']['{key}']")),
        },
        _ => Ok(format!("$.vc.credentialSubject.{}", claim_key)),
    }
}

pub fn create_presentation_submission(
    presentation_definition_id: Uuid,
    credential_presentations: Vec<PresentedCredential>,
    format: &str,
    format_map: HashMap<String, String>,
) -> Result<PresentationSubmissionMappingDTO, ExchangeProtocolError> {
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
                        format: format_map
                            .get(&presented_credential.credential_schema.format)
                            .ok_or_else(|| {
                                ExchangeProtocolError::Failed("format not found".to_string())
                            })?
                            .to_owned(),
                        path: format!("$.vp.verifiableCredential[{index}]"),
                    }),
                })
            })
            .collect::<Result<_, _>>()?,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_open_id_for_vp_sharing_url_encoded(
    base_url: &str,
    openidvc_params: &OpenID4VCParams,
    client_id: String,
    interaction_id: InteractionId,
    interaction_data: &OpenID4VPVerifierInteractionContent,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VPFormat>,
    client_id_scheme: ClientIdSchemaType,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, ExchangeProtocolError> {
    let params = if openidvc_params.use_request_uri {
        get_params_with_request_uri(base_url, proof.id, client_id, client_id_scheme)
    } else {
        match client_id_scheme {
            ClientIdSchemaType::RedirectUri => get_params_for_redirect_uri(
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
            ClientIdSchemaType::X509SanDns => {
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
            ClientIdSchemaType::VerifierAttestation => {
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
            ClientIdSchemaType::Did => {
                return Err(ExchangeProtocolError::InvalidRequest(
                    "client_id_scheme type 'did' not supported in this context".to_string(),
                ))
            }
        }
    };

    let encoded_params = serde_urlencoded::to_string(params)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    Ok(encoded_params)
}

fn get_params_with_request_uri(
    base_url: &str,
    proof_id: ProofId,
    client_id: String,
    client_id_scheme: ClientIdSchemaType,
) -> OpenID4VPAuthorizationRequestQueryParams {
    OpenID4VPAuthorizationRequestQueryParams {
        client_id,
        request_uri: Some(format!(
            "{base_url}/ssi/oidc-verifier/v1/{}/client-request",
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
    client_id_scheme: ClientIdSchemaType,
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
    openidvc_params: &OpenID4VCParams,
    client_id: String,
    interaction_id: InteractionId,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VPFormat>,
    interaction_data: &OpenID4VPVerifierInteractionContent,
) -> Result<OpenID4VPAuthorizationRequestQueryParams, ExchangeProtocolError> {
    let mut presentation_definition = None;
    let mut presentation_definition_uri = None;
    if openidvc_params.presentation_definition_by_value {
        let pd = serde_json::to_string(&interaction_data.presentation_definition)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        presentation_definition = Some(pd);
    } else {
        presentation_definition_uri = Some(format!(
            "{base_url}/ssi/oidc-verifier/v1/{}/presentation-definition",
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
            ClientIdSchemaType::RedirectUri,
        ))
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        client_metadata = Some(metadata);
    } else {
        client_metadata_uri = Some(format!(
            "{base_url}/ssi/oidc-verifier/v1/{}/client-metadata",
            proof.id
        ));
    }

    Ok(OpenID4VPAuthorizationRequestQueryParams {
        client_id: client_id.to_string(),
        client_id_scheme: Some(ClientIdSchemaType::RedirectUri),
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
    type Error = ExchangeProtocolError;

    fn try_from(value: OpenID4VPAuthorizationRequestQueryParams) -> Result<Self, Self::Error> {
        let url_parse = |uri: String| {
            Url::parse(&uri).map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))
        };

        fn json_parse<T: for<'a> Deserialize<'a>>(
            input: String,
        ) -> Result<T, ExchangeProtocolError> {
            serde_json::from_str(&input)
                .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))
        }

        Ok(Self {
            client_id: value.client_id,
            client_id_scheme: value
                .client_id_scheme
                .unwrap_or(ClientIdSchemaType::RedirectUri),
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
                .unwrap_or(ClientIdSchemaType::RedirectUri),
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

impl TryFrom<OpenID4VCIInteractionDataDTO> for OpenID4VCITokenResponseDTO {
    type Error = OpenID4VCIError;
    fn try_from(value: OpenID4VCIInteractionDataDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            access_token: value.access_token.to_string(),
            token_type: "bearer".to_string(),
            expires_in: Timestamp(
                value
                    .access_token_expires_at
                    .ok_or(OpenID4VCIError::RuntimeError(
                        "access_token_expires_at missing".to_string(),
                    ))?
                    .unix_timestamp(),
            ),
            refresh_token: value.refresh_token,
            refresh_token_expires_in: value
                .refresh_token_expires_at
                .map(|dt| Timestamp(dt.unix_timestamp())),
        })
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
            exchange: "OPENID4VC".to_string(),
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

impl TryFrom<CredentialSchema> for DetailCredentialSchemaResponseDTO {
    type Error = ExchangeProtocolError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let organisation_id = match value.organisation {
            None => Err(ExchangeProtocolError::Failed(
                "Organisation has not been fetched".to_string(),
            )),
            Some(value) => Ok(value.id),
        }?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            deleted_at: value.deleted_at,
            last_modified: value.last_modified,
            imported_source_url: value.imported_source_url,
            name: value.name,
            format: value.format,
            revocation_method: value.revocation_method,
            wallet_storage_type: value.wallet_storage_type,
            organisation_id,
            schema_type: value.schema_type.into(),
            schema_id: value.schema_id,
            layout_type: value.layout_type.into(),
            layout_properties: value.layout_properties.map(Into::into),
            allow_suspension: value.allow_suspension,
        })
    }
}

impl From<CredentialSchemaClaim> for CredentialClaimSchemaDTO {
    fn from(value: CredentialSchemaClaim) -> Self {
        Self {
            id: value.schema.id,
            created_date: value.schema.created_date,
            last_modified: value.schema.last_modified,
            key: value.schema.key,
            datatype: value.schema.data_type,
            required: value.required,
            array: value.schema.array,
            claims: vec![],
        }
    }
}

pub(super) fn credentials_supported_mdoc(
    schema: CredentialSchema,
    config: &CoreConfig,
) -> Result<OpenID4VCICredentialConfigurationData, ExchangeProtocolError> {
    let claim_schemas: &Vec<CredentialSchemaClaim> =
        schema
            .claim_schemas
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "claim_schemas is None".to_string(),
            ))?;

    // order of namespaces and elements inside MDOC schema as defined in OpenID4VCI mdoc spec: `{namespace}~{element}`
    let element_order: Vec<String> = claim_schemas
        .iter()
        .filter(|claim| {
            claim
                .schema
                .key
                .chars()
                .filter(|c| *c == NESTED_CLAIM_MARKER)
                .count()
                == 1
        })
        .map(|element| element.schema.key.replace(NESTED_CLAIM_MARKER, "~"))
        .collect();

    let claim_schema = prepare_nested_representation(&schema, config)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let credential_configuration = OpenID4VCICredentialConfigurationData {
        wallet_storage_type: schema.wallet_storage_type.map(Into::into),
        format: map_core_to_oidc_format(&schema.format)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
        // We only take objects from the initial structure as arrays are not allowed on the first level
        claims: claim_schema.claims,
        order: if element_order.len() > 1 {
            Some(element_order)
        } else {
            None
        },
        credential_definition: None,
        doctype: Some(schema.schema_id),
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema.name },
        ]),
        ..Default::default()
    };

    Ok(credential_configuration)
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
                jwt_id: None,
                custom: self,
                proof_of_possession_key: None,
                vc_type: None,
            },
        };
        Ok(unsigned_jwt.tokenize(Some(auth_fn)).await?)
    }
}
