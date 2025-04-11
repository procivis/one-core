use indexmap::map::Entry;
use indexmap::IndexMap;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::Hasher;
use secrecy::ExposeSecret;
use shared_types::{ClaimSchemaId, CredentialId, CredentialSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::error::OpenID4VCIError;
use super::model::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesRequestDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaLayoutPropertiesRequestDTO,
    CredentialSchemaLogoPropertiesRequestDTO, DidListItemResponseDTO,
    OpenID4VCICredentialConfigurationData, OpenID4VCICredentialSubjectItem,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO,
    OpenID4VCIProofTypeSupported, OpenID4VCITokenResponseDTO,
};
use crate::common_mapper::NESTED_CLAIM_MARKER;
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
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::provider::http_client;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, OpenID4VCICredentialValueDetails,
};
use crate::provider::issuance_protocol::openid4vci_draft13::IssuanceProtocolError;
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::ServiceError;
use crate::util::oidc::map_to_openid4vp_format;

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
) -> Result<(Vec<CredentialSchemaClaim>, Vec<Claim>), IssuanceProtocolError> {
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

pub(crate) fn from_create_request(
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    schema_type: String,
) -> Result<CredentialSchema, IssuanceProtocolError> {
    from_create_request_with_id(
        Uuid::new_v4().into(),
        request,
        organisation,
        core_base_url,
        schema_type,
    )
}

fn from_create_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    core_base_url: &str,
    schema_type: String,
) -> Result<CredentialSchema, IssuanceProtocolError> {
    if request.claims.is_empty() {
        return Err(IssuanceProtocolError::Failed(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

    let url = format!("{core_base_url}/ssi/schema/v1/{id}");
    let schema_id = request.schema_id.unwrap_or(url.clone());

    Ok(CredentialSchema {
        id,
        deleted_at: None,
        created_date: now,
        last_modified: now,
        name: request.name,
        format: request.format,
        wallet_storage_type: request.wallet_storage_type,
        revocation_method: request.revocation_method,
        external_schema: request.external_schema,
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

pub(crate) fn map_offered_claims_to_credential_schema(
    credential_schema: &CredentialSchema,
    credential_id: CredentialId,
    claim_keys: &IndexMap<String, OpenID4VCICredentialValueDetails>,
) -> Result<Vec<Claim>, IssuanceProtocolError> {
    let claim_schemas =
        credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "Missing claim schemas for existing credential schema".to_string(),
            ))?;

    let now = OffsetDateTime::now_utc();

    let nested_schema_claim_view: CredentialSchemaClaimsNestedView = claim_schemas
        .clone()
        .try_into()
        .map_err(|err: ServiceError| IssuanceProtocolError::Other(err.into()))?;

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
) -> Result<Vec<Claim>, IssuanceProtocolError> {
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
) -> Result<Vec<Claim>, IssuanceProtocolError> {
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
        ClaimsNestedFieldView::Nodes(_) => Err(IssuanceProtocolError::Failed(format!(
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
) -> Result<Vec<Claim>, IssuanceProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(IssuanceProtocolError::Failed(format!(
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
) -> Result<Vec<Claim>, IssuanceProtocolError> {
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
        None if field.required() => Err(IssuanceProtocolError::Failed(format!(
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
) -> Result<Vec<Claim>, IssuanceProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(IssuanceProtocolError::Failed(format!(
                "Validation Error. Claim key {} has wrong type",
                array.key(),
            )))
        }
        ClaimsNestedFieldView::Nodes(claims) => claims,
    };

    if claims_view.is_empty() && array.required() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Validation Error. Required array claim key {} has no elements",
            array.key(),
        )));
    }

    (0..claims_view.len()).try_fold(vec![], |claims, index| {
        let claim = claims_view
            .get(&index.to_string())
            .ok_or(IssuanceProtocolError::Failed(format!(
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
    type Error = IssuanceProtocolError;

    fn try_from(
        value: IndexMap<String, OpenID4VCICredentialValueDetails>,
    ) -> Result<Self, Self::Error> {
        let mut claims = IndexMap::<String, ClaimsNestedFieldView>::new();

        for (key, value) in value {
            match key.rsplit_once(NESTED_CLAIM_MARKER) {
                Some((head, tail)) => {
                    let parent = get_or_insert_view(&mut claims, head)?;
                    let ClaimsNestedFieldView::Nodes(nodes) = parent else {
                        return Err(IssuanceProtocolError::Failed(
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
) -> Result<&'a mut ClaimsNestedFieldView, IssuanceProtocolError> {
    match path.split_once(NESTED_CLAIM_MARKER) {
        Some((head, tail)) => {
            let value = root
                .entry(head.to_owned())
                .or_insert_with(|| ClaimsNestedFieldView::Nodes(Default::default()));

            let ClaimsNestedFieldView::Nodes(nodes) = value else {
                return Err(IssuanceProtocolError::Failed(
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

pub(crate) fn create_credential(
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
        exchange: "OPENID4VCI_DRAFT13".to_string(), // this will be rewritten later in SSIHolderService
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
) -> Result<String, IssuanceProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;
    let base_url = get_url(base_url)?;
    Ok(format!(
        "{base_url}/ssi/openid4vci/draft-13/{}/offer/{}",
        credential_schema.id, credential.id
    ))
}

fn get_url(base_url: Option<String>) -> Result<String, IssuanceProtocolError> {
    base_url.ok_or(IssuanceProtocolError::Failed("Missing base_url".to_owned()))
}

impl TryFrom<&OpenID4VCITokenResponseDTO> for OpenID4VCIIssuerInteractionDataDTO {
    type Error = OpenID4VCIError;
    fn try_from(value: &OpenID4VCITokenResponseDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            pre_authorized_code_used: true,
            access_token_hash: SHA256
                .hash(value.access_token.expose_secret().as_bytes())
                .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
            access_token_expires_at: Some(
                OffsetDateTime::from_unix_timestamp(value.expires_in.0)
                    .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))?,
            ),
            refresh_token_hash: value
                .refresh_token
                .as_ref()
                .map(|refresh_token| {
                    SHA256
                        .hash(refresh_token.expose_secret().as_bytes())
                        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))
                })
                .transpose()?,
            refresh_token_expires_at: value
                .refresh_token_expires_in
                .as_ref()
                .map(|refresh_token_expires_in| {
                    OffsetDateTime::from_unix_timestamp(refresh_token_expires_in.0)
                        .map_err(|e| OpenID4VCIError::RuntimeError(e.to_string()))
                })
                .transpose()?,
            nonce: value.c_nonce.clone(),
        })
    }
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
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
) -> Result<OpenID4VCICredentialConfigurationData, IssuanceProtocolError> {
    let claim_schemas: &Vec<CredentialSchemaClaim> =
        schema
            .claim_schemas
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
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
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

    let format_type = config
        .format
        .get_fields(&schema.format)
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
        .r#type;

    let credential_configuration = OpenID4VCICredentialConfigurationData {
        wallet_storage_type: schema.wallet_storage_type,
        format: map_to_openid4vp_format(&format_type)
            .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?
            .to_string(),
        // We only take objects from the initial structure as arrays are not allowed on the first level
        claims: claim_schema.claims,
        order: if element_order.len() > 1 {
            Some(element_order)
        } else {
            None
        },
        doctype: Some(schema.schema_id),
        display: Some(vec![
            OpenID4VCIIssuerMetadataCredentialSupportedDisplayDTO { name: schema.name },
        ]),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        proof_types_supported,
        ..Default::default()
    };

    Ok(credential_configuration)
}

pub(crate) fn map_proof_types_supported(
    supported_jose_alg_ids: Vec<String>,
) -> IndexMap<String, OpenID4VCIProofTypeSupported> {
    IndexMap::from([(
        "jwt".to_string(),
        OpenID4VCIProofTypeSupported {
            proof_signing_alg_values_supported: supported_jose_alg_ids,
        },
    )])
}

pub(crate) fn map_cryptographic_binding_methods_supported(
    supported_did_methods: &[String],
) -> Vec<String> {
    let mut binding_methods: Vec<_> = supported_did_methods
        .iter()
        .map(|did_method| format!("did:{}", did_method))
        .collect();
    binding_methods.push("jwk".to_string());
    binding_methods
}
