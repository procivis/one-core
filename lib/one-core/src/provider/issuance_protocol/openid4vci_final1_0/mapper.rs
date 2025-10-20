use indexmap::IndexMap;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use secrecy::ExposeSecret;
use shared_types::{CredentialId, CredentialSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::model::{
    CredentialSchemaBackgroundPropertiesRequestDTO, CredentialSchemaCodePropertiesRequestDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaLayoutPropertiesRequestDTO,
    CredentialSchemaLogoPropertiesRequestDTO, OpenID4VCICredentialConfigurationData,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCITokenResponseDTO,
};
use crate::config::core_config::{CoreConfig, Params};
use crate::config::{ConfigError, ConfigParsingError};
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::credential_schema_claim::from_jwt_request_claim_schema;
use crate::mapper::oidc::map_to_openid4vp_format;
use crate::model::certificate::Certificate;
use crate::model::claim::Claim;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::{
    Arrayed, BackgroundProperties, CodeProperties, CodeTypeEnum, CredentialSchema,
    CredentialSchemaClaim, CredentialSchemaClaimsNestedObjectView,
    CredentialSchemaClaimsNestedTypeView, CredentialSchemaClaimsNestedView, LayoutProperties,
    LogoProperties,
};
use crate::model::identifier::Identifier;
use crate::model::interaction::Interaction;
use crate::model::organisation::Organisation;
use crate::provider::http_client;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::error::{IssuanceProtocolError, OpenID4VCIError};
use crate::provider::issuance_protocol::model::OpenID4VCIProofTypeSupported;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaRequestDTO, CredentialIssuerParams,
    CredentialSchemaDetailResponseDTO, ExtendedSubjectClaimsDTO, ExtendedSubjectDTO,
    OpenID4VCICredentialMetadataClaimResponseDTO, OpenID4VCICredentialMetadataResponseDTO,
    OpenID4VCICredentialValueDetails,
};
use crate::service::credential_schema::dto::CredentialClaimSchemaDTO;
use crate::service::error::ServiceError;

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
    schema_type: String,
) -> Result<CredentialSchema, IssuanceProtocolError> {
    from_create_request_with_id(Uuid::new_v4().into(), request, organisation, schema_type)
}

fn from_create_request_with_id(
    id: CredentialSchemaId,
    request: CreateCredentialSchemaRequestDTO,
    organisation: Organisation,
    schema_type: String,
) -> Result<CredentialSchema, IssuanceProtocolError> {
    if request.claims.is_empty() {
        return Err(IssuanceProtocolError::Failed(
            "Claim schemas cannot be empty".to_string(),
        ));
    }

    let now = OffsetDateTime::now_utc();

    let claim_schemas = unnest_claim_schemas(request.claims);

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
        imported_source_url: request.imported_source_url,
        schema_id: request.schema_id,
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

pub(crate) fn extract_offered_claims(
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
            visit_nested_claim(credential_id, now, claims, field, nested_claim, "")
        })
}

fn visit_nested_field_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    claim: &CredentialSchemaClaim,
    nested_claim_view: &ClaimsNestedFieldView,
) -> Result<Vec<Claim>, IssuanceProtocolError> {
    match nested_claim_view {
        ClaimsNestedFieldView::Leaf { key, value } => {
            let mut res = vec![];
            if let Some(value) = value.value.to_owned() {
                res.push(Claim {
                    id: Uuid::new_v4(),
                    credential_id,
                    created_date: now,
                    last_modified: now,
                    value: Some(value),
                    path: key.clone(),
                    selectively_disclosable: false,
                    schema: Some(claim.schema.clone()),
                });
            }
            Ok(res)
        }
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
    path_to_root: &str,
) -> Result<Vec<Claim>, IssuanceProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(IssuanceProtocolError::Failed(format!(
                "Validation Error. Claim key {} has wrong type",
                object.claim.schema.key,
            )));
        }
        ClaimsNestedFieldView::Nodes(claims) => claims,
    };
    let path_container_to_root = if path_to_root.is_empty() {
        object.claim.schema.key.clone()
    } else {
        path_to_root.to_string()
    };
    let mut child_claims = object
        .fields
        .iter()
        .try_fold(vec![], |claims, (key, field)| {
            let claim = claims_view.get(key);
            let path_property_to_root = format!("{path_container_to_root}/{key}");
            visit_nested_claim(
                credential_id,
                now,
                claims,
                field,
                claim,
                &path_property_to_root,
            )
        })?;

    if !child_claims.is_empty() {
        // Object not empty -> insert object container claim
        child_claims.push(Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: None,
            path: path_container_to_root,
            selectively_disclosable: false,
            schema: Some(object.claim.schema.clone()),
        })
    }

    Ok(child_claims)
}

fn visit_nested_claim(
    credential_id: CredentialId,
    now: OffsetDateTime,
    claims: Vec<Claim>,
    field: &Arrayed<CredentialSchemaClaimsNestedTypeView>,
    claim: Option<&ClaimsNestedFieldView>,
    path_to_root: &str,
) -> Result<Vec<Claim>, IssuanceProtocolError> {
    match claim {
        Some(nested_claim) => {
            let nested_claims = match field {
                Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Field(claim)) => {
                    visit_nested_field_field(credential_id, now, claim, nested_claim)
                }
                Arrayed::Single(CredentialSchemaClaimsNestedTypeView::Object(object)) => {
                    visit_nested_object_field(
                        credential_id,
                        now,
                        object,
                        nested_claim,
                        path_to_root,
                    )
                }
                Arrayed::InArray(array) => {
                    visit_nested_array_field(credential_id, now, array, nested_claim, path_to_root)
                }
            }?;
            Ok([claims, nested_claims].concat())
        }
        // TODO ONE-7022: Remove exemption for metadata claims once credential formatters extract them.
        None if field.required() && !field.metadata() => Err(IssuanceProtocolError::Failed(
            format!("Validation Error. Claim key {} missing", field.key(),),
        )),
        None => Ok(claims),
    }
}

fn visit_nested_array_field(
    credential_id: CredentialId,
    now: OffsetDateTime,
    array: &CredentialSchemaClaimsNestedTypeView,
    nested_claim_view: &ClaimsNestedFieldView,
    path_to_root: &str,
) -> Result<Vec<Claim>, IssuanceProtocolError> {
    let claims_view = match nested_claim_view {
        ClaimsNestedFieldView::Leaf { .. } => {
            return Err(IssuanceProtocolError::Failed(format!(
                "Validation Error. Claim key {} has wrong type",
                array.key(),
            )));
        }
        ClaimsNestedFieldView::Nodes(claims) => claims,
    };

    if claims_view.is_empty() && array.required() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Validation Error. Required array claim key {} has no elements",
            array.key(),
        )));
    }

    let array_schema = match array {
        CredentialSchemaClaimsNestedTypeView::Field(field) => field.schema.clone(),
        CredentialSchemaClaimsNestedTypeView::Object(obj) => obj.claim.schema.clone(),
    };
    let path_container_to_root = if path_to_root.is_empty() {
        array_schema.key.clone()
    } else {
        path_to_root.to_string()
    };
    let mut child_claims = (0..claims_view.len()).try_fold(vec![], |claims, index| {
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
                let path_element_to_root = format!("{path_container_to_root}/{index}");
                visit_nested_object_field(credential_id, now, object, claim, &path_element_to_root)
            }
        }?;
        Ok([claims, nested_claims].concat())
    })?;

    if !child_claims.is_empty() {
        // Array not empty -> insert array container claim
        child_claims.push(Claim {
            id: Uuid::new_v4(),
            credential_id,
            created_date: now,
            last_modified: now,
            value: None,
            path: path_container_to_root,
            selectively_disclosable: false,
            schema: Some(array_schema),
        });
    }

    Ok(child_claims)
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
    issuer_identifier: Option<Identifier>,
    issuer_certificate: Option<Certificate>,
) -> Credential {
    let now = OffsetDateTime::now_utc();

    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: None,
        last_modified: now,
        deleted_at: None,
        protocol: "OPENID4VCI_FINAL1".to_string(), // this will be rewritten later in SSIHolderService
        redirect_uri,
        role: CredentialRole::Holder,
        state: CredentialStateEnum::Pending,
        suspend_end_date: None,
        profile: None,
        claims: Some(claims),
        issuer_identifier,
        issuer_certificate,
        holder_identifier: None,
        schema: Some(credential_schema),
        key: None,
        interaction: Some(interaction),
        revocation_list: None,
        credential_blob_id: None,
        wallet_unit_attestation_blob_id: None,
    }
}

pub(crate) fn get_credential_offer_url(
    protocol_base_url: String,
    credential: &Credential,
) -> Result<String, IssuanceProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;
    Ok(format!(
        "{protocol_base_url}/{}/offer/{}",
        credential_schema.id, credential.id
    ))
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
            notification_id: None,
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

pub(super) fn credentials_supported_mdoc(
    schema: CredentialSchema,
    credential_metadata: OpenID4VCICredentialMetadataResponseDTO,
    config: &CoreConfig,
    cryptographic_binding_methods_supported: Vec<String>,
    proof_types_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
) -> Result<OpenID4VCICredentialConfigurationData, IssuanceProtocolError> {
    let format_type = config
        .format
        .get_fields(&schema.format)
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
        .r#type;

    let credential_configuration = OpenID4VCICredentialConfigurationData {
        format: map_to_openid4vp_format(&format_type)
            .map_err(|error| IssuanceProtocolError::Failed(error.to_string()))?
            .to_string(),
        doctype: Some(schema.schema_id.clone()),
        credential_metadata: Some(credential_metadata),
        procivis_schema: Some(schema.imported_source_url.clone()),
        cryptographic_binding_methods_supported: Some(cryptographic_binding_methods_supported),
        proof_types_supported,
        scope: Some(schema.schema_id),
        ..Default::default()
    };

    Ok(credential_configuration)
}

pub(crate) fn map_proof_types_supported<R: From<[(String, OpenID4VCIProofTypeSupported); 1]>>(
    supported_jose_alg_ids: Vec<String>,
) -> R {
    R::from([(
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
        .map(|did_method| format!("did:{did_method}"))
        .collect();
    binding_methods.push("jwk".to_string());
    binding_methods
}

pub(crate) fn parse_credential_issuer_params(
    config_params: &Option<Params>,
) -> Result<CredentialIssuerParams, ConfigError> {
    config_params
        .as_ref()
        .and_then(|p| p.merge())
        .map(serde_json::from_value)
        .ok_or(ConfigError::Parsing(
            ConfigParsingError::GeneralParsingError("Credential issuer params missing".to_string()),
        ))?
        .map_err(|e| ConfigError::Parsing(ConfigParsingError::GeneralParsingError(e.to_string())))
}

pub(crate) fn map_metadata_claims_to_extended_subject(
    credential_metadata_claims: Vec<OpenID4VCICredentialMetadataClaimResponseDTO>,
) -> Result<ExtendedSubjectDTO, IssuanceProtocolError> {
    let mut claims = IndexMap::new();

    for claim in credential_metadata_claims {
        let path = claim.path.join("/");

        // Create OpenID4VCICredentialValueDetails for each claim
        claims.insert(
            path,
            OpenID4VCICredentialValueDetails {
                value: None, // No value provided in metadata claims
            },
        );
    }

    Ok(ExtendedSubjectDTO {
        keys: if claims.is_empty() {
            None
        } else {
            Some(ExtendedSubjectClaimsDTO { claims })
        },
    })
}

pub(super) fn parse_procivis_schema_claim(
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
