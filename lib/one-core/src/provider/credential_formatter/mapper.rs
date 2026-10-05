use std::collections::{BTreeMap, HashMap};

use convert_case::{Case, Casing};
use indexmap::IndexMap;
use one_dto_mapper::{convert_inner, try_convert_inner};
use shared_types::{CredentialFormat, CredentialSchemaId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use uuid::fmt::Urn;

use super::mdoc_formatter::MdocCredential;
use super::model::{FormatterCapabilities, IssuedClaimValue, IssuedClaims, UnsignedCredential};
use super::sdjwtvc_formatter::model::SdJwtVcCredential;
use super::vcdm::{
    ContextType, CredentialSchemaMetadata, VcdmCredential, VcdmCredentialSchema,
    VcdmCredentialSubject,
};
use crate::config::core_config::{CoreConfig, DatatypeConfig, DatatypeType, FormatType};
use crate::error::ContextWithErrorCode;
use crate::mapper::credential_schema_claim::technical_claim_path;
use crate::model::certificate::Certificate;
use crate::model::claim_path::ClaimPathSegment;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialStatus, Issuer,
};
use crate::service::credential_schema::dto::CredentialSchemaLayoutPropertiesResponseDTO;

pub const W3C_SCHEMA_TYPE: &str = "ProcivisOneSchema2024";

pub(super) fn default_2_years() -> Duration {
    Duration::days(365 * 2)
}

impl FormatterCapabilities {
    /// adjusts capabilities to also match constraints set by another format
    pub(crate) fn combine_constraints(&mut self, other: &Self) {
        let Self {
            features,
            selective_disclosure,
            issuance_did_methods,
            issuance_exchange_protocols,
            proof_exchange_protocols,
            revocation_methods,
            signing_key_algorithms,
            verification_key_algorithms,
            verification_key_storages,
            datatypes,
            forbidden_claim_names,
            issuance_identifier_types,
            verification_identifier_types,
            holder_identifier_types,
            holder_key_algorithms,
            holder_did_methods,
        } = other;

        fn intersect<T: PartialEq>(s: &mut Vec<T>, o: &[T]) {
            s.retain(|x| o.contains(x));
        }

        intersect(&mut self.features, features);
        intersect(&mut self.selective_disclosure, selective_disclosure);
        intersect(&mut self.issuance_did_methods, issuance_did_methods);
        intersect(
            &mut self.issuance_exchange_protocols,
            issuance_exchange_protocols,
        );
        intersect(&mut self.proof_exchange_protocols, proof_exchange_protocols);
        intersect(&mut self.revocation_methods, revocation_methods);
        intersect(&mut self.signing_key_algorithms, signing_key_algorithms);
        intersect(
            &mut self.verification_key_algorithms,
            verification_key_algorithms,
        );
        intersect(
            &mut self.verification_key_storages,
            verification_key_storages,
        );
        intersect(&mut self.datatypes, datatypes);

        for name in forbidden_claim_names {
            if !self.forbidden_claim_names.contains(name) {
                self.forbidden_claim_names.push(name.to_owned());
            }
        }

        intersect(
            &mut self.issuance_identifier_types,
            issuance_identifier_types,
        );
        intersect(
            &mut self.verification_identifier_types,
            verification_identifier_types,
        );
        intersect(&mut self.holder_identifier_types, holder_identifier_types);
        intersect(&mut self.holder_key_algorithms, holder_key_algorithms);
        intersect(&mut self.holder_did_methods, holder_did_methods);
    }
}

pub(crate) async fn first_certificate(
    identifier: &Identifier,
) -> Result<Option<Certificate>, FormatterError> {
    match &identifier.data {
        IdentifierData::Certificate(certificates)
        | IdentifierData::CertificateAuthority(certificates) => {
            Ok(certificates.as_ref().await?.first().cloned())
        }
        _ => Ok(None),
    }
}

pub(crate) async fn unsigned_credential(
    credential: &Credential,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
    credential_schema: &CredentialSchema,
    credential_schema_format: &CredentialSchemaFormat,
    config: &CoreConfig,
) -> Result<UnsignedCredential, FormatterError> {
    let format_type = config
        .format
        .get_type(&credential_schema_format.format)
        .error_while("getting format type")?;
    let claims = credential_claims(credential, credential_schema_format, &config.datatype).await?;
    let ecosystem_schema_id = credential_schema_format.ecosystem_schema_id.clone();

    match format_type {
        FormatType::Mdoc => Ok(UnsignedCredential::Mdoc(MdocCredential {
            doctype: ecosystem_schema_id,
            valid_until: credential.common().expires_at,
            credential_status,
            claims,
        })),
        FormatType::SdJwtVc => Ok(UnsignedCredential::SdJwtVc(SdJwtVcCredential {
            vct: ecosystem_schema_id,
            issuer: issuer_url_for_credential(credential, core_base_url).await?,
            valid_until: credential.common().expires_at,
            credential_status,
            claims,
        })),
        FormatType::Jwt
        | FormatType::SdJwt
        | FormatType::JsonLdClassic
        | FormatType::JsonLdBbsPlus => {
            // We don't add the credentialSubject.id here for backwards compatibility with older JWT/SD-JWT formatters where they store the "id" in the "sub" claim.
            // For JSON-LD formats the "id" is added to the credentialSubject inside the formatter.
            let credential_subject =
                VcdmCredentialSubject::new(claims).error_while("creating subject")?;
            let issuer = Issuer::Url(issuer_url_for_credential(credential, core_base_url).await?);

            let layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO> =
                convert_inner(credential_schema.layout_properties.clone());
            let metadata = layout_properties.map(|layout_properties| CredentialSchemaMetadata {
                layout_properties: layout_properties.into(),
                // for backward compatibility
                layout_type: Some("CARD".to_string()),
            });
            let vcdm_schema = VcdmCredentialSchema {
                id: ecosystem_schema_id,
                r#type: W3C_SCHEMA_TYPE.to_string(),
                metadata,
            };
            let credential_schema_context = get_credential_schema_context(
                core_base_url,
                credential_schema.id,
                credential_schema_format,
            )?;

            let mut vcdm = VcdmCredential::new_v2(issuer, credential_subject)
                .add_context(ContextType::Url(credential_schema_context))
                .add_type(credential_schema.name.to_case(Case::Pascal))
                .add_credential_schema(vcdm_schema);
            // The ID property is optional according to the VCDM. We need to include it for BBS+ due to ONE-3193
            if format_type == FormatType::JsonLdBbsPlus {
                vcdm.id = Some(
                    Urn::from_uuid(credential.common().id.into())
                        .to_string()
                        .parse()?,
                );
            }
            vcdm.credential_status = credential_status;
            vcdm.valid_until = credential.common().expires_at;
            Ok(UnsignedCredential::Vcdm(vcdm))
        }
    }
}

/// Builds the claim tree of the credential from its stored claims, using the technical keys of
/// the schema format.
async fn credential_claims(
    credential: &Credential,
    credential_schema_format: &CredentialSchemaFormat,
    datatype_config: &DatatypeConfig,
) -> Result<IssuedClaims, FormatterError> {
    let stored_claims = credential.claims().as_ref().await?;
    let mappings = credential_schema_format.claim_mappings.as_ref().await?;
    let mappings: HashMap<_, _> = mappings
        .iter()
        .map(|mapping| (mapping.claim_schema_id, mapping))
        .collect();
    let mut leaves = Vec::with_capacity(stored_claims.len());
    for claim in stored_claims.iter() {
        // container claims have no value
        let Some(value) = &claim.value else {
            continue;
        };
        let claim_schema = claim.schema.as_ref().await?;
        if claim_schema.metadata {
            continue;
        }
        let mapping = mappings.get(&claim_schema.id).ok_or_else(|| {
            FormatterError::CouldNotFormat(format!(
                "missing claim mapping for claim schema `{}`",
                claim_schema.key
            ))
        })?;
        let path = technical_claim_path(claim, &claim_schema, mapping)
            .error_while("mapping claim path")?;
        let value = claim_value(value, &claim_schema.data_type, datatype_config)?;
        leaves.push((path, value));
    }
    nest(leaves)
}

/// Nests the claims by their paths. The stored order is kept, array elements are sorted by index.
fn nest(
    leaves: Vec<(Vec<ClaimPathSegment>, IssuedClaimValue)>,
) -> Result<IssuedClaims, FormatterError> {
    let mut root = Node::Object(IndexMap::new());
    for (path, value) in leaves {
        if path.is_empty() {
            return Err(FormatterError::CouldNotFormat(
                "claim path is empty".to_string(),
            ));
        }
        root.insert(&path, value)?;
    }
    match root.finish()? {
        IssuedClaimValue::Object(claims) => Ok(claims),
        _ => Err(FormatterError::CouldNotFormat(
            "claims are not an object".to_string(),
        )),
    }
}

/// Array elements can arrive in any order, so they are collected by index first.
enum Node {
    Value(IssuedClaimValue),
    Object(IndexMap<String, Node>),
    Array(BTreeMap<usize, Node>),
}

impl Node {
    fn container_for(path: &[ClaimPathSegment]) -> Self {
        match path.first() {
            Some(ClaimPathSegment::Index(_)) => Self::Array(BTreeMap::new()),
            _ => Self::Object(IndexMap::new()),
        }
    }

    fn insert(
        &mut self,
        path: &[ClaimPathSegment],
        value: IssuedClaimValue,
    ) -> Result<(), FormatterError> {
        match (self, path) {
            (node, []) => {
                *node = Self::Value(value);
                Ok(())
            }
            (Self::Object(children), [ClaimPathSegment::Key(key), rest @ ..]) => children
                .entry(key.clone())
                .or_insert_with(|| Self::container_for(rest))
                .insert(rest, value),
            (Self::Array(items), [ClaimPathSegment::Index(index), rest @ ..]) => items
                .entry(*index)
                .or_insert_with(|| Self::container_for(rest))
                .insert(rest, value),
            (Self::Object(_), [index, ..]) => Err(FormatterError::CouldNotFormat(format!(
                "array index `{index}` nested under an object"
            ))),
            (Self::Array(_), [key, ..]) => Err(FormatterError::CouldNotFormat(format!(
                "claim `{key}` nested under an array"
            ))),
            (Self::Value(_), [segment, ..]) => Err(FormatterError::CouldNotFormat(format!(
                "claim `{segment}` nested under a value"
            ))),
        }
    }

    fn finish(self) -> Result<IssuedClaimValue, FormatterError> {
        Ok(match self {
            Self::Value(value) => value,
            Self::Object(children) => IssuedClaimValue::Object(
                children
                    .into_iter()
                    .map(|(key, node)| Ok((key, node.finish()?)))
                    .collect::<Result<IssuedClaims, FormatterError>>()?,
            ),
            Self::Array(items) => {
                // the stored array elements must cover the indices 0..n
                if let Some((missing, _)) = items
                    .keys()
                    .enumerate()
                    .find(|(position, index)| position != *index)
                {
                    return Err(FormatterError::CouldNotFormat(format!(
                        "array index `{missing}` is missing"
                    )));
                }
                IssuedClaimValue::Array(
                    items
                        .into_values()
                        .map(Self::finish)
                        .collect::<Result<_, _>>()?,
                )
            }
        })
    }
}

/// Converts the stored claim value according to its datatype.
fn claim_value(
    value: &str,
    datatype: &str,
    datatype_config: &DatatypeConfig,
) -> Result<IssuedClaimValue, FormatterError> {
    let fields = datatype_config
        .get_fields(datatype)
        .error_while("getting datatype config")?;
    let datatype_type = fields.r#type;
    let invalid = || {
        FormatterError::CouldNotFormat(format!("`{value}` is not a valid {datatype_type} value"))
    };
    Ok(match datatype_type {
        DatatypeType::String | DatatypeType::Enum => IssuedClaimValue::String(value.to_owned()),
        DatatypeType::Number => {
            IssuedClaimValue::Number(if let Ok(integer) = value.parse::<i64>() {
                integer.into()
            } else if let Ok(integer) = value.parse::<u64>() {
                integer.into()
            } else {
                value
                    .parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .ok_or_else(invalid)?
            })
        }
        DatatypeType::Boolean => IssuedClaimValue::Bool(value.parse().map_err(|_| invalid())?),
        DatatypeType::Date => IssuedClaimValue::Date(value.to_owned()),
        DatatypeType::Picture => {
            let mdl_portrait = fields
                .params
                .as_ref()
                .and_then(|params| params.public.as_ref())
                .and_then(|public| public["encodeAsMdlPortrait"].as_bool())
                .unwrap_or(false);
            if mdl_portrait {
                IssuedClaimValue::MdlPortrait(value.to_owned())
            } else {
                IssuedClaimValue::Picture(value.to_owned())
            }
        }
        DatatypeType::SwiyuPicture => IssuedClaimValue::SwiyuPicture(value.to_owned()),
        DatatypeType::Object | DatatypeType::Array => {
            return Err(FormatterError::CouldNotFormat(format!(
                "claim value with container datatype {datatype_type}"
            )));
        }
    })
}

fn get_credential_schema_context(
    core_base_url: &str,
    credential_schema_id: CredentialSchemaId,
    schema_format: &CredentialSchemaFormat,
) -> Result<Url, FormatterError> {
    // Derive the context from `schema_id` itself rather than from the local
    // `credential_schema_id`/`core_base_url`. `schema_id` is what ends up in
    // `vcdm.credentialSchema.id`, and holder/verifier-side validation
    // (`is_context_list_valid`) derives the *expected* context from it with
    // this same replacement. For imported schemas `schema_id` is copied
    // verbatim from the original system and may reference a different
    // host/uuid than our own `credential_schema_id`/`core_base_url`, so
    // deriving the context from it directly keeps the two in sync.
    let context = match &schema_format.ecosystem_schema_id {
        id if id.contains("/ssi/schema/v1/") => id.replace("/ssi/schema/v1/", "/ssi/context/v1/"),
        id if id.contains("/ssi/schema/v2/") => id.replace("/ssi/schema/v2/", "/ssi/context/v1/"),
        _ => format!("{core_base_url}/ssi/context/v1/{credential_schema_id}"),
    };
    Ok(context.parse()?)
}

async fn issuer_url_for_credential(
    credential: &Credential,
    core_base_url: &str,
) -> Result<Url, FormatterError> {
    let issuer_identifier = match credential.issuer_identifier() {
        Some(identifier) => Some(identifier.as_ref().await?.to_owned()),
        None => None,
    };

    if let Some(IdentifierData::Did(issuer_did)) = issuer_identifier
        .as_ref()
        .map(|identifier| &identifier.data)
    {
        let issuer_did = issuer_did.as_ref().await?;
        return Ok(issuer_did.did.clone().into_url());
    }

    let issuer_identifier_id = issuer_identifier
        .as_ref()
        .ok_or(FormatterError::CouldNotFormat(
            "missing credential issuer identifier".to_string(),
        ))?
        .id;

    Ok(format!(
        "{core_base_url}/ssi/openid4vci/{}/{issuer_identifier_id}/{}",
        credential.common().protocol,
        credential.common().schema.id()
    )
    .parse()?)
}

impl TryFrom<serde_json::Value> for CredentialClaim {
    type Error = FormatterError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        Ok(Self {
            selectively_disclosable: false,
            metadata: false,
            value: value.try_into()?,
        })
    }
}

impl TryFrom<serde_json::Value> for CredentialClaimValue {
    type Error = FormatterError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        Ok(match value {
            serde_json::Value::Null => {
                return Err(FormatterError::CouldNotFormat(
                    "Null json value encountered".to_string(),
                ));
            }
            serde_json::Value::Bool(value) => Self::Bool(value),
            serde_json::Value::Number(value) => Self::Number(value),
            serde_json::Value::String(value) => Self::String(value),
            serde_json::Value::Array(values) => Self::Array(try_convert_inner(values)?),
            serde_json::Value::Object(values) => Self::Object(try_convert_inner(
                HashMap::from_iter(values.into_iter().filter(|(_, value)| !value.is_null())),
            )?),
        })
    }
}

impl From<CredentialClaim> for serde_json::Value {
    fn from(value: CredentialClaim) -> Self {
        value.value.into()
    }
}

impl From<CredentialClaimValue> for serde_json::Value {
    fn from(value: CredentialClaimValue) -> Self {
        match value {
            CredentialClaimValue::Bool(value) => Self::Bool(value),
            CredentialClaimValue::Number(value) => Self::Number(value),
            CredentialClaimValue::String(value) => Self::String(value),
            CredentialClaimValue::Array(values) => Self::Array(convert_inner(values)),
            CredentialClaimValue::Object(values) => Self::Object(serde_json::Map::from_iter(
                values
                    .into_iter()
                    .map(|(key, value)| (key, value.into()))
                    .collect::<HashMap<_, serde_json::Value>>(),
            )),
        }
    }
}

impl CredentialClaimValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, CredentialClaim>> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut HashMap<String, CredentialClaim>> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[CredentialClaim]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_array_mut(&mut self) -> Option<&mut Vec<CredentialClaim>> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }
}

pub(super) fn to_format_with_mappings(
    format: CredentialFormat,
    credential_schema_id: CredentialSchemaId,
    ecosystem_schema_id: String,
    claim_schemas: &[ClaimSchema],
    now: OffsetDateTime,
) -> CredentialSchemaFormat {
    let credential_schema_format_id = Uuid::new_v4().into();
    let mut claim_mappings = Vec::with_capacity(claim_schemas.len());
    for claim_schema in claim_schemas {
        let mapping = CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_format_id,
            claim_schema_id: claim_schema.id,
            technical_key: claim_schema.key.clone(),
            namespace: None,
        };
        claim_mappings.push(mapping);
    }

    CredentialSchemaFormat {
        id: credential_schema_format_id,
        created_date: now,
        last_modified: now,
        credential_schema_id,
        format,
        ecosystem_schema_id,
        claim_mappings: claim_mappings.into(),
    }
}

#[cfg(test)]
mod test {
    use indexmap::indexset;
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;
    use crate::service::test_utilities::generic_config;
    use crate::util::vcdm_jsonld_contexts::is_context_list_valid;

    // Regression test for the bug reported for JSON-LD (Classic/BBS+) schema
    // import: import assigns a new local `credential_schema.id` (and may
    // rehost `imported_source_url`), but the per-format `schema_id` - which
    // becomes `credentialSchema.id` in issued VCs - is copied verbatim from
    // the imported schema, so it may still reference a different host/uuid
    // than the local `credential_schema_id`/`core_base_url`. The `@context`
    // entry must be derived from `schema_id` itself (not from the local id),
    // so it stays consistent with what holder/verifier-side
    // `is_context_list_valid` expects.
    #[test]
    fn test_context_matches_schema_id_for_imported_json_ld_schema() {
        let now = crate::clock::now_utc();

        // `schema_id` as copied verbatim from the imported schema: it still
        // references the *original* system's host and UUID.
        let original_host = "https://original.example.com";
        let original_uuid = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let imported_schema_id =
            format!("{original_host}/ssi/schema/v2/{original_uuid}/JSON_LD_CLASSIC");

        // The row id generated locally for the imported schema (`Uuid::new_v4()`
        // in `CredentialSchemaImportParserImpl::parse`), unrelated to `original_uuid`.
        let new_local_host = "https://local.example.com";
        let new_credential_schema_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222")
            .unwrap()
            .into();

        let schema_format = CredentialSchemaFormat {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            credential_schema_id: new_credential_schema_id,
            format: "JSON_LD_CLASSIC".into(),
            ecosystem_schema_id: imported_schema_id.clone(),
            claim_mappings: Default::default(),
        };

        // This is exactly what the formatter does when building the VC.
        let context_url =
            get_credential_schema_context(new_local_host, new_credential_schema_id, &schema_format)
                .unwrap();

        // The context follows `schema_id` onto the *original* host/uuid,
        // ignoring the local host/id entirely.
        assert_eq!(
            context_url.as_str(),
            format!("{original_host}/ssi/context/v1/{original_uuid}/JSON_LD_CLASSIC")
        );

        // `vcdm.credentialSchema.id` (== schema_id) also points at the
        // original host/uuid, untouched by import.
        let vcdm_schema = VcdmCredentialSchema {
            id: imported_schema_id,
            r#type: W3C_SCHEMA_TYPE.to_string(),
            metadata: None,
        };

        let context_list = indexset![ContextType::Url(context_url)];

        // Fixed: holder/verifier-side validation now accepts the credential
        // because the derived context and schema_id agree.
        let result = is_context_list_valid(&context_list, None, Some(&vec![vcdm_schema]));
        assert!(result.is_ok());
    }

    fn leaf(value: &str) -> IssuedClaimValue {
        IssuedClaimValue::String(value.to_string())
    }

    fn key(key: &str) -> ClaimPathSegment {
        ClaimPathSegment::Key(key.to_string())
    }

    fn nested_json(leaves: Vec<(Vec<ClaimPathSegment>, &str)>) -> serde_json::Value {
        let leaves = leaves
            .into_iter()
            .map(|(path, value)| (path, leaf(value)))
            .collect();
        IssuedClaimValue::Object(nest(leaves).unwrap()).into()
    }

    #[test]
    fn test_nest_objects() {
        assert_eq!(
            json!({"name": "John", "location": {"x": "1", "y": "2"}}),
            nested_json(vec![
                (vec![key("name")], "John"),
                (vec![key("location"), key("x")], "1"),
                (vec![key("location"), key("y")], "2"),
            ])
        );
    }

    #[test]
    fn test_nest_arrays() {
        assert_eq!(
            json!({"name": "John", "location": ["1", "2"]}),
            nested_json(vec![
                (vec![key("name")], "John"),
                (vec![key("location"), ClaimPathSegment::Index(0)], "1"),
                (vec![key("location"), ClaimPathSegment::Index(1)], "2"),
            ])
        );
    }

    #[test]
    fn test_nest_numeric_key_is_not_an_array_index() {
        assert_eq!(
            json!({"years": {"2024": "1", "0": "2"}}),
            nested_json(vec![
                (vec![key("years"), key("2024")], "1"),
                (vec![key("years"), key("0")], "2"),
            ])
        );
    }

    #[test]
    fn test_nest_special_characters() {
        let name = "weird ~!@#$%^&*()_+{}|:\"<>?`-=[]\\;',.";
        assert_eq!(
            json!({"location": {name: "1"}}),
            nested_json(vec![(vec![key("location"), key(name)], "1")])
        );
    }

    #[test]
    fn test_nest_array_with_more_than_ten_items_keeps_index_order() {
        let leaves = (0..11)
            .rev()
            .map(|i| {
                (
                    vec![
                        key("representative"),
                        ClaimPathSegment::Index(i),
                        key("name"),
                    ],
                    leaf(&format!("name {i}")),
                )
            })
            .collect();

        let nested = serde_json::Value::from(IssuedClaimValue::Object(nest(leaves).unwrap()));

        let representatives = nested["representative"].as_array().unwrap();
        assert_eq!(11, representatives.len());
        for (i, representative) in representatives.iter().enumerate() {
            assert_eq!(
                format!("name {i}"),
                representative["name"].as_str().unwrap()
            );
        }
    }

    #[test]
    fn test_nest_keeps_stored_key_order() {
        let nested = nest(vec![
            (vec![key("b")], leaf("1")),
            (
                vec![key("list"), ClaimPathSegment::Index(1)],
                leaf("second"),
            ),
            (vec![key("a"), key("y")], leaf("2")),
            (vec![key("list"), ClaimPathSegment::Index(0)], leaf("first")),
            (vec![key("a"), key("x")], leaf("3")),
        ])
        .unwrap();

        assert_eq!(vec!["b", "list", "a"], nested.keys().collect::<Vec<_>>());
        assert_eq!(
            IssuedClaimValue::Array(vec![leaf("first"), leaf("second")]),
            nested["list"]
        );
        let IssuedClaimValue::Object(a) = &nested["a"] else {
            panic!("expected object");
        };
        assert_eq!(vec!["y", "x"], a.keys().collect::<Vec<_>>());
    }

    #[test]
    fn test_nest_fails_on_a_missing_array_index() {
        let result = nest(vec![
            (vec![key("list"), ClaimPathSegment::Index(0)], leaf("first")),
            (vec![key("list"), ClaimPathSegment::Index(2)], leaf("third")),
        ]);

        assert!(result.is_err());
    }

    #[test]
    fn test_claim_value_enum_is_a_string() {
        let config = generic_config().core.datatype;
        assert_eq!(
            IssuedClaimValue::String("urn:etsi:esi:eaa:eu:qualified".to_string()),
            claim_value("urn:etsi:esi:eaa:eu:qualified", "EAA_CATEGORY", &config).unwrap()
        );
    }

    #[test]
    fn test_claim_value_number_beyond_i64_stays_an_integer() {
        let config: DatatypeConfig = serde_json::from_value(json!({
            "NUMBER": {"display": "number", "type": "NUMBER", "order": 1}
        }))
        .unwrap();
        assert_eq!(
            IssuedClaimValue::Number(u64::MAX.into()),
            claim_value("18446744073709551615", "NUMBER", &config).unwrap()
        );
    }

    #[test]
    fn test_claim_value_picture_resolves_mdl_portrait_param() {
        let config: DatatypeConfig = serde_json::from_value(json!({
            "PICTURE": {"display": "picture", "type": "PICTURE", "order": 1},
            "MDL_PICTURE": {
                "display": "portrait",
                "type": "PICTURE",
                "order": 2,
                "params": {"public": {"encodeAsMdlPortrait": true}}
            }
        }))
        .unwrap();
        let data_uri = "data:image/jpeg;base64,AAAA";
        assert_eq!(
            IssuedClaimValue::Picture(data_uri.to_string()),
            claim_value(data_uri, "PICTURE", &config).unwrap()
        );
        assert_eq!(
            IssuedClaimValue::MdlPortrait(data_uri.to_string()),
            claim_value(data_uri, "MDL_PICTURE", &config).unwrap()
        );
    }
}
