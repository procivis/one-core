use std::collections::HashMap;

use convert_case::{Case, Casing};
use indexmap::IndexSet;
use one_dto_mapper::{convert_inner, try_convert_inner};
use shared_types::{CredentialFormat, CredentialSchemaId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;
use uuid::fmt::Urn;

use super::common::map_claims;
use super::model::{CredentialData, CredentialSchema, FormatterCapabilities, PublishedClaim};
use super::nest_claims;
use super::vcdm::{ContextType, VcdmCredential, VcdmCredentialSubject};
use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::ContextWithErrorCode;
use crate::model::certificate::Certificate;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialSchemaMetadata, CredentialStatus, Issuer,
};
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
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

#[expect(clippy::too_many_arguments)]
pub(crate) async fn credential_data_from_credential_detail_response(
    credential_detail: CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>,
    credential: &Credential,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
    context: IndexSet<ContextType>,
    credential_schema: &crate::model::credential_schema::CredentialSchema,
    credential_schema_format: &CredentialSchemaFormat,
    config: &CoreConfig,
) -> Result<CredentialData, FormatterError> {
    let flat_claims = map_claims(&credential_detail.claims, false);

    let vcdm = vcdm_from_credential_and_published_claims(
        credential,
        core_base_url,
        credential_status,
        context,
        flat_claims.clone(),
        credential_schema,
        credential_schema_format,
        config,
    )
    .await?;

    Ok(CredentialData {
        vcdm,
        claims: flat_claims,
        holder_identifier: None,
        holder_key_id: None,
        issuer_certificate: None,
    })
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn vcdm_from_credential_and_published_claims(
    credential: &Credential,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
    mut context: IndexSet<ContextType>,
    flat_claims: Vec<PublishedClaim>,
    credential_schema: &crate::model::credential_schema::CredentialSchema,
    credential_schema_format: &CredentialSchemaFormat,
    config: &CoreConfig,
) -> Result<VcdmCredential, FormatterError> {
    let claims = nest_claims(flat_claims).error_while("nesting claims")?;

    // The ID property is optional according to the VCDM. We need to include it for BBS+ due to ONE-3193
    let format_type = config
        .format
        .get_type(&credential_schema_format.format)
        .error_while("getting format type")?;
    let credential_id = if format_type == FormatType::JsonLdBbsPlus {
        Urn::from_uuid(credential.id.into())
            .to_string()
            .parse()
            .ok()
    } else {
        None
    };

    let credential_schema_context = get_credential_schema_context(
        core_base_url,
        credential_schema.id,
        credential_schema_format,
    )?;
    context.insert(ContextType::Url(credential_schema_context));
    let issuer = issuer_for_credential(credential, core_base_url).await?;
    // We don't add the credentialSubject.id here for backwards compatibility with older JWT/SD-JWT formatters where they store the "id" in the "sub" claim.
    // For JSON-LD formats the "id" is added to the credentialSubject inside the formatter.
    // This is currently the only way to remain backwards compatible with the old formatters.
    let credential_subject = VcdmCredentialSubject::new(claims).error_while("creating subject")?;

    let layout_properties: Option<CredentialSchemaLayoutPropertiesResponseDTO> =
        convert_inner(credential_schema.layout_properties.clone());
    let metadata = layout_properties.map(|layout_properties| CredentialSchemaMetadata {
        layout_properties: layout_properties.into(),
        // for backward compatibility
        layout_type: Some("CARD".to_string()),
    });

    let vcdm_schema = CredentialSchema {
        id: credential_schema_format.ecosystem_schema_id.clone(),
        r#type: W3C_SCHEMA_TYPE.to_string(),
        metadata,
    };

    let mut vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .add_type(credential_schema.name.to_case(Case::Pascal))
        .add_credential_schema(vcdm_schema);
    vcdm.id = credential_id;
    vcdm.context.extend(context);
    vcdm.credential_status.extend(credential_status);
    vcdm.valid_until = credential.expires_at;
    Ok(vcdm)
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

async fn issuer_for_credential(
    credential: &Credential,
    core_base_url: &str,
) -> Result<Issuer, FormatterError> {
    let issuer_identifier = match credential.issuer_identifier.as_ref() {
        Some(identifier) => Some(identifier.as_ref().await?.to_owned()),
        None => None,
    };

    if let Some(IdentifierData::Did(issuer_did)) = issuer_identifier
        .as_ref()
        .map(|identifier| &identifier.data)
    {
        let issuer_did = issuer_did.as_ref().await?;
        return Ok(Issuer::Url(issuer_did.did.clone().into_url()));
    }

    let issuer_identifier_id = issuer_identifier
        .as_ref()
        .ok_or(FormatterError::CouldNotFormat(
            "missing credential issuer identifier".to_string(),
        ))?
        .id;

    let url: Url = format!(
        "{core_base_url}/ssi/openid4vci/{}/{issuer_identifier_id}/{}",
        credential.protocol,
        credential.schema.id()
    )
    .parse()?;
    Ok(Issuer::Url(url))
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
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::{W3C_SCHEMA_TYPE, get_credential_schema_context};
    use crate::model::credential_schema_format::CredentialSchemaFormat;
    use crate::provider::credential_formatter::model::CredentialSchema as VcdmSchema;
    use crate::provider::credential_formatter::vcdm::ContextType;
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
        let vcdm_schema = VcdmSchema {
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
}
