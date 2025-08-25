use std::collections::HashMap;

use convert_case::{Case, Casing};
use indexmap::IndexSet;
use one_dto_mapper::{convert_inner, try_convert_inner};
use time::OffsetDateTime;
use url::Url;
use uuid::fmt::Urn;

use super::common::map_claims;
use super::model::{CredentialData, CredentialSchema};
use super::nest_claims;
use super::vcdm::{ContextType, VcdmCredential, VcdmCredentialSubject};
use crate::config::core_config::RevocationType;
use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, CredentialClaimValue, CredentialSchemaMetadata, CredentialStatus, Issuer,
};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::error::ServiceError;

#[allow(clippy::too_many_arguments)]
pub(crate) fn credential_data_from_credential_detail_response(
    credential_detail: CredentialDetailResponseDTO,
    credential: &Credential,
    issuer_certificate: Option<Certificate>,
    holder_identifier: Option<Identifier>,
    holder_key_id: String,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
    context: IndexSet<ContextType>,
) -> Result<CredentialData, ServiceError> {
    let flat_claims = map_claims(&credential_detail.claims, false);
    let claims = nest_claims(flat_claims.clone())?;

    let valid_from = OffsetDateTime::now_utc();
    let valid_until = valid_from + time::Duration::days(365 * 2);

    let schema = credential_detail.schema;
    // The ID property is optional according to the VCDM. We need to include it for BBS+ due to ONE-3193
    // We also include it if LLVC credentials are used for revocation
    let credential_id = if schema.format.eq("JSON_LD_BBSPLUS")
        || credential_status
            .iter()
            .any(|status| status.r#type == RevocationType::Lvvc.to_string())
    {
        Urn::from_uuid(credential.id.into())
            .to_string()
            .parse()
            .ok()
    } else {
        None
    };

    let mut context = context;
    let credential_schema_context: Url = format!("{core_base_url}/ssi/context/v1/{}", schema.id)
        .parse()
        .map_err(|_| ServiceError::Other("Invalid credential schema context".to_string()))?;
    context.insert(ContextType::Url(credential_schema_context));
    let issuer = issuer_for_credential(credential, core_base_url)?;
    // We don't add the credentialSubject.id here for backwards compatibility with older JWT/SD-JWT formatters where they store the "id" in the "sub" claim.
    // For JSON-LD formats the "id" is added to the credentialSubject inside the formatter.
    // This is currently the only way to remain backwards compatible with the old formatters and allow LVVC credential to set the credentialSubject.id.
    let credential_subject = VcdmCredentialSubject::new(claims)?;

    let layout_metadata =
        schema
            .layout_properties
            .zip(schema.layout_type)
            .map(
                |(layout_properties, layout_type)| CredentialSchemaMetadata {
                    layout_properties: layout_properties.into(),
                    layout_type,
                },
            );

    let credential_schema = CredentialSchema {
        id: schema.schema_id,
        r#type: schema.schema_type.to_string(),
        metadata: layout_metadata,
    };

    let mut vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .add_type(schema.name.to_case(Case::Pascal))
        .add_credential_schema(credential_schema)
        .with_valid_from(valid_from)
        .with_valid_until(valid_until);
    vcdm.id = credential_id;
    vcdm.context.extend(context);
    vcdm.credential_status.extend(credential_status);

    Ok(CredentialData {
        vcdm,
        claims: flat_claims,
        holder_identifier,
        holder_key_id: Some(holder_key_id),
        issuer_certificate,
    })
}

fn issuer_for_credential(
    credential: &Credential,
    core_base_url: &str,
) -> Result<Issuer, ServiceError> {
    if let Some(issuer_did) = credential
        .issuer_identifier
        .as_ref()
        .and_then(|identifier| identifier.did.as_ref())
    {
        return Ok(Issuer::Url(issuer_did.did.clone().into_url()));
    }
    let credential_schema_id = credential
        .schema
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "missing credential schema".to_string(),
        ))?
        .id;
    let url: Url = format!("{core_base_url}/ssi/openid4vci/draft-13/{credential_schema_id}",)
        .parse()
        .map_err(|_| ServiceError::Other("Invalid credential schema context".to_string()))?;
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
                return Err(FormatterError::Failed(
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
