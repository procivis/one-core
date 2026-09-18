use crate::config::core_config::{CoreConfig, DatatypeType};
use crate::error::ContextWithErrorCode;
use crate::mapper::credential_schema_claim::claim_path_to_formatted_path;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::Credential;
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::provider::credential_formatter::mapper::vcdm_from_credential_and_published_claims;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialStatus, PublishedClaim, PublishedClaimValue,
};
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

pub(super) async fn credential_to_credential_detail_v2(
    credential: &Credential,
    credential_schema: &CredentialSchema,
    credential_schema_format: &CredentialSchemaFormat,
    config: &CoreConfig,
    core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
) -> Result<CredentialData, IssuanceProtocolError> {
    let claims = credential.claims.as_ref().await?;
    let mappings = credential_schema_format.claim_mappings.as_ref().await?;
    let mut published_claims = Vec::with_capacity(claims.len());
    for claim in claims
        .iter()
        // filter out container claims
        .filter(|c| c.value.is_some())
    {
        let claim_schema = claim.schema.as_ref().await?;
        // filter out metadata
        if claim_schema.metadata {
            continue;
        }
        let mapping = mappings
            .iter()
            .find(|mapping| mapping.claim_schema_id == claim_schema.id)
            .ok_or(IssuanceProtocolError::Failed(
                "claim mapping not found".to_string(),
            ))?;
        let published_claim = claim_to_published_claim(claim, &claim_schema, mapping, config)?;
        published_claims.push(published_claim);
    }
    let vcdm = vcdm_from_credential_and_published_claims(
        credential,
        core_base_url,
        credential_status,
        vcdm_v2_base_context(None),
        published_claims.clone(),
        credential_schema,
        credential_schema_format,
        config,
    )
    .await
    .error_while("creating VCDM")?;

    let credential_data = CredentialData {
        vcdm,
        claims: published_claims,
        holder_identifier: None,
        holder_key_id: None,
        issuer_certificate: None,
    };
    Ok(credential_data)
}

fn claim_to_published_claim(
    claim: &Claim,
    claim_schema: &ClaimSchema,
    claim_mapping: &CredentialSchemaFormatClaimSchema,
    config: &CoreConfig,
) -> Result<PublishedClaim, IssuanceProtocolError> {
    let claim_value = claim
        .value
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(format!(
            "Missing value on leaf claim: {}",
            claim.id
        )))?;
    let value = match config
        .datatype
        .get_fields(&claim_schema.data_type)
        .error_while("getting datatype config")?
        .r#type
    {
        DatatypeType::Number => {
            if let Ok(number) = claim_value.parse::<i64>() {
                PublishedClaimValue::Integer(number)
            } else if let Ok(float) = claim_value.parse::<f64>() {
                PublishedClaimValue::Float(float)
            } else {
                // Fallback to empty string
                PublishedClaimValue::String(String::new())
            }
        }
        DatatypeType::Boolean => {
            if let Ok(bool) = claim_value.parse::<bool>() {
                PublishedClaimValue::Bool(bool)
            } else {
                // Fallback to empty string
                PublishedClaimValue::String(String::new())
            }
        }
        _ => PublishedClaimValue::String(claim_value.to_owned()),
    };

    // map to technical keys
    let key = claim_path_to_formatted_path(claim, claim_schema, claim_mapping)?;
    Ok(PublishedClaim {
        key,
        value,
        datatype: Some(claim_schema.data_type.clone()),
    })
}
