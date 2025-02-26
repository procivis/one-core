use indexmap::IndexSet;
use shared_types::DidValue;
use time::OffsetDateTime;
use uuid::fmt::Urn;

use super::common::map_claims;
use super::model::{CredentialData, CredentialSchema};
use super::nest_claims;
use super::vcdm::{ContextType, VcdmCredential, VcdmCredentialSubject};
use crate::config::core_config::RevocationType;
use crate::provider::credential_formatter::model::{
    CredentialSchemaMetadata, CredentialStatus, Issuer,
};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::error::ServiceError;

pub fn credential_data_from_credential_detail_response(
    credential: CredentialDetailResponseDTO,
    holder_did: DidValue,
    holder_key_id: String,
    _core_base_url: &str,
    credential_status: Vec<CredentialStatus>,
    context: IndexSet<ContextType>,
) -> Result<CredentialData, ServiceError> {
    let issuer_did = credential.issuer_did.map(|did| did.did).ok_or_else(|| {
        ServiceError::MappingError(format!(
            "Missing issuer DID in CredentialDetailResponseDTO for credential {}",
            credential.id
        ))
    })?;

    let flat_claims = map_claims(&credential.claims, false);
    let claims = nest_claims(flat_claims.clone())?;

    let valid_from = OffsetDateTime::now_utc();
    let valid_until = valid_from + time::Duration::days(365 * 2);

    // The ID property is optional according to the VCDM. We need to include it for BBS+ due to ONE-3193
    // We also include it if LLVC credentials are used for revocation
    let credential_id = if credential.schema.format.eq("JSON_LD_BBSPLUS")
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

    // We don't add the credentialSubject.id here for backwards compatibility with older JWT/SD-JWT formatters where they store the "id" in the "sub" claim.
    // For JSON-LD formats the "id" is added to the credentialSubject inside the formatter.
    // This is currently the only way to remain backwards compatible with the old formatters and allow LVVC credential to set the credentialSubject.id.
    let credential_subject = VcdmCredentialSubject::new(claims);

    let layout_metadata = credential
        .schema
        .layout_properties
        .zip(credential.schema.layout_type)
        .map(
            |(layout_properties, layout_type)| CredentialSchemaMetadata {
                layout_properties: layout_properties.into(),
                layout_type,
            },
        );

    let credential_schema = CredentialSchema {
        id: credential.schema.schema_id,
        r#type: credential.schema.schema_type.to_string(),
        metadata: layout_metadata,
    };

    // todo: Uncomment this to add the credential context after bbs+ is fixed in https://procivis.atlassian.net/browse/ONE-4764
    // let mut context = context;
    // let credential_schema_context: Url =
    //     format!("{core_base_url}/ssi/context/v1/{}", credential.schema.id)
    //         .parse()
    //         .map_err(|_| ServiceError::Other("Invalid credential schema context".to_string()))?;
    // context.insert(ContextType::Url(credential_schema_context));

    let issuer = Issuer::Url(issuer_did.into_url());
    let mut vcdm = VcdmCredential::new_v2(issuer, credential_subject)
        .add_credential_schema(credential_schema)
        .with_valid_from(valid_from)
        .with_valid_until(valid_until);
    vcdm.id = credential_id;
    vcdm.context.extend(context);
    vcdm.credential_status.extend(credential_status);

    Ok(CredentialData {
        vcdm,
        claims: flat_claims,
        holder_did: Some(holder_did),
        holder_key_id: Some(holder_key_id),
    })
}
