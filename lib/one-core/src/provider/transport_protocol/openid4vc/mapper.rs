use std::collections::HashMap;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{
        claim::Claim, claim_schema::ClaimSchema, credential::Credential,
        credential_schema::CredentialSchemaClaim, interaction::InteractionId,
    },
    provider::transport_protocol::{
        openid4vc::dto::{
            OpenID4VCICredentialDefinition, OpenID4VCICredentialRequestDTO,
            OpenID4VCICredentialSubject, OpenID4VCIGrant, OpenID4VCIGrants,
        },
        TransportProtocolError,
    },
    util::oidc::map_core_to_oidc_format,
};

use super::dto::{OpenID4VCICredentialOffer, OpenID4VCICredentialValeDetails};

pub(super) fn create_credential_offer_encoded(
    base_url: Option<String>,
    interaction_id: &InteractionId,
    credential: &Credential,
) -> Result<String, TransportProtocolError> {
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(TransportProtocolError::Failed(
            "Missing credential schema".to_owned(),
        ))?;

    let claims = credential
        .claims
        .as_ref()
        .ok_or(TransportProtocolError::Failed("Missing claims".to_owned()))?;

    let url = base_url.ok_or(TransportProtocolError::Failed(
        "Missing base_url".to_owned(),
    ))?;

    let offer = OpenID4VCICredentialOffer {
        credential_issuer: format!("{}/ssi/oidc-issuer/v1/{}", url, credential_schema.id),
        credentials: vec![OpenID4VCICredentialRequestDTO {
            format: map_core_to_oidc_format(&credential_schema.format)
                .map_err(|e| TransportProtocolError::Failed(e.to_string()))?,
            credential_definition: OpenID4VCICredentialDefinition {
                r#type: vec!["VerifiableCredential".to_string()],
                credential_subject: Some(OpenID4VCICredentialSubject {
                    keys: HashMap::from_iter(claims.iter().filter_map(|claim| {
                        claim.schema.as_ref().map(|schema| {
                            (
                                schema.key.clone(),
                                OpenID4VCICredentialValeDetails {
                                    value: claim.value.clone(),
                                    value_type: schema.data_type.clone(),
                                },
                            )
                        })
                    })),
                }),
            },
        }],
        grants: OpenID4VCIGrants {
            code: OpenID4VCIGrant {
                pre_authorized_code: interaction_id.to_string(),
            },
        },
    };

    let offer_string =
        serde_json::to_string(&offer).map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    let offer_encoded = serde_urlencoded::to_string([("credential_offer", offer_string)])
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?;

    Ok(offer_encoded)
}

pub(super) fn create_claims_from_credential_definition(
    credential_definition: &OpenID4VCICredentialDefinition,
) -> Option<Vec<(CredentialSchemaClaim, Claim)>> {
    let credential_subject = credential_definition.credential_subject.as_ref()?;
    let created_at = OffsetDateTime::now_utc();

    let claims = credential_subject
        .keys
        .iter()
        .map(|(key, value_details)| {
            let claim_schema = ClaimSchema {
                id: Uuid::new_v4(),
                key: key.to_string(),
                data_type: value_details.value_type.to_string(),
                created_date: created_at,
                last_modified: created_at,
            };
            let schema_claim = CredentialSchemaClaim {
                schema: claim_schema.clone(),
                required: false,
            };
            let claim = Claim {
                id: Uuid::new_v4(),
                created_date: created_at,
                last_modified: created_at,
                value: value_details.value.to_string(),
                schema: Some(claim_schema),
            };

            (schema_claim, claim)
        })
        .collect();

    Some(claims)
}
