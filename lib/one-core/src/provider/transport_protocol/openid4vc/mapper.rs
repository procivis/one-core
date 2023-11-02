use std::collections::HashMap;

use crate::{
    model::{credential::Credential, interaction::InteractionId},
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
