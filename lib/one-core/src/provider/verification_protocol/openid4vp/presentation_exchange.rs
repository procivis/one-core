use std::sync::Arc;

use uuid::Uuid;

use crate::config::core_config::{CoreConfig, FormatType, VerificationProtocolType};
use crate::mapper::oidc::map_to_openid4vp_format;
use crate::proto::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::model::{
    CredentialToPresent, FormatPresentationCtx, FormattedPresentation,
};
use crate::provider::presentation_formatter::provider::PresentationFormatterProvider;
use crate::provider::verification_protocol::dto::{
    FormattedCredentialPresentation, PresentationDefinitionRequestedCredentialResponseDTO,
    PresentationReference,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft25::mappers::encode_client_id_with_scheme_draft25;
use crate::provider::verification_protocol::openid4vp::mapper::{
    cred_to_presentation_format_type, format_to_type,
};
use crate::provider::verification_protocol::openid4vp::mdoc::{
    mdoc_draft_handover, mdoc_presentation_context,
};
use crate::provider::verification_protocol::openid4vp::model::{
    EncryptionInfo, NestedPresentationSubmissionDescriptorDTO, OpenID4VPHolderInteractionData,
    PexSubmission, PresentationSubmissionDescriptorDTO, PresentationSubmissionMappingDTO,
    VpSubmissionData,
};
use crate::provider::verification_protocol::openid4vp::service::encryption_info_from_metadata;

#[expect(clippy::too_many_arguments)]
pub(crate) async fn pex_submission_data(
    credential_presentations: Vec<FormattedCredentialPresentation>,
    interaction_data: &OpenID4VPHolderInteractionData,
    holder_nonce: &str,
    client: &dyn HttpClient,
    config: &CoreConfig,
    presentation_formatter_provider: &dyn PresentationFormatterProvider,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    protocol: VerificationProtocolType,
) -> Result<(VpSubmissionData, Option<EncryptionInfo>), VerificationProtocolError> {
    let response_uri =
        interaction_data
            .response_uri
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "response_uri is None".to_string(),
            ))?;
    let verifier_nonce =
        interaction_data
            .nonce
            .clone()
            .ok_or(VerificationProtocolError::Failed(
                "nonce is None".to_string(),
            ))?;
    let encryption_info = encryption_info_from_metadata(client, interaction_data).await?;

    let vp_token_is_array = credential_presentations.len() > 1;
    let mut vp_tokens = vec![];
    let mut descriptor_map = vec![];
    for (idx, credential) in credential_presentations.into_iter().enumerate() {
        let PresentationReference::PresentationExchange(reference) = &credential.reference else {
            return Err(VerificationProtocolError::Failed(
                "Unsupported presentation reference".to_string(),
            ));
        };
        let credential_format_type = format_to_type(&credential, config)?;
        let mut credentials_to_present = vec![CredentialToPresent {
            raw_credential: credential.presentation,
            credential_format: credential_format_type,
        }];
        let has_validity_credential =
            if let Some(validity_cred) = credential.validity_credential_presentation {
                credentials_to_present.push(CredentialToPresent {
                    raw_credential: validity_cred,
                    credential_format: credential_format_type,
                });
                true
            } else {
                false
            };
        let presentation_format_type = cred_to_presentation_format_type(credential_format_type);
        if encryption_info.is_none() && presentation_format_type == FormatType::Mdoc {
            return Err(VerificationProtocolError::Failed(
                "MDOC presentation requires encryption but no verifier EC keys are available"
                    .to_string(),
            ));
        }
        let (_, presentation_formatter) =  presentation_formatter_provider.get_presentation_formatter_by_type(presentation_format_type)
            .ok_or(VerificationProtocolError::Failed(format!("No matching formatter found for presentation format type {presentation_format_type}")))?;

        let auth_fn = key_provider
            .get_signature_provider(
                &credential.key,
                credential.jwk_key_id,
                key_algorithm_provider.clone(),
            )
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
        let ctx = if presentation_format_type == FormatType::Mdoc {
            let client_id = if protocol == VerificationProtocolType::OpenId4VpDraft25 {
                &encode_client_id_with_scheme_draft25(
                    interaction_data.client_id.clone(),
                    interaction_data.client_id_scheme,
                )
            } else {
                &interaction_data.client_id
            };

            mdoc_presentation_context(mdoc_draft_handover(
                client_id,
                response_uri,
                &verifier_nonce,
                holder_nonce,
            )?)?
        } else {
            FormatPresentationCtx {
                nonce: Some(verifier_nonce.clone()),
                ..Default::default()
            }
        };
        let FormattedPresentation {
            vp_token,
            oidc_format,
        } = presentation_formatter
            .format_presentation(
                credentials_to_present,
                auth_fn,
                &credential.holder_did.map(|did| did.did),
                ctx,
            )
            .await
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
        vp_tokens.push(vp_token);
        let credential_openid4vp_format = map_to_openid4vp_format(&credential_format_type)
            .map_err(|error| VerificationProtocolError::Failed(error.to_string()))?
            .to_string();
        let idx = if vp_token_is_array { Some(idx) } else { None };
        descriptor_map.append(&mut submission_descriptors(
            reference,
            oidc_format,
            &credential_openid4vp_format,
            idx,
            has_validity_credential,
        ));
    }

    let presentation_definition_id = interaction_data
        .presentation_definition
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "presentation_definition is None".to_string(),
        ))?
        .id
        .to_owned();

    let submission_data = VpSubmissionData::Pex(PexSubmission {
        presentation_submission: PresentationSubmissionMappingDTO {
            id: Uuid::new_v4().to_string(),
            definition_id: presentation_definition_id,
            descriptor_map,
        },
        vp_token: vp_tokens,
    });
    Ok((submission_data, encryption_info))
}

fn submission_descriptors(
    reference: &PresentationDefinitionRequestedCredentialResponseDTO,
    presentation_format: String,
    credential_format: &str,
    vp_token_index: Option<usize>,
    with_validity_presentation: bool,
) -> Vec<PresentationSubmissionDescriptorDTO> {
    let mut result = vec![];
    let path_nested_supported =
        presentation_format == "jwt_vp_json" || presentation_format == "ldp_vp";
    let mut vp_token_path = "$".to_string();
    if let Some(idx) = vp_token_index {
        vp_token_path.push_str(&format!("[{idx}]"));
    };
    result.push(PresentationSubmissionDescriptorDTO {
        id: reference.id.clone(),
        format: presentation_format.to_owned(),
        path: vp_token_path.to_owned(),
        path_nested: if path_nested_supported {
            Some(NestedPresentationSubmissionDescriptorDTO {
                format: credential_format.to_owned(),
                path: format!("{vp_token_path}.vp.verifiableCredential[0]"),
            })
        } else {
            None
        },
    });
    if with_validity_presentation {
        result.push(PresentationSubmissionDescriptorDTO {
            id: reference.id.clone(),
            format: presentation_format,
            path_nested: if path_nested_supported {
                Some(NestedPresentationSubmissionDescriptorDTO {
                    format: credential_format.to_owned(),
                    path: format!("{vp_token_path}.vp.verifiableCredential[1]"),
                })
            } else {
                None
            },
            path: vp_token_path,
        });
    }
    result
}
