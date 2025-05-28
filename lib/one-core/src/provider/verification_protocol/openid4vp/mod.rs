//! Implementation of OpenID4VP.
//! https://openid.net/specs/openid-4-verifiable-presentations-1_0.html

use std::collections::{HashMap, HashSet};

use mapper::{get_claim_name_by_json_path, presentation_definition_from_interaction_data};
use one_dto_mapper::convert_inner;

use super::dto::{CredentialGroup, CredentialGroupItem, PresentationDefinitionResponseDTO};
use super::{FormatMapper, StorageAccess, TypeToDescriptorMapper, VerificationProtocolError};
use crate::config::core_config::CoreConfig;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::proof::Proof;
use crate::provider::verification_protocol::mapper::{
    gather_object_datatypes_from_config, get_relevant_credentials_to_credential_schemas,
};
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPClientMetadata, OpenID4VPPresentationDefinition,
};
use crate::service::proof::dto::ShareProofRequestParamsDTO;
use crate::util::oidc::map_from_openid4vp_format;

pub mod draft20;
pub mod draft20_swiyu;
pub mod draft25;
pub mod error;
pub(crate) mod jwe_presentation;
pub(crate) mod mapper;
pub(crate) mod mdoc;
pub mod model;
pub mod proximity_draft00;
pub mod service;
pub mod validator;

fn get_client_id_scheme(
    params: Option<ShareProofRequestParamsDTO>,
    supported_client_id_schemes: &[ClientIdScheme],
    verifier_identifier: Identifier,
) -> Result<ClientIdScheme, VerificationProtocolError> {
    let param_scheme = params.unwrap_or_default().client_id_scheme;

    if let Some(scheme) = param_scheme {
        return Ok(scheme);
    }

    let fallback_scheme = supported_client_id_schemes
        .iter()
        .find(|scheme| {
            get_supported_client_id_scheme_for_identifier(&verifier_identifier.r#type)
                .contains(scheme)
        })
        .cloned()
        .ok_or_else(|| {
            VerificationProtocolError::InvalidRequest(
                "No supported client_id_scheme for selected identifier type".to_string(),
            )
        })?;

    Ok(fallback_scheme)
}

fn get_supported_client_id_scheme_for_identifier(
    identifier: &IdentifierType,
) -> Vec<ClientIdScheme> {
    match identifier {
        IdentifierType::Key => vec![],
        IdentifierType::Did => vec![
            ClientIdScheme::Did,
            ClientIdScheme::VerifierAttestation,
            ClientIdScheme::RedirectUri,
        ],
        IdentifierType::Certificate => vec![ClientIdScheme::X509SanDns],
    }
}

fn extract_common_formats(
    allowed_schema_input_descriptor_formats: HashSet<String>,
    client_metadata: &Option<OpenID4VPClientMetadata>,
) -> Result<HashSet<String>, VerificationProtocolError> {
    if let Some(client_metadata) = client_metadata {
        let oidc_formats = client_metadata.vp_formats.keys().collect::<HashSet<_>>();

        let schema_formats: HashSet<String> = oidc_formats
            .iter()
            .map(|oidc_format| {
                map_from_openid4vp_format(oidc_format)
                    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
            })
            .collect::<Result<_, _>>()?;

        Ok(allowed_schema_input_descriptor_formats
            .intersection(&schema_formats)
            .cloned()
            .collect())
    } else {
        Ok(allowed_schema_input_descriptor_formats)
    }
}

pub(crate) async fn get_presentation_definition_with_local_credentials(
    verifier_presentation_definition: OpenID4VPPresentationDefinition,
    proof: &Proof,
    client_metadata: Option<OpenID4VPClientMetadata>,
    storage_access: &StorageAccess,
    config: &CoreConfig,
) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
    let mut credential_groups: Vec<CredentialGroup> = vec![];
    let mut group_id_to_schema_id: HashMap<String, String> = HashMap::new();

    let mut allowed_oidc_input_descriptor_formats = HashSet::new();

    for input_descriptor in verifier_presentation_definition.input_descriptors {
        input_descriptor.format.keys().for_each(|key| {
            allowed_oidc_input_descriptor_formats.insert(key.to_owned());
        });
        let validity_credential_nbf = input_descriptor.constraints.validity_credential_nbf;

        let mut fields = input_descriptor.constraints.fields;

        let target_schema_id = if input_descriptor.format.contains_key("mso_mdoc") {
            input_descriptor.id.to_owned()
        } else {
            let schema_id_filter_index = fields
                .iter()
                .position(|field| {
                    field.filter.is_some()
                        && field.path.contains(&"$.credentialSchema.id".to_string())
                        || field.path.contains(&"$.vct".to_string())
                })
                .ok_or(VerificationProtocolError::Failed(
                    "schema_id filter not found".to_string(),
                ))?;

            let schema_id_filter = fields.remove(schema_id_filter_index).filter.ok_or(
                VerificationProtocolError::Failed("schema_id filter not found".to_string()),
            )?;

            schema_id_filter.r#const
        };

        group_id_to_schema_id.insert(input_descriptor.id.clone(), target_schema_id);
        credential_groups.push(CredentialGroup {
            id: input_descriptor.id,
            name: input_descriptor.name,
            purpose: input_descriptor.purpose,
            claims: fields
                .iter()
                .map(|requested_claim| {
                    Ok(CredentialGroupItem {
                        id: requested_claim
                            .id
                            .map(|id| id.to_string())
                            .unwrap_or(requested_claim.path.join(".")),
                        key: get_claim_name_by_json_path(&requested_claim.path)?,
                        required: !requested_claim.optional.is_some_and(|optional| optional),
                    })
                })
                .collect::<anyhow::Result<Vec<_>, _>>()?,
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
            validity_credential_nbf,
        });
    }

    let allowed_schema_input_descriptor_formats: HashSet<_> = allowed_oidc_input_descriptor_formats
        .iter()
        .map(|oidc_format| {
            map_from_openid4vp_format(oidc_format)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
        })
        .collect::<Result<_, _>>()?;

    let allowed_schema_formats =
        extract_common_formats(allowed_schema_input_descriptor_formats, &client_metadata)?;

    let organisation = proof
        .interaction
        .as_ref()
        .and_then(|interaction| interaction.organisation.as_ref())
        .ok_or(VerificationProtocolError::Failed(
            "proof organisation missing".to_string(),
        ))?;

    let (credentials, credential_groups) = get_relevant_credentials_to_credential_schemas(
        storage_access,
        credential_groups,
        group_id_to_schema_id,
        &allowed_schema_formats,
        &gather_object_datatypes_from_config(&config.datatype),
        organisation.id,
    )
    .await?;

    presentation_definition_from_interaction_data(
        proof.id,
        convert_inner(credentials),
        convert_inner(credential_groups),
        config,
    )
}
