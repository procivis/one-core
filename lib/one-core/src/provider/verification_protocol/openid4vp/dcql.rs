use std::collections::HashMap;

use dcql::matching::CredentialFilter;
use dcql::{ClaimPath, CredentialFormat, CredentialQuery, DcqlQuery, PathSegment};
use shared_types::{CredentialId, OrganisationId};

use crate::config::core_config::CoreConfig;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::proof::Proof;
use crate::provider::verification_protocol::dto::{
    PresentationDefinitionFieldDTO, PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::mapper::credential_model_to_credential_dto;
use crate::service::storage_proxy::StorageAccess;

/// Retrieve the "presentation definition" for the given DCQL query.
///
/// Limitations:
///   - No DCQL support for:
///     - credential_sets
///     - claim value matching
///     - trusted authorities
///     - `multiple` flag
///     - `require_cryptographic_holder_binding` flag
///   - Metadata claims such as `exp`, `aud`, `@context` or `_sd` cannot be queried
///   - No support for `vct` inheritance
///   - W3C VCs have proprietary lookup logic based on the JSON-LD context
///   - Claim paths with array index or array all selectors are not supported
///   - TODO: Misinterpretation of absent `claims` restriction: instead of all non-selectively disclosable
///     claims, all claims (regardless of the ability to selectively disclose) are returned
pub(crate) async fn get_presentation_definition_for_dcql_query(
    dcql_query: DcqlQuery,
    proof: &Proof,
    storage_access: &StorageAccess,
    config: &CoreConfig,
) -> Result<PresentationDefinitionResponseDTO, VerificationProtocolError> {
    let organisation = proof
        .interaction
        .as_ref()
        .and_then(|interaction| interaction.organisation.as_ref())
        .ok_or(VerificationProtocolError::Failed(
            "proof organisation missing".to_string(),
        ))?;

    let query_to_filters = dcql_query
        .credential_filters()
        .map_err(VerificationProtocolError::DcqlError)?;

    let mut relevant_credentials = vec![];
    let mut requested_credentials = vec![];
    for query in dcql_query.credentials {
        let credential_filters =
            query_to_filters
                .get(&query.id)
                .ok_or(VerificationProtocolError::Failed(format!(
                    "missing credential filters for credential query with id {}",
                    query.id
                )))?;

        // This is very inefficient. We would have the information here to also filter by the claims
        // required, appropriate state / role, etc. but so far this was not a problem so it is not
        // optimized.
        let mut credential_candidates =
            fetch_credentials_for_schema_ids(storage_access, organisation.id, credential_filters)
                .await?;

        credential_candidates.retain(|credential| {
            credential.state == CredentialStateEnum::Accepted
                && credential.role == CredentialRole::Holder
        });

        let field_to_credentials =
            first_applicable_claim_set(&credential_candidates, credential_filters)?;
        relevant_credentials.append(&mut credential_candidates);
        requested_credentials.push(to_requested_credential(query, field_to_credentials))
    }
    Ok(PresentationDefinitionResponseDTO {
        request_groups: vec![PresentationDefinitionRequestGroupResponseDTO {
            id: proof.id.to_string(),
            name: None,
            purpose: None,
            rule: PresentationDefinitionRuleDTO {
                r#type: PresentationDefinitionRuleTypeEnum::All,
                min: None,
                max: None,
                count: None,
            },
            requested_credentials,
        }],
        credentials: credential_model_to_credential_dto(relevant_credentials, config)?,
    })
}

fn to_requested_credential(
    query: CredentialQuery,
    field_to_credentials: FieldToCredentialAssignments,
) -> PresentationDefinitionRequestedCredentialResponseDTO {
    let mut fields = vec![];
    for (field_path, credential_ids) in field_to_credentials.field_to_credentials {
        let key_map = credential_ids
            .into_iter()
            .map(|id| (id.to_string(), field_path.clone()))
            .collect();
        let claim_query = query
            .claims
            .iter()
            .flatten()
            .find(|claim| dcql_path_to_claim_key(&claim.path) == field_path);

        // the query is absent in case `claims` was not provided in the DCQL query
        let field = if let Some(claim_query) = claim_query {
            PresentationDefinitionFieldDTO {
                id: claim_query
                    .id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(field_path.clone()),
                name: Some(field_path.clone()),
                purpose: None,
                required: Some(claim_query.required.unwrap_or(true)),
                key_map,
            }
        } else {
            PresentationDefinitionFieldDTO {
                id: field_path.clone(),
                name: Some(field_path.clone()),
                purpose: None,
                required: Some(false),
                key_map,
            }
        };
        fields.push(field);
    }
    PresentationDefinitionRequestedCredentialResponseDTO {
        id: query.id.to_string(),
        name: None,
        purpose: None,
        fields,
        applicable_credentials: field_to_credentials.applicable_credentials,
        inapplicable_credentials: field_to_credentials.inapplicable_credentials,
        validity_credential_nbf: None,
    }
}

struct FieldToCredentialAssignments {
    field_to_credentials: HashMap<String, Vec<CredentialId>>,
    applicable_credentials: Vec<String>,
    inapplicable_credentials: Vec<String>,
}

fn first_applicable_claim_set(
    credentials: &[Credential],
    filters: &[CredentialFilter],
) -> Result<FieldToCredentialAssignments, VerificationProtocolError> {
    // Try to find at least one credential matching for each credential filter
    // The filters are ordered by verifier preference. The number of filters corresponds
    // to the number of entries in `claim_sets` for the current credential query.
    for filter in filters {
        let mut field_to_credentials = HashMap::new();
        let mut applicable_credentials = vec![];
        let mut inapplicable_credentials = vec![];

        // match each credential against the particular filter / claim set
        for credential in credentials {
            let selected_claims = select_claims(credential, filter)?;

            if let Some(selected_claims) = selected_claims {
                applicable_credentials.push(credential.id.to_string());
                // The current credential matched. Arrange them by path so that it is easier
                // to later build the `field.keyMap`.
                for selected_claim in selected_claims {
                    field_to_credentials
                        .entry(selected_claim)
                        .and_modify(|credentials: &mut Vec<CredentialId>| {
                            credentials.push(credential.id)
                        })
                        .or_insert(vec![credential.id]);
                }
            } else {
                // the current credential is not applicable given the current claim set
                inapplicable_credentials.push(credential.id.to_string());
            }
        }

        // If we have at least one match, we can stop and use that claim set.
        // Otherwise, we need to continue searching for matches using the next claim set.
        if !field_to_credentials.is_empty() {
            return Ok(FieldToCredentialAssignments {
                field_to_credentials,
                applicable_credentials,
                inapplicable_credentials,
            });
        }
    }

    // We have exhausted all options / claim sets and never found any credential matching.
    Ok(FieldToCredentialAssignments {
        field_to_credentials: filters
            // Presumably the last option has the lowest requirements (as it is the least preferred by verifiers).
            // Let's use that as the minimum requirement the credentials in the wallet failed to match.
            .last()
            .iter()
            .flat_map(|filter| &filter.claims)
            .filter(|claim| claim.required)
            .map(|claim| (dcql_path_to_claim_key(&claim.path), vec![]))
            .collect(),
        applicable_credentials: vec![],
        inapplicable_credentials: credentials
            .iter()
            .map(|credential| credential.id.to_string())
            .collect(),
    })
}

fn select_claims(
    credential: &Credential,
    filter: &CredentialFilter,
) -> Result<Option<Vec<String>>, VerificationProtocolError> {
    let Some(claims) = &credential.claims else {
        return Err(VerificationProtocolError::Failed(format!(
            "credential {} has no claims",
            credential.id
        )));
    };

    // TODO: if filter.claims is empty select everything up to array claims
    if claims.is_empty() {
        return Err(VerificationProtocolError::Failed(
            "Empty / missing claims not yet supported".to_owned(),
        ));
    }

    let mut result = vec![];
    for claim_filter in &filter.claims {
        if claim_filter
            .path
            .segments
            .iter()
            .any(|segment| !matches!(segment, PathSegment::PropertyName(_)))
        {
            return Err(VerificationProtocolError::Failed(format!(
                "unsupported claim filter (reaching into array claim): {}",
                claim_filter.path
            )));
        }
        let path_prefix = dcql_path_to_claim_key(&claim_filter.path);
        if claims
            .iter()
            .any(|claim| claim.path.starts_with(&path_prefix))
        {
            result.push(path_prefix);
        } else if claim_filter.required {
            // no match but claim is required --> abort as not matching
            return Ok(None);
        }
    }
    Ok(Some(result))
}

async fn fetch_credentials_for_schema_ids(
    storage_access: &StorageAccess,
    organisation_id: OrganisationId,
    credential_filters: &[CredentialFilter],
) -> Result<Vec<Credential>, VerificationProtocolError> {
    let mut credentials = vec![];

    // The filters only change based on the different claim sets. So to retrieve the
    // credential schema ids, just looking at the first one is sufficient.
    let Some(filter) = credential_filters.first() else {
        return Err(VerificationProtocolError::Failed(
            "empty credential filters".to_string(),
        ));
    };

    for schema_id in &filter.schema_ids {
        let schema_id = match filter.format {
            CredentialFormat::JwtVc | CredentialFormat::LdpVc => schema_id
                // Make use of the fact that Procivis One issuers put the schema id into the context,
                // hence we can potentially parse it out of the supplied types.
                // Note: This will most likely fail with third party issuers. Improve the logic,
                // once we need to interop with such issuers.
                .split_once("#")
                .map(|(first, _)| first)
                .unwrap_or(schema_id),
            CredentialFormat::MsoMdoc | CredentialFormat::SdJwt => schema_id,
        };

        credentials.append(
            &mut storage_access
                .get_credentials_by_credential_schema_id(schema_id, organisation_id)
                .await
                .map_err(VerificationProtocolError::StorageAccessError)?,
        );
    }
    Ok(credentials)
}

fn dcql_path_to_claim_key(path: &ClaimPath) -> String {
    path.segments
        .iter()
        .map(ToString::to_string)
        // remove the quotes around strings
        .map(|s| s.replace("\"", ""))
        .collect::<Vec<_>>()
        .join("/")
}
