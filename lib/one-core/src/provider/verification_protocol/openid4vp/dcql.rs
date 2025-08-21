use std::collections::{HashMap, HashSet, VecDeque};

use dcql::matching::{ClaimFilter, CredentialFilter};
use dcql::{ClaimPath, ClaimValue, CredentialFormat, CredentialQuery, DcqlQuery, PathSegment};
use shared_types::{CredentialId, OrganisationId};

use crate::config::core_config::{CoreConfig, FormatType};
use crate::model::claim::Claim;
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
///     - trusted authorities
///     - `multiple` flag
///     - `require_cryptographic_holder_binding` flag
///   - Metadata claims such as `exp`, `aud`, `@context` or `_sd` cannot be queried
///   - No support for `vct` inheritance
///   - W3C VCs have proprietary lookup logic based on the JSON-LD context
///   - Misleading requested credential `fields` `required` flag when credentials with different schemas are queried
///     simultaneously and where only some claims support selective disclosure:
///     Since there is only one required flag per field, the required flag will be set to `true` if the field is present in
///     at least one credential where the field is not selectively disclosable even if it would be optional given the DCQL
///     query, and it would be selectively disclosable for other credentials.
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
            let Some(schema) = &credential.schema else {
                return false;
            };
            format_matches(&query.format, &schema.format, config)
        });

        credential_candidates.retain(|credential| {
            matches!(
                credential.state,
                CredentialStateEnum::Accepted
                    | CredentialStateEnum::Revoked
                    | CredentialStateEnum::Suspended
            ) && credential.role == CredentialRole::Holder
        });

        let match_result = first_applicable_claim_set(&credential_candidates, credential_filters)?;
        relevant_credentials.append(&mut credential_candidates);
        requested_credentials.push(to_requested_credential(query, match_result)?)
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

fn format_matches(dcql_format: &CredentialFormat, format: &str, config: &CoreConfig) -> bool {
    let Some(credential_format) = config
        .format
        .get_fields(format)
        .ok()
        .map(|field| field.r#type)
    else {
        return false;
    };
    match dcql_format {
        CredentialFormat::JwtVc => credential_format == FormatType::Jwt,
        CredentialFormat::LdpVc => {
            credential_format == FormatType::JsonLdBbsPlus
                || credential_format == FormatType::JsonLdClassic
        }
        CredentialFormat::MsoMdoc => credential_format == FormatType::Mdoc,
        CredentialFormat::SdJwt => credential_format == FormatType::SdJwtVc,
        CredentialFormat::W3cSdJwt => credential_format == FormatType::SdJwt,
    }
}

fn to_requested_credential(
    query: CredentialQuery,
    match_result: ClaimSetMatchResult,
) -> Result<PresentationDefinitionRequestedCredentialResponseDTO, VerificationProtocolError> {
    let mut fields = vec![];
    for (claim_path, claim_to_credentials) in match_result.claims_to_credentials {
        let selective_disclosure_supported = claim_to_credentials.selective_disclosure_supported;
        let key_map = claim_to_credentials
            .credentials
            .into_iter()
            .map(|id| (id, claim_path.clone()))
            .collect();
        let required = if selective_disclosure_supported {
            claim_to_credentials.required_by_verifier
        } else {
            // Everything is "required" (i.e. will be revealed) if selective disclosure is not
            // supported.
            true
        };
        let field = PresentationDefinitionFieldDTO {
            id: format!("{}:{}", query.id, claim_path),
            name: Some(claim_path.clone()),
            purpose: None,
            required: Some(required),
            key_map,
        };
        fields.push(field);
    }
    Ok(PresentationDefinitionRequestedCredentialResponseDTO {
        id: query.id.to_string(),
        name: None,
        purpose: None,
        fields,
        applicable_credentials: match_result.applicable_credentials,
        inapplicable_credentials: match_result.inapplicable_credentials,
        validity_credential_nbf: None,
    })
}

struct ClaimSetMatchResult {
    claims_to_credentials: HashMap<String, ClaimToCredentials>,
    applicable_credentials: Vec<CredentialId>,
    inapplicable_credentials: Vec<CredentialId>,
}

struct ClaimToCredentials {
    // all credentials that have this claim
    credentials: Vec<CredentialId>,
    // Whether selectively disclosing this claim is supported by _all_ applicable credentials
    selective_disclosure_supported: bool,
    required_by_verifier: bool,
}

fn first_applicable_claim_set(
    credentials: &[Credential],
    filters: &[CredentialFilter],
) -> Result<ClaimSetMatchResult, VerificationProtocolError> {
    let mut claims_to_credentials = HashMap::new();
    let mut applicable_credentials = vec![];
    let mut inapplicable_credentials = vec![];
    // match each credential against the particular filter / claim set
    for credential in credentials {
        if !matches!(credential.state, CredentialStateEnum::Accepted) {
            inapplicable_credentials.push(credential.id);
            continue;
        }
        // Go through the filters and find the first that matches some claims, if any.
        let Some(selected_claims) = filters
            .iter()
            .filter_map(|filter| select_claims(credential, filter).transpose())
            .next()
            .transpose()?
        else {
            // the current credential is not applicable for any of the filters
            // -> mark inapplicable and continue
            inapplicable_credentials.push(credential.id);
            continue;
        };

        // The current credential matched. Arrange the claims by path so that it is easier
        // to later build the `field.keyMap`.
        applicable_credentials.push(credential.id);
        for selected_claim in selected_claims {
            let sd_supported = selected_claim.selective_disclosure_supported;
            claims_to_credentials
                .entry(selected_claim.key)
                .and_modify(|claim_to_creds: &mut ClaimToCredentials| {
                    claim_to_creds.credentials.push(credential.id);
                    claim_to_creds.selective_disclosure_supported =
                        claim_to_creds.selective_disclosure_supported && sd_supported;
                })
                .or_insert(ClaimToCredentials {
                    selective_disclosure_supported: sd_supported,
                    credentials: vec![credential.id],
                    required_by_verifier: selected_claim.required_by_verifier,
                });
        }
    }

    if !applicable_credentials.is_empty() {
        return Ok(ClaimSetMatchResult {
            claims_to_credentials,
            applicable_credentials,
            inapplicable_credentials,
        });
    }

    // We have exhausted all options / claim sets and never found any matching credential.
    // -> build the match result so that it explains which fields we were looking for that didn't
    // match any credentials.
    Ok(ClaimSetMatchResult {
        claims_to_credentials: filters
            // Presumably the last option has the lowest requirements (as it is the least preferred by verifiers).
            // Let's use that as the minimum requirement the credentials in the wallet failed to match.
            .last()
            .iter()
            .flat_map(|filter| filter.claims.iter().map(|claim| (claim, &filter.format)))
            .filter(|(claim, _)| claim.required)
            .map(|(claim, format)| {
                (
                    dcql_path_to_absent_claim_key(&claim.path, format),
                    ClaimToCredentials {
                        credentials: vec![],
                        // the empty set of credentials is always selectively disclosable
                        selective_disclosure_supported: true,
                        required_by_verifier: true,
                    },
                )
            })
            .collect(),
        // empty
        applicable_credentials,
        // all credential candidates
        inapplicable_credentials,
    })
}

#[derive(PartialEq, Eq, Hash)]
struct SelectedClaim {
    key: String,
    selective_disclosure_supported: bool,
    required_by_verifier: bool,
}

fn select_claims(
    credential: &Credential,
    filter: &CredentialFilter,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    let Some(claims) = &credential.claims else {
        return Err(VerificationProtocolError::Failed(format!(
            "credential {} missing claims",
            credential.id
        )));
    };

    let mut result = HashMap::new();
    // add all nonselectively disclosable claims defined from root
    {
        let root_nonselectively_disclosable: Vec<_> = claims
            .iter()
            .filter(|claim| !claim.selectively_disclosable)
            .filter(|claim| !claim.path.contains("/"))
            .collect();

        // children of the root nonselectively disclosable that are also not selectively disclosable
        let nonselectively_disclosable_children_of_root = get_nonselectively_disclosable_children(
            claims,
            root_nonselectively_disclosable
                .iter()
                .map(|claim| claim.path.as_str())
                .collect::<Vec<_>>(),
        );

        let nonselectively_disclosable = root_nonselectively_disclosable
            .iter()
            .chain(nonselectively_disclosable_children_of_root.iter());

        result.extend(nonselectively_disclosable.map(|claim| {
            (
                claim.path.to_owned(),
                SelectedClaim {
                    key: claim.path.to_owned(),
                    selective_disclosure_supported: claim.selectively_disclosable,
                    required_by_verifier: false,
                },
            )
        }));
    }

    // add claims requested by the verifier
    for claim_filter in &filter.claims {
        let matching_claims = get_matching_claims(claims, claim_filter, &filter.format)?;
        if !matching_claims.is_empty() {
            matching_claims.into_iter().for_each(|matching_claim| {
                if let Some(claim) = result.get_mut(&matching_claim.path) {
                    claim.required_by_verifier =
                        claim.required_by_verifier || claim_filter.required;
                } else {
                    result.insert(
                        matching_claim.path.to_owned(),
                        SelectedClaim {
                            key: matching_claim.path.to_owned(),
                            selective_disclosure_supported: matching_claim.selectively_disclosable,
                            required_by_verifier: claim_filter.required,
                        },
                    );
                }
            });
        } else if claim_filter.required {
            // no match but claim is required --> abort as not matching
            return Ok(None);
        }
    }

    Ok(Some(result.into_values().collect()))
}

fn get_matching_claims<'a>(
    claims: &'a [Claim],
    claim_filter: &ClaimFilter,
    format: &CredentialFormat,
) -> Result<HashSet<&'a Claim>, VerificationProtocolError> {
    let values_filter = claim_filter
        .values
        .iter()
        .map(stringify_value)
        .collect::<Vec<_>>();

    let filtered_claims: Vec<_> = claims
        .iter()
        // use filter_map to propagate errors of fallible predicate
        .filter_map(|claim| {
            dcql_path_exactly_matches_claim_key(&claim_filter.path, &claim.path, claims, format)
                .map(|matches| {
                    if matches
                        && (values_filter.is_empty()
                            || claim
                                .value
                                .as_ref()
                                .is_some_and(|value| values_filter.contains(value)))
                    {
                        Some(claim)
                    } else {
                        None
                    }
                })
                .transpose()
        })
        .collect::<Result<_, _>>()?;

    if filtered_claims.is_empty() {
        // no matches found, return empty result
        return Ok(HashSet::new());
    }

    // "trunk" nodes on the path from root to the filtered_claims
    // all of these are either arrays or objects
    let mut claims_towards_root = HashSet::<&Claim>::new();
    filtered_claims.iter().try_for_each(|claim| {
        let mut current_path = claim.path.as_str();
        while let Some((parent_path, _)) = current_path.rsplit_once('/') {
            let parent_claim = claims
                .iter()
                .find(|claim| claim.path == parent_path)
                .ok_or(VerificationProtocolError::Failed(format!(
                    "Missing claim with path '{parent_path}' (parent of claim {}).",
                    claim.id
                )))?;
            claims_towards_root.insert(parent_claim);
            current_path = parent_path;
        }
        Ok(())
    })?;

    // branches of nodes that are not selectively disclosable
    let nonselectively_disclosable_children = get_nonselectively_disclosable_children(
        claims,
        claims_towards_root.iter().map(|claim| claim.path.as_str()),
    );

    let mut combined_set = HashSet::new();
    combined_set.extend(filtered_claims);
    combined_set.extend(claims_towards_root);
    combined_set.extend(nonselectively_disclosable_children);
    Ok(combined_set)
}

fn get_nonselectively_disclosable_children<'a, 'b>(
    all_claims: &'a [Claim],
    of_parent_paths: impl IntoIterator<Item = &'b str>,
) -> Vec<&'a Claim> {
    let mut result = vec![];

    let mut parent_paths = VecDeque::from_iter(of_parent_paths);
    loop {
        let Some(parent_path) = parent_paths.pop_front() else {
            break;
        };

        let nonselectively_disclosable_children = all_claims
            .iter()
            .filter(|claim| !claim.selectively_disclosable)
            .filter(|claim| {
                claim
                    .path
                    .rsplit_once("/")
                    .is_some_and(|(prefix, _)| prefix == parent_path)
            });

        for child in nonselectively_disclosable_children {
            parent_paths.push_back(child.path.as_str());
            result.push(child);
        }
    }

    result
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
            CredentialFormat::JwtVc | CredentialFormat::LdpVc | CredentialFormat::W3cSdJwt => {
                schema_id
                    // Make use of the fact that Procivis One issuers put the schema id into the context,
                    // hence we can potentially parse it out of the supplied types.
                    // Note: This will most likely fail with third party issuers. Improve the logic,
                    // once we need to interop with such issuers.
                    .split_once("#")
                    .map(|(first, _)| first)
                    .unwrap_or(schema_id)
            }
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

/// Predicate that checks if the DCQL path matches the claim path exactly, as in
/// it addresses the claim directly (and not a child claim).
fn dcql_path_exactly_matches_claim_key(
    dcql_path: &ClaimPath,
    claim_path: &str,
    claims: &[Claim],
    format: &CredentialFormat,
) -> Result<bool, VerificationProtocolError> {
    let dcql_segments = adjust_dcql_path_for_format(dcql_path, format);
    let claim_path_segments = claim_path.split('/').collect::<Vec<_>>();
    if dcql_segments.len() != claim_path_segments.len() {
        // nesting depth mismatch -> no match
        return Ok(false);
    }

    let mut current_path = "".to_string();
    for (dcql_path_segment, claim_path_segment) in
        dcql_segments.into_iter().zip(claim_path.split('/'))
    {
        current_path = if current_path.is_empty() {
            claim_path_segment.to_string()
        } else {
            format!("{current_path}/{claim_path_segment}")
        };
        let schema = claims
            .iter()
            .find(|claim| claim.path == current_path)
            .and_then(|claim| claim.schema.as_ref())
            .ok_or(VerificationProtocolError::Failed(format!(
                "missing schema for claim with path '{current_path}'"
            )))?;
        match dcql_path_segment {
            PathSegment::PropertyName(name) => {
                if name != claim_path_segment {
                    // wrong property name -> no match
                    return Ok(false);
                }
            }
            PathSegment::ArrayIndex(index) => {
                if !schema.array {
                    // property is not an array -> no match
                    return Ok(false);
                }
                if index.to_string() != claim_path_segment {
                    // wrong index -> no match
                    return Ok(false);
                }
            }
            PathSegment::ArrayAll => {
                if !schema.array {
                    // property is not an array -> no match
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn dcql_path_to_absent_claim_key(path: &ClaimPath, format: &CredentialFormat) -> String {
    let segments_iter = adjust_dcql_path_for_format(path, format);
    segments_iter
        .into_iter()
        .map(|segment| {
            match segment {
                PathSegment::PropertyName(name) => name.to_owned(),
                PathSegment::ArrayIndex(index) => index.to_string(),
                // We need to show the claim path of claims that are missing,
                // -> substituting array index 0 to convey the "at least one element" semantics.
                PathSegment::ArrayAll => "0".to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn adjust_dcql_path_for_format<'a>(
    path: &'a ClaimPath,
    format: &CredentialFormat,
) -> Vec<&'a PathSegment> {
    let mut segments_iter = path.segments.iter().peekable();
    match format {
        CredentialFormat::JwtVc | CredentialFormat::LdpVc | CredentialFormat::W3cSdJwt => {
            // skip the credentialSubject for W3C credentials
            segments_iter
                .next_if(|val| *val == &PathSegment::PropertyName("credentialSubject".to_string()));
        }
        CredentialFormat::MsoMdoc | CredentialFormat::SdJwt => {
            // nothing to do
        }
    }
    segments_iter.collect()
}

fn stringify_value(value: &ClaimValue) -> String {
    match value {
        ClaimValue::String(string) => string.to_string(),
        ClaimValue::Integer(int) => format!("{int}"),
        ClaimValue::Boolean(bool) => format!("{bool}"),
    }
}

impl From<FormatType> for CredentialFormat {
    fn from(value: FormatType) -> Self {
        match value {
            FormatType::Jwt => CredentialFormat::JwtVc,
            FormatType::PhysicalCard => CredentialFormat::LdpVc,
            FormatType::SdJwt => CredentialFormat::W3cSdJwt,
            FormatType::SdJwtVc => CredentialFormat::SdJwt,
            FormatType::JsonLdClassic => CredentialFormat::LdpVc,
            FormatType::JsonLdBbsPlus => CredentialFormat::LdpVc,
            FormatType::Mdoc => CredentialFormat::MsoMdoc,
        }
    }
}
