use std::collections::HashMap;

use dcql::matching::CredentialFilter;
use dcql::{ClaimPath, CredentialFormat, CredentialQuery, DcqlQuery, PathSegment};
use shared_types::{CredentialId, OrganisationId};

use crate::config::core_config::CoreConfig;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchema;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
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
///   - Misleading requested credential `fields` array when `claims` is absent: The mapping to
///     presentation definition assumes that _all_ claims are selectively disclosable, which is not
///     generally true for third-party credentials. This might result in UI components showing too
///     little data being disclosed on proof requests.
///   - Misleading requested credential `fields` `required` flag when credentials with different schemas are queried
///     simultaneously and where only some credential schemas support selective disclosure (this is only possible for W3C VCs):
///     Since there is only one required flag per field, the required flag will be set to `true` if the field is present in
///     at least one credential where the field is not selectively disclosable even if it would be optional given the DCQL
///     query, and it would be selectively disclosable for other credentials.
pub(crate) async fn get_presentation_definition_for_dcql_query(
    dcql_query: DcqlQuery,
    proof: &Proof,
    storage_access: &StorageAccess,
    config: &CoreConfig,
    formatter_provider: &dyn CredentialFormatterProvider,
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

        let match_result = first_applicable_claim_set(
            &credential_candidates,
            credential_filters,
            formatter_provider,
        )?;
        relevant_credentials.append(&mut credential_candidates);
        requested_credentials.push(to_requested_credential(query, match_result))
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
    match_result: ClaimSetMatchResult,
) -> PresentationDefinitionRequestedCredentialResponseDTO {
    let mut fields = vec![];
    for (claim_path, claim_to_credentials) in match_result.claims_to_credentials {
        let selective_disclosure_supported = claim_to_credentials.selective_disclosure_supported;
        let key_map = claim_to_credentials
            .credentials
            .into_iter()
            .map(|id| (id.to_string(), claim_path.clone()))
            .collect();
        let claim_query = query
            .claims
            .iter()
            .flatten()
            .find(|claim| dcql_path_to_claim_key(&claim.path, &query.format) == claim_path);

        // The query is absent in case `claims` was not provided in the DCQL query, or we have a
        // credential that does not support selective disclosure and more claims are revealed than
        // requested by the verifier.
        let field = if let Some(claim_query) = claim_query {
            let required = if selective_disclosure_supported {
                claim_query.required.unwrap_or(true)
            } else {
                // Everything is "required" (i.e. will be revealed) if selective disclosure is not
                // supported.
                true
            };
            PresentationDefinitionFieldDTO {
                id: claim_query
                    .id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or(claim_path.clone()),
                name: Some(claim_path.clone()),
                purpose: None,
                required: Some(required),
                key_map,
            }
        } else {
            PresentationDefinitionFieldDTO {
                id: claim_path.clone(),
                name: Some(claim_path.clone()),
                purpose: None,
                // Required if selective disclosure is _not_ supported
                required: Some(!selective_disclosure_supported),
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
        applicable_credentials: match_result.applicable_credentials,
        inapplicable_credentials: match_result.inapplicable_credentials,
        validity_credential_nbf: None,
    }
}

struct ClaimSetMatchResult {
    claims_to_credentials: HashMap<String, ClaimToCredentials>,
    applicable_credentials: Vec<String>,
    inapplicable_credentials: Vec<String>,
}

struct ClaimToCredentials {
    // all credentials that have this claim
    credentials: Vec<CredentialId>,
    // Whether selectively disclosing this claim is supported by _all_ applicable credentials
    selective_disclosure_supported: bool,
}

fn first_applicable_claim_set(
    credentials: &[Credential],
    filters: &[CredentialFilter],
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<ClaimSetMatchResult, VerificationProtocolError> {
    // Try to find at least one credential matching for each credential filter
    // The filters are ordered by verifier preference. The number of filters corresponds
    // to the number of entries in `claim_sets` for the current credential query.
    for filter in filters {
        let mut claim_to_credentials = HashMap::new();
        let mut applicable_credentials = vec![];
        let mut inapplicable_credentials = vec![];

        // match each credential against the particular filter / claim set
        for credential in credentials {
            let selected_claims = select_claims(credential, filter, formatter_provider)?;

            if let Some(selected_claims) = selected_claims {
                applicable_credentials.push(credential.id.to_string());
                // The current credential matched. Arrange them by path so that it is easier
                // to later build the `field.keyMap`.
                for selected_claim in selected_claims {
                    let sd_supported = selected_claim.selective_disclosure_supported;
                    claim_to_credentials
                        .entry(selected_claim.key)
                        .and_modify(|claim_to_creds: &mut ClaimToCredentials| {
                            claim_to_creds.credentials.push(credential.id);
                            claim_to_creds.selective_disclosure_supported =
                                claim_to_creds.selective_disclosure_supported && sd_supported;
                        })
                        .or_insert(ClaimToCredentials {
                            selective_disclosure_supported: sd_supported,
                            credentials: vec![credential.id],
                        });
                }
            } else {
                // the current credential is not applicable given the current claim set
                inapplicable_credentials.push(credential.id.to_string());
            }
        }

        // If we have at least one match, we can stop and use that claim set.
        // Otherwise, we need to continue searching for matches using the next claim set.
        if !applicable_credentials.is_empty() {
            return Ok(ClaimSetMatchResult {
                claims_to_credentials: claim_to_credentials,
                applicable_credentials,
                inapplicable_credentials,
            });
        }
    }

    // We have exhausted all options / claim sets and never found any credential matching.
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
                    dcql_path_to_claim_key(&claim.path, format),
                    ClaimToCredentials {
                        credentials: vec![],
                        // the empty set of credentials is always selectively disclosable
                        selective_disclosure_supported: true,
                    },
                )
            })
            .collect(),
        applicable_credentials: vec![],
        inapplicable_credentials: credentials
            .iter()
            .map(|credential| credential.id.to_string())
            .collect(),
    })
}

struct SelectedClaim {
    key: String,
    selective_disclosure_supported: bool,
}

fn select_claims(
    credential: &Credential,
    filter: &CredentialFilter,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    let Some(claims) = &credential.claims else {
        return Err(VerificationProtocolError::Failed(format!(
            "credential {} has no claims",
            credential.id
        )));
    };

    // Credentials could have the different schemas and not each credential of the same schema
    // necessarily needs to have the same claims selectively disclosable.
    // Given the info on a per-claim basis is not available at least each credential is checked
    // individually whether it's format supports selective disclosure.
    // TODO: We should improve the SD support flag be on a per-claim basis.
    let credential_schema = credential
        .schema
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(format!(
            "missing credential schema for credential {}",
            credential.id
        )))?;

    // The format does _not_ support selective disclosure, so we are forced to reveal _all_ claims.
    if !selective_disclosure_supported(credential_schema, formatter_provider)? {
        let all_claims = credential
            .claims
            .iter()
            .flatten()
            .map(|claim| SelectedClaim {
                key: claim.path.to_string(),
                selective_disclosure_supported: false,
            })
            .collect();
        return Ok(Some(all_claims));
    }

    // The format _does_ support selective disclosure and no claims were requested, hence we show
    // nothing at all.
    if claims.is_empty() {
        return Ok(Some(vec![]));
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
        let path_prefix = dcql_path_to_claim_key(&claim_filter.path, &filter.format);
        if claims
            .iter()
            .any(|claim| claim.path.starts_with(&path_prefix))
        {
            result.push(SelectedClaim {
                key: path_prefix,
                // If the format supports it in general, we assume SD is possible for all claims.
                // TODO: actually fill this in accurately based on the given credential
                selective_disclosure_supported: true,
            });
        } else if claim_filter.required {
            // no match but claim is required --> abort as not matching
            return Ok(None);
        }
    }
    Ok(Some(result))
}

fn selective_disclosure_supported(
    schema: &CredentialSchema,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<bool, VerificationProtocolError> {
    let formatter_capabilities = formatter_provider
        .get_credential_formatter(&schema.format)
        .ok_or(VerificationProtocolError::Failed(format!(
            "missing credential formatter for credential format {}",
            schema.format
        )))?
        .get_capabilities();
    Ok(!formatter_capabilities.selective_disclosure.is_empty())
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

fn dcql_path_to_claim_key(path: &ClaimPath, format: &CredentialFormat) -> String {
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

    segments_iter
        .map(ToString::to_string)
        // remove the quotes around strings
        .map(|s| s.replace("\"", ""))
        .collect::<Vec<_>>()
        .join("/")
}
