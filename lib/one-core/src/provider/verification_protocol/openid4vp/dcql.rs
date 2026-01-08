use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use dcql::matching::{ClaimFilter, CredentialFilter};
use dcql::{
    ClaimPath, ClaimValue, CredentialFormat, CredentialQuery, DcqlQuery, PathSegment,
    TrustedAuthority,
};
use itertools::Itertools;
use one_dto_mapper::{convert_inner, try_convert_inner};
use shared_types::{CredentialId, OrganisationId};
use time::OffsetDateTime;

use crate::config::core_config::{CoreConfig, FormatType};
use crate::mapper::credential_schema_claim::claim_schema_from_metadata_claim_schema;
use crate::model::claim::Claim;
use crate::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::model::proof::Proof;
use crate::proto::openid4vp_proof_validator::validator::get_trusted_akis;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::verification_protocol::dto::{
    ApplicableCredentialOrFailureHintEnum, CredentialDetailClaimExtResponseDTO,
    CredentialQueryFailureHintResponseDTO, CredentialQueryFailureReasonEnum,
    CredentialQueryResponseDTO, CredentialSetResponseDTO, PresentationDefinitionFieldDTO,
    PresentationDefinitionRequestGroupResponseDTO,
    PresentationDefinitionRequestedCredentialResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
    PresentationDefinitionV2ResponseDTO,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::mapper::credential_model_to_credential_dto;
use crate::service::credential::dto::{
    CredentialAttestationBlobs, CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::credential_schema::dto::CredentialSchemaDetailResponseDTO;
use crate::service::storage_proxy::StorageAccess;
use crate::util::authority_key_identifier::{AuthorityKeyIdentifier, get_akis_for_pem_chain};

/// Retrieve the "presentation definition" for the given DCQL query.
///
/// Limitations:
///   - No DCQL support for:
///     - credential_sets
///   - Some metadata claims such as `@context` or `_sd` cannot be queried
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
    credential_formatter_provider: &dyn CredentialFormatterProvider,
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
        // required, etc. but so far this was not a problem so it is not optimized.
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

        if let Some(authorities) = &query.trusted_authorities {
            filter_credentials_by_trusted_authorities(
                &mut credential_candidates,
                authorities.as_slice(),
            )
            .await;
        }

        let match_result = first_applicable_claim_set(
            &credential_candidates,
            credential_filters,
            credential_formatter_provider,
            config,
        )?;
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

pub(crate) async fn get_presentation_definition_v2(
    dcql_query: DcqlQuery,
    proof: &Proof,
    storage_access: &StorageAccess,
    formatter_provider: &dyn CredentialFormatterProvider,
    config: &CoreConfig,
) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
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

    let mut credential_queries = HashMap::new();
    let credential_sets = if let Some(credential_sets) = dcql_query.credential_sets {
        convert_inner(credential_sets)
    } else {
        dcql_query
            .credentials
            .iter()
            .map(|query| CredentialSetResponseDTO {
                required: true,
                options: vec![vec![query.id.to_string()]],
            })
            .collect()
    };

    for query in dcql_query.credentials {
        let credential_filters =
            query_to_filters
                .get(&query.id)
                .ok_or(VerificationProtocolError::Failed(format!(
                    "missing credential filters for credential query with id {}",
                    query.id
                )))?;

        // This is very inefficient. We would have the information here to also filter by the claims
        // required, etc. but so far this was not a problem so it is not optimized.
        let mut credential_candidates =
            fetch_credentials_for_schema_ids(storage_access, organisation.id, credential_filters)
                .await?;

        credential_candidates.retain(|credential| {
            let Some(schema) = &credential.schema else {
                return false;
            };
            format_matches(&query.format, &schema.format, config)
                && credential.role == CredentialRole::Holder
        });

        if credential_candidates.is_empty() {
            let schema_ids = credential_filters
                .iter()
                .flat_map(|filter| {
                    filter
                        .schema_ids
                        .iter()
                        .map(|schema_id| map_schema_id(filter, schema_id))
                })
                .collect::<Vec<_>>();
            let credential_schema = storage_access
                .find_schema_by_schema_ids(&schema_ids, organisation.id)
                .await
                .map_err(VerificationProtocolError::StorageAccessError)?;
            let credential_schema = try_convert_inner(credential_schema).map_err(|err| {
                VerificationProtocolError::Failed(format!("Failed to map credential schema: {err}"))
            })?;
            credential_queries.insert(
                query.id.to_string(),
                failure_hint(
                    &query,
                    CredentialQueryFailureReasonEnum::NoCredential,
                    credential_schema,
                )?,
            );
            // done with this query
            continue;
        }

        let (candidates, invalid_credentials): (Vec<_>, Vec<_>) = credential_candidates
            .into_iter()
            .partition(|credential| credential.state == CredentialStateEnum::Accepted);
        if candidates.is_empty() {
            let credential_schema = try_convert_inner(
                invalid_credentials
                    .into_iter()
                    .next()
                    .and_then(|cred| cred.schema),
            )
            .map_err(|err| {
                VerificationProtocolError::Failed(format!("Failed to map credential schema: {err}"))
            })?;
            credential_queries.insert(
                query.id.to_string(),
                failure_hint(
                    &query,
                    CredentialQueryFailureReasonEnum::Validity,
                    credential_schema,
                )?,
            );
            // done with this query
            continue;
        }

        // if none of the candidates is applicable, use this schema for the failure hint.
        let failure_hint_schema = candidates.first().and_then(|cred| cred.schema.clone());
        let mut applicable_credentials = vec![];
        for candidate in candidates {
            let format = &candidate
                .schema
                .as_ref()
                .ok_or(VerificationProtocolError::Failed(format!(
                    "missing schema for credential {}",
                    candidate.id
                )))?
                .format;
            let formatter = formatter_provider.get_credential_formatter(format).ok_or(
                VerificationProtocolError::Failed(format!(
                    "missing formatter for credential format {format}",
                )),
            )?;

            let claims = first_matching_claims(&candidate, credential_filters, &*formatter)?;
            let Some(claims) = claims else {
                continue;
            };
            let credential_detail_dto = credential_detail_response_from_model(
                candidate,
                config,
                None,
                CredentialAttestationBlobs::default(),
            )
            .map_err(|err| {
                VerificationProtocolError::Failed(format!("Failed to map credential to DTO: {err}"))
            })?;
            applicable_credentials.push(map_to_filtered_dto(credential_detail_dto, &claims));
        }
        if applicable_credentials.is_empty() {
            credential_queries.insert(
                query.id.to_string(),
                failure_hint(
                    &query,
                    CredentialQueryFailureReasonEnum::Constraint,
                    try_convert_inner(failure_hint_schema).map_err(|err| {
                        VerificationProtocolError::Failed(format!(
                            "Failed to map credential schema: {err}"
                        ))
                    })?,
                )?,
            );
        } else {
            credential_queries.insert(
                query.id.to_string(),
                CredentialQueryResponseDTO {
                    multiple: query.multiple,
                    credential_or_failure_hint:
                        ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                            applicable_credentials,
                        },
                },
            );
        }
    }
    Ok(PresentationDefinitionV2ResponseDTO {
        credential_queries,
        credential_sets,
    })
}

pub(super) async fn filter_credentials_by_trusted_authorities(
    credentials: &mut Vec<Credential>,
    authorities: &[TrustedAuthority],
) {
    // Bail out early if credential set is empty
    if credentials.is_empty() {
        return;
    }

    let trusted_akis = get_trusted_akis(authorities);
    credentials.retain(|cred| credential_issuer_in_aki_list(cred, trusted_akis.as_slice()));
}

fn credential_issuer_in_aki_list(credential: &Credential, list: &[AuthorityKeyIdentifier]) -> bool {
    let Some(issuer_cert) = credential.issuer_certificate.as_ref() else {
        return false;
    };

    let Ok(issuer_akis) = get_akis_for_pem_chain(issuer_cert.chain.as_bytes()) else {
        return false;
    };

    for issuer_aki in issuer_akis {
        for aki in list {
            if issuer_aki == *aki {
                return true;
            }
        }
    }

    false
}

fn failure_hint(
    query: &CredentialQuery,
    reason: CredentialQueryFailureReasonEnum,
    credential_schema: Option<CredentialSchemaDetailResponseDTO>,
) -> Result<CredentialQueryResponseDTO, VerificationProtocolError> {
    Ok(CredentialQueryResponseDTO {
        multiple: query.multiple,
        credential_or_failure_hint: ApplicableCredentialOrFailureHintEnum::FailureHint {
            failure_hint: Box::new(CredentialQueryFailureHintResponseDTO {
                reason,
                credential_schema,
            }),
        },
    })
}

fn map_to_filtered_dto(
    full_dto: CredentialDetailResponseDTO<DetailCredentialClaimResponseDTO>,
    selected_claims: &[SelectedClaim],
) -> CredentialDetailResponseDTO<CredentialDetailClaimExtResponseDTO> {
    let selected_claims_by_path = selected_claims
        .iter()
        .map(|claim| (claim.path.to_owned(), claim))
        .collect::<HashMap<_, _>>();

    CredentialDetailResponseDTO {
        id: full_dto.id,
        created_date: full_dto.created_date,
        issuance_date: full_dto.issuance_date,
        revocation_date: full_dto.revocation_date,
        state: full_dto.state,
        last_modified: full_dto.last_modified,
        schema: full_dto.schema,
        issuer: full_dto.issuer,
        issuer_certificate: full_dto.issuer_certificate,
        claims: full_dto
            .claims
            .into_iter()
            .filter_map(|claim| to_claim_detail_ext_filtered(claim, &selected_claims_by_path))
            .collect(),
        redirect_uri: full_dto.redirect_uri,
        role: full_dto.role,
        lvvc_issuance_date: full_dto.lvvc_issuance_date,
        suspend_end_date: full_dto.suspend_end_date,
        mdoc_mso_validity: full_dto.mdoc_mso_validity,
        holder: full_dto.holder,
        protocol: full_dto.protocol,
        profile: full_dto.profile,
        wallet_app_attestation: None,
        wallet_unit_attestation: None,
    }
}

fn to_claim_detail_ext_filtered(
    claim: DetailCredentialClaimResponseDTO,
    all_selected_claims: &HashMap<String, &SelectedClaim>,
) -> Option<CredentialDetailClaimExtResponseDTO> {
    // exit early if not in filter list
    let selected_claim = all_selected_claims.get(&claim.path)?;

    // value mapping
    let value = match claim.value {
        DetailCredentialClaimValueResponseDTO::Boolean(val) => {
            DetailCredentialClaimValueResponseDTO::Boolean(val)
        }
        DetailCredentialClaimValueResponseDTO::Float(val) => {
            DetailCredentialClaimValueResponseDTO::Float(val)
        }
        DetailCredentialClaimValueResponseDTO::Integer(val) => {
            DetailCredentialClaimValueResponseDTO::Integer(val)
        }
        DetailCredentialClaimValueResponseDTO::String(val) => {
            DetailCredentialClaimValueResponseDTO::String(val)
        }
        DetailCredentialClaimValueResponseDTO::Nested(children) => {
            let mapped_children = children
                .into_iter()
                .filter_map(|child| to_claim_detail_ext_filtered(child, all_selected_claims))
                .collect::<Vec<_>>();
            if mapped_children.is_empty() {
                return None;
            }
            DetailCredentialClaimValueResponseDTO::Nested(mapped_children)
        }
    };
    Some(CredentialDetailClaimExtResponseDTO {
        path: claim.path,
        schema: claim.schema,
        value,
        user_selection: selected_claim.user_selection,
        required: !selected_claim.selective_disclosure_supported
            || selected_claim.required_by_verifier,
    })
}

fn first_matching_claims(
    credential: &Credential,
    filters: &[CredentialFilter],
    formatter: &dyn CredentialFormatter,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    for filter in filters {
        let claims = select_matching_claims(credential, filter, formatter)?;
        let Some(claims) = claims else {
            continue;
        };
        return Ok(Some(claims));
    }
    Ok(None)
}

fn format_matches(
    dcql_format: &CredentialFormat,
    format: &shared_types::CredentialFormat,
    config: &CoreConfig,
) -> bool {
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
        multiple: query.multiple.then_some(true),
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
    formatter_provider: &dyn CredentialFormatterProvider,
    config: &CoreConfig,
) -> Result<ClaimSetMatchResult, VerificationProtocolError> {
    if credentials.is_empty() {
        // no local candidates available
        // build the match result so that it explains which fields we were looking for that didn't match any credentials.
        return Ok(ClaimSetMatchResult {
            claims_to_credentials: filters
                // Presumably the last option has the lowest requirements (as it is the least preferred by verifiers).
                // Let's use that as the minimum requirement the credentials in the wallet failed to match.
                .last()
                .iter()
                .flat_map(|filter| filter.claims.iter().map(|claim| (claim, &filter.format)))
                .filter(|(claim, _)| claim.required)
                .filter_map(|(claim, format)| {
                    let result = formatter_for_dcql_format(format, config, formatter_provider);
                    let formatter = match result {
                        Ok(formatter) => formatter,
                        Err(err) => return Some(Err(err)),
                    };
                    let user_claim_path = formatter.user_claims_path();
                    if dcql_path_matches_metadata(
                        &claim.path,
                        &formatter
                            .get_metadata_claims()
                            .into_iter()
                            .map(|metadata| {
                                claim_schema_from_metadata_claim_schema(
                                    metadata,
                                    OffsetDateTime::now_utc(),
                                )
                            })
                            .collect::<Vec<_>>(),
                        &user_claim_path,
                    ) {
                        // filter out absent metadata claims
                        return None;
                    }
                    let result = dcql_path_to_absent_claim_key(&claim.path, &user_claim_path);
                    let claim_key = match result {
                        Ok(claim_key) => claim_key,
                        Err(err) => return Some(Err(err)),
                    };
                    Some(Ok((
                        claim_key,
                        ClaimToCredentials {
                            credentials: vec![],
                            // the empty set of credentials is always selectively disclosable
                            selective_disclosure_supported: true,
                            required_by_verifier: true,
                        },
                    )))
                })
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect(),
            // empty
            applicable_credentials: vec![],
            inapplicable_credentials: vec![],
        });
    }

    let mut claims_to_credentials = HashMap::new();
    let mut applicable_credentials = vec![];
    let mut inapplicable_credentials = vec![];

    // match each credential against the particular filter / claim set
    for credential in credentials {
        let mut applicable = false;
        let mut matched_claims = vec![];

        let format = &credential
            .schema
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(format!(
                "missing schema for credential {}",
                credential.id
            )))?
            .format;
        let formatter = formatter_provider.get_credential_formatter(format).ok_or(
            VerificationProtocolError::Failed(format!(
                "missing formatter for credential format {format}",
            )),
        )?;

        // Go through the filters and find the first that matches some claims, if any.
        for filter in filters {
            let claims = select_claims(credential, filter, &*formatter, false)?;

            let credential_applicable = !claims
                .iter()
                .any(|c| matches!(c, MatchedClaim::Missing { .. }));
            if credential_applicable {
                matched_claims = claims;
                applicable = true;
                break;
            }

            // for inapplicable credentials remember the first filter result
            if matched_claims.is_empty() {
                matched_claims = claims;
            }
        }

        if !matches!(credential.state, CredentialStateEnum::Accepted) {
            applicable = false;
        }

        if applicable {
            applicable_credentials.push(credential.id);
        } else {
            inapplicable_credentials.push(credential.id);
        }

        // filter out metadata to not expose it in the keyMaps
        for matched_claim in matched_claims.into_iter().filter(|claim| !match claim {
            MatchedClaim::Selected(c) => c.metadata,
            MatchedClaim::Missing { metadata, .. } => *metadata,
        }) {
            match matched_claim {
                MatchedClaim::Selected(selected_claim) => {
                    let sd_supported = selected_claim.selective_disclosure_supported;
                    claims_to_credentials
                        .entry(selected_claim.path)
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
                MatchedClaim::Missing { path, .. } => {
                    let user_claim_path = formatter.user_claims_path();
                    claims_to_credentials
                        .entry(dcql_path_to_absent_claim_key(&path, &user_claim_path)?)
                        .or_insert(ClaimToCredentials {
                            credentials: vec![],
                            // the empty set of credentials is always selectively disclosable
                            selective_disclosure_supported: true,
                            required_by_verifier: true,
                        });
                }
            };
        }
    }

    Ok(ClaimSetMatchResult {
        claims_to_credentials,
        applicable_credentials,
        inapplicable_credentials,
    })
}

fn formatter_for_dcql_format(
    format: &CredentialFormat,
    config: &CoreConfig,
    formatter_provider: &dyn CredentialFormatterProvider,
) -> Result<Arc<dyn CredentialFormatter>, VerificationProtocolError> {
    let format_types = match format {
        CredentialFormat::JwtVc => vec![FormatType::Jwt],
        CredentialFormat::LdpVc => vec![FormatType::JsonLdClassic, FormatType::JsonLdBbsPlus],
        CredentialFormat::MsoMdoc => vec![FormatType::Mdoc],
        CredentialFormat::SdJwt => vec![FormatType::SdJwtVc],
        CredentialFormat::W3cSdJwt => vec![FormatType::SdJwt],
    };
    let formatter_name = format_types
        .iter()
        .flat_map(|format_type| {
            config
                .format
                .iter()
                .find(|(_, cfg)| cfg.r#type == *format_type)
        })
        .map(|(key, _)| key)
        .next()
        .ok_or(VerificationProtocolError::Failed(format!(
            "No formatter found for DCQL format {format}"
        )))?;
    formatter_provider
        .get_credential_formatter(formatter_name)
        .ok_or(VerificationProtocolError::Failed(format!(
            "No formatter found for format {formatter_name}"
        )))
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct SelectedClaim {
    path: String,
    selective_disclosure_supported: bool,
    required_by_verifier: bool,
    user_selection: bool,
    metadata: bool,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum MatchedClaim {
    Selected(SelectedClaim),
    Missing {
        path: ClaimPath,
        format: CredentialFormat,
        metadata: bool,
    },
}

fn select_matching_claims(
    credential: &Credential,
    filter: &CredentialFilter,
    formatter: &dyn CredentialFormatter,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    let claims = select_claims(credential, filter, formatter, true)?;
    let mut result = vec![];
    for claim in claims {
        match claim {
            MatchedClaim::Missing { .. } => return Ok(None), // abort as not matching on missing required claim
            MatchedClaim::Selected(selected_claim) => result.push(selected_claim),
        }
    }
    Ok(Some(result))
}

fn select_claims(
    credential: &Credential,
    filter: &CredentialFilter,
    formatter: &dyn CredentialFormatter,
    select_children: bool,
) -> Result<Vec<MatchedClaim>, VerificationProtocolError> {
    let Some(claims) = &credential.claims else {
        return Err(VerificationProtocolError::Failed(format!(
            "credential {} missing claims",
            credential.id
        )));
    };

    let mut selected = HashMap::new();
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

        selected.extend(
            nonselectively_disclosable
                .map(|claim| {
                    Ok((
                        claim.path.to_owned(),
                        SelectedClaim {
                            path: claim.path.to_owned(),
                            selective_disclosure_supported: claim.selectively_disclosable,
                            required_by_verifier: false,
                            // non-selectively disclosable claims can never be de-selected by the user
                            user_selection: false,
                            metadata: claim
                                .schema
                                .as_ref()
                                .ok_or(VerificationProtocolError::Failed(format!(
                                    "missing claim schema for claim {}",
                                    claim.id
                                )))?
                                .metadata,
                        },
                    ))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }

    let mut missing_claims = vec![];

    let credential_claim_schemas = credential
        .schema
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(format!(
            "missing schema for credential {}",
            credential.id
        )))?
        .claim_schemas
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(format!(
            "missing claim schemas for credential {}",
            credential.id
        )))?;

    let user_claim_path = formatter.user_claims_path();
    // add claims requested by the verifier
    for claim_filter in &filter.claims {
        let matching_claims =
            get_matching_claims(claims, claim_filter, &user_claim_path, select_children)?;
        if !matching_claims.is_empty() {
            matching_claims.into_iter().try_for_each(|matching_claim| {
                // All optional claims that were explicitly requested by the verifier
                // should have a toggle.
                let user_selection = matching_claim.exact && !claim_filter.required;
                if let Some(claim) = selected.get_mut(&matching_claim.claim.path) {
                    claim.required_by_verifier =
                        claim.required_by_verifier || claim_filter.required;
                    claim.user_selection = claim.user_selection || user_selection
                } else {
                    let claim = matching_claim.claim;
                    selected.insert(
                        claim.path.to_owned(),
                        SelectedClaim {
                            path: claim.path.to_owned(),
                            selective_disclosure_supported: claim.selectively_disclosable,
                            required_by_verifier: claim_filter.required,
                            user_selection,
                            metadata: claim
                                .schema
                                .as_ref()
                                .ok_or(VerificationProtocolError::Failed(format!(
                                    "missing claim schema for claim {}",
                                    claim.id
                                )))?
                                .metadata,
                        },
                    );
                };
                Ok(())
            })?;
        } else if claim_filter.required {
            // no match but claim is required --> add to missing claims (mark the credential as inapplicable)
            missing_claims.push(MatchedClaim::Missing {
                path: claim_filter.path.to_owned(),
                format: filter.format.to_owned(),
                metadata: dcql_path_matches_metadata(
                    &claim_filter.path,
                    credential_claim_schemas,
                    &formatter.user_claims_path(),
                ),
            });
        }
    }

    let mut result: Vec<MatchedClaim> =
        selected.into_values().map(MatchedClaim::Selected).collect();

    result.extend(missing_claims);

    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ClaimMatch<'a> {
    claim: &'a Claim,
    // Whether it was an exact match on the DCQL path or matched transitively by other matched claims
    exact: bool,
}

fn get_matching_claims<'a>(
    claims: &'a [Claim],
    claim_filter: &ClaimFilter,
    user_claim_path: &[String],
    select_children: bool,
) -> Result<HashSet<ClaimMatch<'a>>, VerificationProtocolError> {
    let values_filter = claim_filter
        .values
        .iter()
        .map(stringify_value)
        .collect::<Vec<_>>();

    let exactly_matching_claims: Vec<_> = claims
        .iter()
        // use filter_map to propagate errors of fallible predicate
        .filter_map(|claim| {
            dcql_path_exactly_matches_claim(&claim_filter.path, claim, claims, user_claim_path)
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

    if exactly_matching_claims.is_empty() {
        // no matches found, return empty result
        return Ok(HashSet::new());
    }

    let mut child_claims = HashSet::<&Claim>::new();
    if select_children {
        // Presentation definition v2: child claims of exactly matching claims are also selected
        exactly_matching_claims.iter().for_each(|claim| {
            let prefix = format!("{}/", claim.path);
            child_claims.extend(claims.iter().filter(|c| c.path.starts_with(&prefix)));
        });
    }

    // "trunk" nodes on the path from root to the filtered_claims
    // all of these are either arrays or objects
    let mut claims_towards_root = HashSet::<&Claim>::new();
    exactly_matching_claims.iter().try_for_each(|claim| {
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
    combined_set.extend(
        exactly_matching_claims
            .into_iter()
            .map(|claim| ClaimMatch { claim, exact: true }),
    );
    combined_set.extend(child_claims.into_iter().map(|claim| ClaimMatch {
        claim,
        exact: false,
    }));
    combined_set.extend(claims_towards_root.into_iter().map(|claim| ClaimMatch {
        claim,
        exact: false,
    }));
    combined_set.extend(
        nonselectively_disclosable_children
            .into_iter()
            .map(|claim| ClaimMatch {
                claim,
                exact: false,
            }),
    );
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
        let schema_id = map_schema_id(filter, schema_id);

        credentials.append(
            &mut storage_access
                .get_presentation_credentials_by_schema_id(schema_id, organisation_id)
                .await
                .map_err(VerificationProtocolError::StorageAccessError)?,
        );
    }
    Ok(credentials)
}

fn map_schema_id(filter: &CredentialFilter, schema_id: &str) -> String {
    match filter.format {
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
    }
    .to_string()
}

/// Predicate that checks if the DCQL path matches the claim path exactly, as in
/// it addresses the claim directly (and not a child claim).
fn dcql_path_exactly_matches_claim(
    dcql_path: &ClaimPath,
    claim: &Claim,
    all_claims: &[Claim],
    user_claim_path: &[String],
) -> Result<bool, VerificationProtocolError> {
    let dcql_segments = if !claim
        .schema
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(format!(
            "missing schema for claim '{}'",
            claim.id
        )))?
        .metadata
    {
        adjust_dcql_path_for_user_claims(dcql_path, user_claim_path)?
    } else {
        dcql_path.segments.iter().collect()
    };
    let claim_path_segments = claim.path.split('/').collect::<Vec<_>>();
    if dcql_segments.len() != claim_path_segments.len() {
        // nesting depth mismatch -> no match
        return Ok(false);
    }

    let mut current_path = "".to_string();
    for (dcql_path_segment, claim_path_segment) in
        dcql_segments.into_iter().zip(claim.path.split('/'))
    {
        current_path = if current_path.is_empty() {
            claim_path_segment.to_string()
        } else {
            format!("{current_path}/{claim_path_segment}")
        };
        let schema = all_claims
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

/// Predicate that checks if the DCQL path matches a metadata claim.
fn dcql_path_matches_metadata(
    dcql_path: &ClaimPath,
    claim_schemas: &[CredentialSchemaClaim],
    user_claim_path: &[String],
) -> bool {
    let array_selector_count = dcql_path
        .segments
        .iter()
        .filter(|s| !matches!(s, PathSegment::PropertyName(_)))
        .count();
    // No currently supported metadata claim uses nested arrays, so at most one array selector must be in the DCQL path
    if array_selector_count > 1 {
        return false;
    }
    let mut segments = dcql_path.segments.iter().collect::<Vec<_>>();
    if array_selector_count == 1 {
        let Some(segment) = segments.pop() else {
            return false;
        };
        if matches!(segment, PathSegment::PropertyName(_)) {
            // In currently supported metadata paths, this needs to be the (single) array selector,
            // if any.
            return false;
        }
    }
    if user_claim_path.len() >= segments.len()
        && segments
            .iter()
            .zip(user_claim_path)
            .all(|(segment, o)| matches!(segment, PathSegment::PropertyName(name) if name == o))
    {
        // the dcql query also addresses user claims, so it is not considered metadata
        return false;
    }

    let dcql_key = segments
        .into_iter()
        .filter_map(|s| {
            if let PathSegment::PropertyName(s) = s {
                Some(s)
            } else {
                None
            }
        })
        .join("/");
    claim_schemas
        .iter()
        .filter(|cs| cs.schema.metadata)
        .any(|cs| cs.schema.key == dcql_key || cs.schema.key.starts_with(&format!("{dcql_key}/")))
}

fn dcql_path_to_absent_claim_key(
    path: &ClaimPath,
    user_claim_path: &[String],
) -> Result<String, VerificationProtocolError> {
    let segments_iter = adjust_dcql_path_for_user_claims(path, user_claim_path)?;
    Ok(segments_iter
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
        .join("/"))
}

fn adjust_dcql_path_for_user_claims<'a>(
    path: &'a ClaimPath,
    user_claim_path: &[String],
) -> Result<Vec<&'a PathSegment>, VerificationProtocolError> {
    let mut segments_iter = path.segments.iter().peekable();
    for user_path_segment in user_claim_path.iter() {
        let Some(PathSegment::PropertyName(name)) = segments_iter.peek() else {
            return Err(VerificationProtocolError::Failed(format!(
                "Unsupported DCQL path: {path} matches user claim path [{}] partially",
                user_claim_path.join(", ")
            )));
        };
        if name == user_path_segment {
            segments_iter.next();
        } else {
            // mismatch, claim path is not reaching into user claims --> return original
            return Ok(path.segments.iter().collect());
        }
    }
    let result = segments_iter.collect::<Vec<_>>();
    if result.is_empty() {
        return Err(VerificationProtocolError::Failed(format!(
            "Unsupported DCQL path: {path} should be more specific than user claim path [{}]",
            user_claim_path.join(", ")
        )));
    }
    Ok(result)
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
