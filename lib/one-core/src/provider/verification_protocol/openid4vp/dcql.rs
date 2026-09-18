use std::collections::{HashMap, VecDeque};

use indexmap::IndexMap;
use itertools::Itertools;
use one_dto_mapper::convert_inner;
use shared_types::{ClaimId, ClaimSchemaId, OrganisationId, TransactionDataId};
use standardized_types::openid4vp::dcql::matching::{ClaimFilter, CredentialFilter};
use standardized_types::openid4vp::dcql::{
    ClaimPath, ClaimValue, CredentialFormat, CredentialQuery, CredentialQueryId, DcqlQuery,
    PathSegment, TrustedAuthority,
};
use standardized_types::openid4vp::{VerifierInfoAttestation, VerifierInfoAttestationFormat};
use standardized_types::x509::KeyIdentifier;

use super::disclosure_policy::{
    dn_and_serial_matches_any_in_chain, dn_matches_leaf_only, entitlement_matches_reg_cert,
    entitlement_matches_via_registry,
};
use crate::config::core_config::{CoreConfig, FormatType};
use crate::error::ContextWithErrorCode;
use crate::mapper::NESTED_CLAIM_MARKER;
use crate::mapper::credential_schema_claim::claim_path_to_formatted_path;
use crate::mapper::x509::pem_chain_to_authority_key_identifiers;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaListQuery};
use crate::model::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use crate::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::proof::Proof;
use crate::model::relation::OptionalRelatedExt;
use crate::proto::openid4vp_proof_validator::validator::get_trusted_akis;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::provider::verification_protocol::dto::{
    ApplicableCredential, ApplicableCredentialOrFailureHintEnum,
    CredentialDetailClaimExtResponseDTO, CredentialQueryFailureHintResponseDTO,
    CredentialQueryFailureReasonEnum, CredentialQueryResponseDTO, CredentialSetResponseDTO,
    DisclosurePolicyViolation, PresentationDefinitionV2ResponseDTO,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::mapper::get_presentation_credentials_by_schema_id;
use crate::provider::verification_protocol::openid4vp::mapper::map_transaction_data;
use crate::provider::verification_protocol::openid4vp::model::ValidatedHolderTxData;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::error::DataLayerError;
use crate::service::credential::dto::{
    CredentialAttestationBlobs, CredentialDetailResponseDTO, DetailCredentialClaimResponseDTO,
    DetailCredentialClaimValueResponseDTO,
};
use crate::service::credential::mapper::{
    credential_detail_response_from_model, get_remaining_batch_item_count,
};
use crate::service::credential_schema::dto::{
    CredentialSchemaDetailResponseDTO, CredentialSchemaFilterValue,
    CredentialSchemaListIncludeEntityTypeEnum,
};
use crate::service::credential_schema::mapper::schema_to_detail_v1_response_dto;

#[expect(clippy::too_many_arguments)]
pub(crate) async fn get_presentation_definition_v2(
    dcql_query: DcqlQuery,
    proof: &Proof,
    credential_repository: &dyn CredentialRepository,
    credential_schema_repository: &dyn CredentialSchemaRepository,
    formatter_provider: &dyn CredentialFormatterProvider,
    ecosystem_provider: &dyn EcosystemDirectory,
    wrp_validator: &dyn WRPValidator,
    config: &CoreConfig,
    verifier_details: Option<&IdentifierDetails>,
    verifier_info: &[VerifierInfoAttestation],
    transaction_data: Option<IndexMap<TransactionDataId, ValidatedHolderTxData>>,
) -> Result<PresentationDefinitionV2ResponseDTO, VerificationProtocolError> {
    let organisation_id = proof
        .interaction
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "proof interaction missing".to_string(),
        ))?
        .as_ref()
        .await?
        .organisation
        .id();

    let query_to_filters = dcql_query.credential_filters()?;

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
        let credential_candidates = fetch_credentials_for_schema_ids(
            organisation_id,
            credential_filters,
            credential_repository,
        )
        .await?;

        let mut filtered_credential_candidates = vec![];
        for candidate in credential_candidates.into_iter().unique_by(|c| c.id) {
            let format = candidate.format.as_required_ref().await?;
            if !format_matches(&query.format, &format.format, config)
                || !credential_filters.iter().any(|filter| {
                    filter
                        .ecosystem_schema_ids
                        .iter()
                        .any(|id| map_schema_id(filter, id) == format.ecosystem_schema_id)
                })
            {
                continue;
            }
            drop(format);
            filtered_credential_candidates.push(candidate);
        }

        if let Some(authorities) = &query.trusted_authorities {
            filter_credentials_by_trusted_authorities(
                &mut filtered_credential_candidates,
                authorities.as_slice(),
            )
            .await;
        }

        if filtered_credential_candidates.is_empty() {
            let ecosystem_schema_ids = credential_filters
                .iter()
                .flat_map(|filter| {
                    filter
                        .ecosystem_schema_ids
                        .iter()
                        .map(|ecosystem_schema_id| map_schema_id(filter, ecosystem_schema_id))
                })
                .collect::<Vec<_>>();
            let credential_schema = find_schema_by_schema_ids(
                &ecosystem_schema_ids,
                organisation_id,
                credential_schema_repository,
            )
            .await
            .error_while("getting credential schemas")?;
            let credential_schema = match credential_schema {
                None => None,
                Some(schema) => Some(
                    schema_to_detail_v1_response_dto(schema, config, formatter_provider)
                        .await
                        .error_while("converting credential schema")?,
                ),
            };
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

        let (candidates, invalid_credentials): (Vec<_>, Vec<_>) = filtered_credential_candidates
            .into_iter()
            .partition(|credential| credential.state == CredentialStateEnum::Accepted);
        if candidates.is_empty() {
            let credential_schema = match invalid_credentials.into_iter().next() {
                None => None,
                Some(cred) => {
                    let schema = cred.schema.as_ref().await?.to_owned();
                    Some(
                        schema_to_detail_v1_response_dto(schema, config, formatter_provider)
                            .await
                            .error_while("converting credential schema")?,
                    )
                }
            };

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
        let failure_hint_schema = match candidates.first() {
            None => None,
            Some(cred) => Some(cred.schema.as_ref().await?.to_owned()),
        };
        let mut applicable_credentials: Vec<ApplicableCredential> = vec![];
        for candidate in candidates {
            let format = candidate.format.as_required_ref().await?.to_owned();
            let formatter = formatter_provider.get_credential_formatter(&format.format)?;
            let mut claim_source = candidate.clone();
            // The candidate query returns only singles and representative batch items.
            claim_source.claims = crate::mapper::credential::stored_credential_claims(&candidate)
                .await?
                .into();
            let claims =
                first_matching_claims(&claim_source, credential_filters, &*formatter).await?;
            let Some(claims) = claims else {
                continue;
            };
            // Expose one public entry per batch using its parent's ID and metadata.
            // The candidate remains the concrete item used for presentation.
            let summary = match &candidate.parent {
                Some(parent) => parent.as_ref().await?.to_owned(),
                None => candidate.clone(),
            };
            if applicable_credentials
                .iter()
                .any(|c| c.credential.id == summary.id)
            {
                continue;
            }
            let remaining_batch_item_count =
                get_remaining_batch_item_count(&summary, credential_repository)
                    .await
                    .error_while("getting remaining batch items")?;

            let embedded_disclosure_policy_violation = check_disclosure_policy(
                &candidate,
                &query.id,
                verifier_details,
                verifier_info,
                wrp_validator,
            )
            .await?;

            let credential_detail_dto = credential_detail_response_from_model(
                summary.clone(),
                claim_source.claims.as_ref().await?.to_owned(),
                config,
                CredentialAttestationBlobs::default(),
                None,
                remaining_batch_item_count,
                credential_repository,
                formatter_provider,
                None,
            )
            .await
            .error_while("creating credential detail")?;

            let credential = map_to_filtered_dto(credential_detail_dto, &claims);
            applicable_credentials.push(ApplicableCredential {
                credential,
                embedded_disclosure_policy_violation,
                presentation_credential_id: candidate.id,
            });
        }
        if applicable_credentials.is_empty() {
            credential_queries.insert(
                query.id.to_string(),
                failure_hint(
                    &query,
                    CredentialQueryFailureReasonEnum::Constraint,
                    match failure_hint_schema {
                        None => None,
                        Some(schema) => Some(
                            schema_to_detail_v1_response_dto(schema, config, formatter_provider)
                                .await
                                .error_while("converting failure hint schema")?,
                        ),
                    },
                )?,
            );
        } else {
            let purpose = if let Some(ecosystem_id) = &proof.ecosystem {
                let ecosystem = ecosystem_provider.get(ecosystem_id)?;
                ecosystem
                    .get_trust_purpose(&proof.id, &query.id)
                    .await
                    .error_while("getting ecosystem purpose")?
            } else {
                None
            };

            credential_queries.insert(
                query.id.to_string(),
                CredentialQueryResponseDTO {
                    multiple: query.multiple,
                    credential_or_failure_hint:
                        ApplicableCredentialOrFailureHintEnum::ApplicableCredentials {
                            applicable_credentials,
                            purpose,
                        },
                },
            );
        }
    }
    Ok(PresentationDefinitionV2ResponseDTO {
        credential_queries,
        credential_sets,
        transaction_data: transaction_data
            .map(map_transaction_data)
            .unwrap_or_default(),
    })
}

async fn filter_credentials_by_trusted_authorities(
    credentials: &mut Vec<Credential>,
    authorities: &[TrustedAuthority],
) {
    if credentials.is_empty() {
        return;
    }

    let trusted_akis = get_trusted_akis(authorities);
    let mut retained = Vec::with_capacity(credentials.len());
    for credential in std::mem::take(credentials) {
        if credential_issuer_in_aki_list(&credential, trusted_akis.as_slice()).await {
            retained.push(credential);
        }
    }
    *credentials = retained;
}

async fn credential_issuer_in_aki_list(credential: &Credential, list: &[KeyIdentifier]) -> bool {
    let Some(issuer_cert) = credential.issuer_certificate.as_ref() else {
        return false;
    };

    let Ok(issuer_cert) = issuer_cert.as_ref().await else {
        return false;
    };

    let Ok(issuer_akis) = pem_chain_to_authority_key_identifiers(&issuer_cert.chain) else {
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
        expires_at: full_dto.expires_at,
        consumed_at: full_dto.consumed_at,
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
        r#type: full_dto.r#type,
        format: full_dto.format,
        interaction_id: full_dto.interaction_id,
        suspend_end_date: full_dto.suspend_end_date,
        mdoc_mso_validity: full_dto.mdoc_mso_validity,
        holder: full_dto.holder,
        protocol: full_dto.protocol,
        profile: full_dto.profile,
        wallet_instance_attestation: None,
        wallet_unit_attestation: None,
        webhook_destination_url: full_dto.webhook_destination_url,
        trust_information: full_dto.trust_information,
        remaining_batch_item_count: full_dto.remaining_batch_item_count,
        parent_id: full_dto.parent_id,
        subscriber_information: full_dto.subscriber_information,
        ecosystem: full_dto.ecosystem,
        offered_formats: None,
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

async fn first_matching_claims(
    credential: &Credential,
    filters: &[CredentialFilter],
    formatter: &dyn CredentialFormatter,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    let format = credential.format.as_required_ref().await?;
    for filter in filters {
        if !filter
            .ecosystem_schema_ids
            .iter()
            .any(|id| map_schema_id(filter, id) == format.ecosystem_schema_id)
        {
            continue;
        }
        let claims = select_matching_claims(credential, filter, formatter).await?;
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
        CredentialFormat::JwtVc(_) => credential_format == FormatType::Jwt,
        CredentialFormat::LdpVc(_) => {
            credential_format == FormatType::JsonLdBbsPlus
                || credential_format == FormatType::JsonLdClassic
        }
        CredentialFormat::MsoMdoc(_) => credential_format == FormatType::Mdoc,
        CredentialFormat::SdJwt(_) => credential_format == FormatType::SdJwtVc,
        CredentialFormat::W3cSdJwt(_) => credential_format == FormatType::SdJwt,
    }
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

async fn select_matching_claims(
    credential: &Credential,
    filter: &CredentialFilter,
    formatter: &dyn CredentialFormatter,
) -> Result<Option<Vec<SelectedClaim>>, VerificationProtocolError> {
    let claims = select_claims(credential, filter, formatter, true).await?;
    let mut result = vec![];
    for claim in claims {
        match claim {
            MatchedClaim::Missing { .. } => return Ok(None), // abort as not matching on missing required claim
            MatchedClaim::Selected(selected_claim) => result.push(selected_claim),
        }
    }
    Ok(Some(result))
}

async fn select_claims(
    credential: &Credential,
    filter: &CredentialFilter,
    formatter: &dyn CredentialFormatter,
    select_children: bool,
) -> Result<Vec<MatchedClaim>, VerificationProtocolError> {
    let claims = credential.claims.as_ref().await?;

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
            &claims,
            root_nonselectively_disclosable
                .iter()
                .map(|claim| claim.path.as_str())
                .collect::<Vec<_>>(),
        );

        let nonselectively_disclosable = root_nonselectively_disclosable
            .iter()
            .chain(nonselectively_disclosable_children_of_root.iter());

        for claim in nonselectively_disclosable {
            selected.insert(
                claim.path.to_owned(),
                SelectedClaim {
                    path: claim.path.to_owned(),
                    selective_disclosure_supported: claim.selectively_disclosable,
                    required_by_verifier: false,
                    // non-selectively disclosable claims can never be de-selected by the user
                    user_selection: false,
                    metadata: claim.schema.as_ref().await?.metadata,
                },
            );
        }
    }

    let mut missing_claims = vec![];

    let credential_schema = credential.schema.as_ref().await?;
    let format = credential.format.as_required_ref().await?;
    let mappings = format.claim_mappings.as_ref().await?;
    let mappings_by_schema_id = mappings
        .iter()
        .map(|m| (m.claim_schema_id, m.clone()))
        .collect();
    let credential_claim_schemas = credential_schema.claim_schemas.as_ref().await?;

    let user_claim_path = formatter.user_claims_path();
    // add claims requested by the verifier
    for claim_filter in &filter.claims {
        let matching_claims = get_matching_claims(
            &claims,
            claim_filter,
            &user_claim_path,
            select_children,
            &mappings_by_schema_id,
        )
        .await?;
        if !matching_claims.is_empty() {
            for (ClaimMatchId { exact, .. }, matching_claim) in matching_claims {
                // All optional claims that were explicitly requested by the verifier
                // should have a toggle.
                let user_selection = exact && !claim_filter.required;
                if let Some(claim) = selected.get_mut(&matching_claim.path) {
                    claim.required_by_verifier =
                        claim.required_by_verifier || claim_filter.required;
                    claim.user_selection = claim.user_selection || user_selection
                } else {
                    selected.insert(
                        matching_claim.path.to_owned(),
                        SelectedClaim {
                            path: matching_claim.path.to_owned(),
                            selective_disclosure_supported: matching_claim.selectively_disclosable,
                            required_by_verifier: claim_filter.required,
                            user_selection,
                            metadata: matching_claim.schema.as_ref().await?.metadata,
                        },
                    );
                };
            }
        } else if claim_filter.required {
            // no match but claim is required --> add to missing claims (mark the credential as inapplicable)
            missing_claims.push(MatchedClaim::Missing {
                path: claim_filter.path.to_owned(),
                format: filter.format.to_owned(),
                metadata: dcql_path_matches_metadata(
                    &claim_filter.path,
                    &credential_claim_schemas,
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
struct ClaimMatchId {
    claim_id: ClaimId,
    // Whether it was an exact match on the DCQL path or matched transitively by other matched claims
    exact: bool,
}

async fn get_matching_claims<'a>(
    claims: &'a [Claim],
    claim_filter: &ClaimFilter,
    user_claim_path: &[String],
    select_children: bool,
    claim_mappings: &HashMap<ClaimSchemaId, CredentialSchemaFormatClaimSchema>,
) -> Result<HashMap<ClaimMatchId, &'a Claim>, VerificationProtocolError> {
    let values_filter = claim_filter
        .values
        .iter()
        .map(stringify_value)
        .collect::<Vec<_>>();

    let mut exactly_matching_claims: Vec<&Claim> = vec![];
    for claim in claims {
        let matches = dcql_path_exactly_matches_claim(
            &claim_filter.path,
            claim,
            claims,
            user_claim_path,
            claim_mappings,
        )
        .await?;
        if matches
            && (values_filter.is_empty()
                || claim
                    .value
                    .as_ref()
                    .is_some_and(|value| values_filter.contains(value)))
        {
            exactly_matching_claims.push(claim);
        }
    }

    if exactly_matching_claims.is_empty() {
        // no matches found, return empty result
        return Ok(HashMap::new());
    }

    let mut child_claims = HashMap::<ClaimId, &Claim>::new();
    if select_children {
        // Presentation definition v2: child claims of exactly matching claims are also selected
        exactly_matching_claims.iter().for_each(|claim| {
            let prefix = format!("{}/", claim.path);
            for claim in claims.iter().filter(|c| c.path.starts_with(&prefix)) {
                child_claims.insert(claim.id, claim);
            }
        });
    }

    // "trunk" nodes on the path from root to the filtered_claims
    // all of these are either arrays or objects
    let mut claims_towards_root = HashMap::<ClaimId, &Claim>::new();
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
            claims_towards_root.insert(parent_claim.id, parent_claim);
            current_path = parent_path;
        }
        Ok::<_, VerificationProtocolError>(())
    })?;

    // branches of nodes that are not selectively disclosable
    let nonselectively_disclosable_children = get_nonselectively_disclosable_children(
        claims,
        claims_towards_root
            .values()
            .map(|claim| claim.path.as_str()),
    );

    let mut combined_set = HashMap::new();
    combined_set.extend(exactly_matching_claims.into_iter().map(|claim| {
        (
            ClaimMatchId {
                claim_id: claim.id,
                exact: true,
            },
            claim,
        )
    }));
    combined_set.extend(child_claims.into_iter().map(|(claim_id, claim)| {
        (
            ClaimMatchId {
                claim_id,
                exact: false,
            },
            claim,
        )
    }));
    combined_set.extend(claims_towards_root.into_iter().map(|(claim_id, claim)| {
        (
            ClaimMatchId {
                claim_id,
                exact: false,
            },
            claim,
        )
    }));
    combined_set.extend(
        nonselectively_disclosable_children
            .into_iter()
            .map(|claim| {
                (
                    ClaimMatchId {
                        claim_id: claim.id,
                        exact: false,
                    },
                    claim,
                )
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
    while let Some(parent_path) = parent_paths.pop_front() {
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
    organisation_id: OrganisationId,
    credential_filters: &[CredentialFilter],
    credential_repository: &dyn CredentialRepository,
) -> Result<Vec<Credential>, VerificationProtocolError> {
    let mut credentials = vec![];

    // The filters only change based on the different claim sets. So to retrieve the
    // credential schema ids, just looking at the first one is sufficient.
    let Some(filter) = credential_filters.first() else {
        return Err(VerificationProtocolError::Failed(
            "empty credential filters".to_string(),
        ));
    };

    for ecosystem_schema_id in &filter.ecosystem_schema_ids {
        let ecosystem_schema_id = map_schema_id(filter, ecosystem_schema_id);

        credentials.append(
            &mut get_presentation_credentials_by_schema_id(
                credential_repository,
                ecosystem_schema_id,
                organisation_id,
            )
            .await
            .error_while("getting presentation credentials for schema")?,
        );
    }
    Ok(credentials)
}

fn map_schema_id(filter: &CredentialFilter, ecosystem_schema_id: &str) -> String {
    match filter.format {
        CredentialFormat::JwtVc(_) | CredentialFormat::LdpVc(_) | CredentialFormat::W3cSdJwt(_) => {
            ecosystem_schema_id
                // Make use of the fact that Procivis One issuers put the schema id into the context,
                // hence we can potentially parse it out of the supplied types.
                // Note: This will most likely fail with third party issuers. Improve the logic,
                // once we need to interop with such issuers.
                .split_once("#")
                .map(|(first, _)| first)
                .unwrap_or(ecosystem_schema_id)
        }
        CredentialFormat::MsoMdoc(_) | CredentialFormat::SdJwt(_) => ecosystem_schema_id,
    }
    .to_string()
}

/// Predicate that checks if the DCQL path matches the claim path exactly, as in
/// it addresses the claim directly (and not a child claim).
async fn dcql_path_exactly_matches_claim(
    dcql_path: &ClaimPath,
    claim: &Claim,
    all_claims: &[Claim],
    user_claim_path: &[String],
    claim_mappings: &HashMap<ClaimSchemaId, CredentialSchemaFormatClaimSchema>,
) -> Result<bool, VerificationProtocolError> {
    let schema: ClaimSchema = claim.schema.as_ref().await?.to_owned();
    let dcql_segments = if !schema.metadata {
        adjust_dcql_path_for_user_claims(dcql_path, user_claim_path)?
    } else {
        dcql_path.segments.iter().collect()
    };
    let effective_path = if let Some(mapping) = claim_mappings.get(&schema.id) {
        claim_path_to_formatted_path(claim, &schema, mapping).error_while("mapping claim path")?
    } else {
        claim.path.to_owned()
    };
    let claim_path_segments = effective_path.split('/').collect::<Vec<_>>();

    if dcql_segments.len() != claim_path_segments.len() {
        // nesting depth mismatch -> no match
        return Ok(false);
    }
    let mut claim_schemas: VecDeque<ClaimSchema> = VecDeque::with_capacity(dcql_segments.len());
    if schema.array
        && dcql_segments
            .last()
            .is_some_and(|s| matches!(s, PathSegment::ArrayAll | PathSegment::ArrayIndex(_)))
    {
        // Array claim schemas are shared between the elements and the container.
        // The leaf schema thus needs to be included twice if the last segment addresses elements and not the container.
        claim_schemas.push_front(schema.to_owned());
    }
    claim_schemas.push_front(schema);
    while let Some(parent_key) = claim_schemas
        .front()
        .and_then(|schema| schema.key.rsplit_once(NESTED_CLAIM_MARKER))
        .map(|(parent_key, _)| parent_key.to_owned())
    {
        let mut parent_schema = None;
        for candidate in all_claims {
            let candidate_schema = candidate.schema.as_ref().await?;
            if candidate_schema.key == parent_key {
                parent_schema = Some(candidate_schema.to_owned());
                break;
            }
        }
        let parent_schema = parent_schema.ok_or(VerificationProtocolError::Failed(format!(
            "missing claim schema for claim '{}'",
            claim.id
        )))?;
        if parent_schema.array {
            // Array claim schemas are shared between the elements and the container, thus need to be
            // included twice.
            claim_schemas.push_front(parent_schema.to_owned());
        }
        claim_schemas.push_front(parent_schema);
    }

    let mut array_flags = vec![];
    if claim_schemas.len() < dcql_segments.len() {
        // The root claim schema represents 2 levels in case of MDOC (also the namespace).
        // The namespace is never an array.
        array_flags.push(false);
    }
    array_flags.extend(claim_schemas.iter().map(|schema| schema.array));

    let mut current_path = "".to_string();
    for ((dcql_path_segment, claim_path_segment), is_array) in dcql_segments
        .into_iter()
        .zip(claim_path_segments)
        .zip(array_flags)
    {
        current_path = if current_path.is_empty() {
            claim_path_segment.to_string()
        } else {
            format!("{current_path}/{claim_path_segment}")
        };
        match dcql_path_segment {
            PathSegment::PropertyName(name) => {
                if name != claim_path_segment {
                    // wrong property name -> no match
                    return Ok(false);
                }
            }
            PathSegment::ArrayIndex(index) => {
                if !is_array {
                    // property is not an array -> no match
                    return Ok(false);
                }
                if index.to_string() != claim_path_segment {
                    // wrong index -> no match
                    return Ok(false);
                }
            }
            PathSegment::ArrayAll => {
                if !is_array {
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
    claim_schemas: &[ClaimSchema],
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
        .filter(|cs| cs.metadata)
        .any(|cs| cs.key == dcql_key || cs.key.starts_with(&format!("{dcql_key}/")))
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

async fn find_schema_by_schema_ids(
    schema_ids: &[String],
    organisation_id: OrganisationId,
    credential_schema_repository: &dyn CredentialSchemaRepository,
) -> Result<Option<CredentialSchema>, DataLayerError> {
    let schema_ids_filter_cond = schema_ids
        .iter()
        .map(|id| CredentialSchemaFilterValue::EcosystemSchemaId(StringMatch::equals(id)))
        .fold(ListFilterCondition::default(), |acc, cond| acc | cond);
    let candidates = credential_schema_repository
        .get_credential_schema_list(CredentialSchemaListQuery {
            include_count: false,
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            sorting: None,
            filtering: Some(
                CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                    & schema_ids_filter_cond,
            ),
            include: Some(vec![
                CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
            ]),
        })
        .await?;
    Ok(candidates.values.into_iter().next())
}

async fn check_disclosure_policy(
    credential: &Credential,
    query_id: &CredentialQueryId,
    verifier_details: Option<&IdentifierDetails>,
    verifier_info: &[VerifierInfoAttestation],
    wrp_validator: &dyn WRPValidator,
) -> Result<Option<DisclosurePolicyViolation>, VerificationProtocolError> {
    use standardized_types::etsi_119_472::disclosure_policy::*;

    let Some(disclosure_policy) = &credential.embedded_disclosure_policy else {
        return Ok(None);
    };

    let disclosure_policy: DisclosurePolicy = serde_json::from_str(disclosure_policy)?;
    let violation = || {
        Some(DisclosurePolicyViolation {
            id: disclosure_policy.id,
            description: disclosure_policy.description,
            url: disclosure_policy.url,
        })
    };

    match disclosure_policy.policy {
        PolicyType::None => Ok(None),
        PolicyType::AllowList { options } => {
            for option in options.values {
                if let Some(dn) = &option.dn
                    && let Some(IdentifierDetails::Certificate(verifier)) = verifier_details
                    && dn_matches_leaf_only(&verifier.chain, dn)?
                {
                    return Ok(None);
                }

                if let Some(entitlement) = &option.entitlement {
                    for reg_cert in verifier_info
                        .iter()
                        .filter(|info| {
                            info.format == VerifierInfoAttestationFormat::RegistrationCert
                        })
                        .filter(|info| {
                            info.credential_ids.is_empty() || info.credential_ids.contains(query_id)
                        })
                    {
                        if entitlement_matches_reg_cert(entitlement, &reg_cert.data).await? {
                            return Ok(None);
                        }
                    }

                    if let Some(IdentifierDetails::Certificate(access_cert)) = verifier_details
                        && entitlement_matches_via_registry(
                            entitlement,
                            &access_cert.chain,
                            wrp_validator,
                        )
                        .await?
                    {
                        return Ok(None);
                    }
                }
            }

            Ok(violation())
        }
        PolicyType::RootOfTrust { options } => {
            let Some(IdentifierDetails::Certificate(verifier)) = verifier_details else {
                return Ok(violation());
            };

            for option in options.values {
                if dn_and_serial_matches_any_in_chain(&verifier.chain, &option.dn, &option.serial)?
                {
                    return Ok(None);
                }
            }

            Ok(violation())
        }
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::mapper::credential_schema_claim::presented_paths_to_disclosed_keys;
    use crate::provider::credential_formatter::MockCredentialFormatter;
    use crate::service::test_utilities::dummy_credential;

    #[tokio::test]
    async fn matching_and_disclosure_use_the_items_exact_format() {
        let mut item = dummy_credential();
        let mut format = item.format.as_required_ref().await.unwrap().to_owned();
        format.id = Uuid::new_v4().into();
        format.format = "MDOC".into();
        format.ecosystem_schema_id = "doctype".into();
        let claim = item.claims.as_ref().await.unwrap()[0].clone();
        format.claim_mappings = vec![CredentialSchemaFormatClaimSchema {
            id: Uuid::new_v4().into(),
            created_date: item.created_date,
            last_modified: item.last_modified,
            credential_schema_format_id: format.id,
            claim_schema_id: claim.schema.id(),
            technical_key: "renamed".into(),
            namespace: Some("namespace".into()),
        }]
        .into();
        // The credential uses the second schema format, with a different name and namespace.
        let mut schema = item.schema.as_ref().await.unwrap().to_owned();
        schema.formats.as_mut().await.unwrap().push(format.clone());
        item.schema = schema.into();
        item.format = Some(format.into());
        item.claims.as_mut().await.unwrap()[0].selectively_disclosable = true;
        let query: DcqlQuery = serde_json::from_value(serde_json::json!({
            "credentials": [{
                "id": "mdoc", "format": "mso_mdoc", "meta": {"doctype_value": "doctype"},
                "claims": [{"path": ["namespace", "renamed"]}]
            }]
        }))
        .unwrap();
        let filters = query.credential_filters().unwrap();
        let filters = filters.values().next().unwrap();
        let mut formatter = MockCredentialFormatter::new();
        formatter.expect_user_claims_path().return_const(vec![]);
        let selected = first_matching_claims(&item, filters, &formatter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert!(selected[0].selective_disclosure_supported);
        assert_eq!(
            presented_paths_to_disclosed_keys(std::slice::from_ref(&claim.path), &item)
                .await
                .unwrap(),
            vec!["namespace/renamed"]
        );

        item.claims = Default::default();
        assert!(
            first_matching_claims(&item, filters, &formatter)
                .await
                .unwrap()
                .is_none()
        );
        item.claims = vec![claim].into();
        item.format
            .as_required_mut()
            .await
            .unwrap()
            .ecosystem_schema_id = "different-doctype".into();
        assert!(
            first_matching_claims(&item, filters, &formatter)
                .await
                .unwrap()
                .is_none()
        );
    }
}
