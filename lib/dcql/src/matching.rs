use std::collections::HashMap;

use crate::{
    ClaimPath, ClaimQuery, ClaimQueryId, ClaimValue, CredentialFormat, CredentialMeta,
    CredentialQueryId, DcqlError, DcqlQuery,
};

/// Filter restrictions for credentials held in the wallet.
#[derive(Debug, Clone)]
pub struct CredentialFilter {
    /// Filter based on the credential format.
    pub format: CredentialFormat,
    /// Filter based on credential schema identifiers.
    /// The exact values depends on the format:
    ///   - mso_mdoc -> `doctype_value`
    ///   - dc+sd-jwt -> `vct_values`
    ///   - W3C VCs (jwt_vc_json and ldp_vc): Most specific (i.e. last) element of each array in `type_values`
    pub schema_ids: Vec<String>,
    /// If non-empty, filter based on claims.
    pub claims: Vec<ClaimFilter>,
}

/// Filter restriction for a single claim on a credential.
#[derive(Debug, Clone)]
pub struct ClaimFilter {
    pub path: ClaimPath,
    /// If non-empty, filter based on claim values
    pub values: Vec<ClaimValue>,
    /// Non-standard extension to have optionality on claim level
    pub required: bool,
}

impl DcqlQuery {
    /// Returns a map of credential query id to a list of filters to look for matching
    /// credentials within the wallet storage.
    /// The filters are ordered by verifier preference if multiple options are conveyed through
    /// `claim_sets`.
    pub fn credential_filters(
        &self,
    ) -> Result<HashMap<CredentialQueryId, Vec<CredentialFilter>>, DcqlError> {
        let mut result: HashMap<CredentialQueryId, Vec<CredentialFilter>> = HashMap::new();
        for credential_query in &self.credentials {
            let schema_ids = match &credential_query.meta {
                CredentialMeta::MsoMdoc { doctype_value } => vec![doctype_value.clone()],
                CredentialMeta::SdJwtVc { vct_values } => vct_values.clone(),
                CredentialMeta::W3cVc { type_values } => type_values
                    .iter()
                    .flat_map(|values| values.last())
                    .cloned()
                    .collect(),
            };

            let base_filter = CredentialFilter {
                format: credential_query.format.clone(),
                schema_ids,
                claims: vec![],
            };

            let filters = if let Some(claims) = &credential_query.claims
                && !claims.is_empty()
            {
                process_claims(base_filter, claims, &credential_query.claim_sets)?
            } else {
                vec![base_filter]
            };
            result.insert(credential_query.id.clone(), filters);
        }
        Ok(result)
    }
}

fn process_claims(
    base_filter: CredentialFilter,
    claims: &[ClaimQuery],
    claim_sets: &Option<Vec<Vec<ClaimQueryId>>>,
) -> Result<Vec<CredentialFilter>, DcqlError> {
    let mut filters = vec![];
    if let Some(claim_sets) = &claim_sets {
        let claims_by_id = claim_filters_to_map(claims)?;
        for claim_set in claim_sets {
            let claim_filters = claim_set
                .iter()
                .map(|id| {
                    claims_by_id
                        .get(id)
                        .cloned()
                        .ok_or(DcqlError::UnknownClaimQueryId { id: id.clone() })
                })
                .collect::<Result<Vec<_>, _>>()?;
            filters.push(CredentialFilter {
                claims: claim_filters,
                ..base_filter.clone()
            });
        }
    } else {
        filters.push(CredentialFilter {
            claims: claims.iter().cloned().map(ClaimFilter::from).collect(),
            ..base_filter
        });
    }
    Ok(filters)
}

fn claim_filters_to_map(
    claim_queries: &[ClaimQuery],
) -> Result<HashMap<ClaimQueryId, ClaimFilter>, DcqlError> {
    let mut result = HashMap::new();
    for claim_query in claim_queries {
        let path = claim_query.path.clone();
        let Some(id) = &claim_query.id else {
            return Err(DcqlError::MissingClaimQueryId { path });
        };
        result.insert(
            id.clone(),
            ClaimFilter {
                path,
                values: claim_query.values.clone().unwrap_or(vec![]),
                required: claim_query.required.unwrap_or(true),
            },
        );
    }
    Ok(result)
}
