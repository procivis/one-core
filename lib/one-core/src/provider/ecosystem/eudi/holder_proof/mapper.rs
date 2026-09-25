use standardized_types::etsi_119_475::{Claim, Credential};
use standardized_types::openid4vp::dcql::{
    ClaimQuery, CredentialFormat, CredentialQuery, MsoMdocMeta, PathSegment, SdJwtVcMeta, W3cVcMeta,
};

use super::QueryMismatchReason;

pub(super) fn credential_query_matches_reg_cert_credential(
    credential_query: &CredentialQuery,
    req_cert_credential: &Credential,
) -> Result<(), QueryMismatchReason> {
    if !format_matches(credential_query, req_cert_credential) {
        return Err(QueryMismatchReason::FormatMismatch(
            credential_query.format.to_owned(),
        ));
    }

    // B.2.9 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
    // If claim is absent, the WRPRC does not declare any specific attributes intended to be requested by the WRP.
    if let Some(allowed_claims) = &req_cert_credential.claim {
        let Some(requested_claims) = &credential_query.claims else {
            return Err(QueryMismatchReason::NoClaimsRequested);
        };

        for requested_claim in requested_claims {
            if !allowed_claims.iter().any(|allowed_claim| {
                query_claim_matches_reg_cert_claim(requested_claim, allowed_claim)
            }) {
                return Err(QueryMismatchReason::ClaimMismatch(
                    requested_claim.to_owned(),
                ));
            }
        }
    }

    Ok(())
}

fn format_matches(credential_query: &CredentialQuery, req_cert_credential: &Credential) -> bool {
    match (&credential_query.format, &req_cert_credential.format) {
        (
            CredentialFormat::MsoMdoc(MsoMdocMeta {
                doctype_value: requested,
            }),
            CredentialFormat::MsoMdoc(MsoMdocMeta {
                doctype_value: allowed,
            }),
        ) if requested == allowed => {}
        (
            CredentialFormat::SdJwtVc(SdJwtVcMeta {
                vct_values: requested,
            }),
            CredentialFormat::SdJwtVc(SdJwtVcMeta {
                vct_values: allowed,
            }),
        ) if requested.iter().all(|vct| allowed.contains(vct)) => {}
        (
            CredentialFormat::JwtVc(W3cVcMeta {
                type_values: types_requested,
            }),
            CredentialFormat::JwtVc(W3cVcMeta {
                type_values: types_allowed,
            }),
        )
        | (
            CredentialFormat::LdpVc(W3cVcMeta {
                type_values: types_requested,
            }),
            CredentialFormat::LdpVc(W3cVcMeta {
                type_values: types_allowed,
            }),
        )
        | (
            CredentialFormat::W3cSdJwt(W3cVcMeta {
                type_values: types_requested,
            }),
            CredentialFormat::W3cSdJwt(W3cVcMeta {
                type_values: types_allowed,
            }),
        ) if types_requested
            .iter()
            .all(|requested| types_allowed.iter().any(|allowed| requested == allowed)) => {}
        _ => {
            return false;
        }
    };
    true
}

fn query_claim_matches_reg_cert_claim(query: &ClaimQuery, claim: &Claim) -> bool {
    if query.path.segments.len() < claim.path.segments.len() {
        // The query is less specific (i.e. matches more claims) than what would be allowed by the reg cert.
        return false;
    }
    if !query
        .path
        .segments
        .iter()
        .zip(&claim.path.segments)
        .all(|(requested, allowed)| match (requested, allowed) {
            (PathSegment::PropertyName(requested), PathSegment::PropertyName(allowed)) => {
                requested == allowed
            }
            (PathSegment::ArrayIndex(requested), PathSegment::ArrayIndex(allowed)) => {
                requested == allowed
            }
            (PathSegment::ArrayIndex(_), PathSegment::ArrayAll)
            | (PathSegment::ArrayAll, PathSegment::ArrayAll) => true,
            _ => false,
        })
    {
        return false;
    }

    // B.2.10 <https://www.etsi.org/deliver/etsi_ts/119400_119499/119475/01.02.01_60/ts_119475v010201p.pdf>
    // If claim values specified, the request must use a subset
    if let Some(allowed_values) = &claim.values {
        let Some(requested) = &query.values else {
            return false;
        };

        if !requested.iter().all(|value| allowed_values.contains(value)) {
            return false;
        }
    }

    true
}
