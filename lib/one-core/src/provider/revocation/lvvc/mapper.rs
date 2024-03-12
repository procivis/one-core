use shared_types::CredentialId;
use std::collections::HashMap;
use time::OffsetDateTime;

use crate::provider::revocation::lvvc::LvvcStatus;
use crate::service::error::ServiceError;

const SUSPEND_END_DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

pub(crate) fn status_from_lvvc_claims(
    lvvc_claims: &HashMap<String, String>,
) -> Result<LvvcStatus, ServiceError> {
    let status = lvvc_claims
        .get("status")
        .ok_or(ServiceError::ValidationError(
            "missing status claim in LVVC".to_string(),
        ))?;

    Ok(match status.as_str() {
        "ACCEPTED" => LvvcStatus::Accepted,
        "REVOKED" => LvvcStatus::Revoked,
        "SUSPENDED" => {
            let suspend_end_date = match lvvc_claims.get("suspendEndDate") {
                None => None,
                Some(date) => Some(
                    OffsetDateTime::parse(date, SUSPEND_END_DATE_FORMAT)
                        .map_err(|e| ServiceError::ValidationError(e.to_string()))?,
                ),
            };
            LvvcStatus::Suspended { suspend_end_date }
        }
        _ => {
            return Err(ServiceError::ValidationError(format!(
                "Unknown LVVC status `{status}`"
            )))
        }
    })
}

pub(super) fn create_id_claim(base_url: &str, credential_id: CredentialId) -> (String, String) {
    (
        "id".to_owned(),
        format!("{base_url}/ssi/credential/v1/{credential_id}"),
    )
}

pub(super) fn create_status_claims(
    status: &LvvcStatus,
) -> Result<Vec<(String, String)>, ServiceError> {
    let mut result = vec![("status".to_owned(), status.to_string())];

    if let LvvcStatus::Suspended {
        suspend_end_date: Some(end_date),
    } = status
    {
        result.push(suspend_end_date_claim(end_date)?);
    }

    Ok(result)
}

fn suspend_end_date_claim(end_date: &OffsetDateTime) -> Result<(String, String), ServiceError> {
    Ok((
        "suspendEndDate".to_owned(),
        end_date
            .format(SUSPEND_END_DATE_FORMAT)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?,
    ))
}
