use std::collections::HashMap;

use shared_types::CredentialId;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::provider::revocation::lvvc::LvvcStatus;
use crate::service::error::ServiceError;

const SUSPEND_END_DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

pub(crate) fn status_from_lvvc_claims(
    lvvc_claims: &HashMap<String, serde_json::Value>,
) -> Result<LvvcStatus, ServiceError> {
    let status = lvvc_claims
        .get("status")
        .ok_or(ServiceError::ValidationError(
            "missing status claim in LVVC".to_string(),
        ))?
        .as_str()
        .ok_or(ServiceError::ValidationError(
            "status claim in LVVC is not string".to_string(),
        ))?;

    Ok(match status {
        "ACCEPTED" => LvvcStatus::Accepted,
        "REVOKED" => LvvcStatus::Revoked,
        "SUSPENDED" => {
            let suspend_end_date = match lvvc_claims.get("suspendEndDate") {
                None => None,
                Some(date) => Some(
                    OffsetDateTime::parse(
                        date.as_str().ok_or(ServiceError::ValidationError(
                            "suspendEndDate claim in LVVC is not string".to_string(),
                        ))?,
                        &Rfc3339,
                    )
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

pub(super) fn create_id_claim(
    base_url: &str,
    credential_id: CredentialId,
) -> (String, String, Option<String>) {
    (
        "id".to_owned(),
        format!("{base_url}/ssi/credential/v1/{credential_id}"),
        None,
    )
}

pub(super) fn create_status_claims(
    status: &LvvcStatus,
) -> Result<Vec<(String, String, Option<String>)>, ServiceError> {
    let mut result = vec![(
        "status".to_owned(),
        status.to_string(),
        Some("STRING".to_owned()),
    )];

    if let LvvcStatus::Suspended {
        suspend_end_date: Some(end_date),
    } = status
    {
        result.push(suspend_end_date_claim(end_date)?);
    }

    Ok(result)
}

fn suspend_end_date_claim(
    end_date: &OffsetDateTime,
) -> Result<(String, String, Option<String>), ServiceError> {
    Ok((
        "suspendEndDate".to_owned(),
        end_date
            .format(SUSPEND_END_DATE_FORMAT)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?,
        Some("DATE".to_owned()),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::collections::HashMap;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn test_create_status_claims() {
        let claims = create_status_claims(&LvvcStatus::Accepted).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "status");
        assert_eq!(claims[0].1, "ACCEPTED");

        let claims = create_status_claims(&LvvcStatus::Revoked).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "status");
        assert_eq!(claims[0].1, "REVOKED");

        let claims = create_status_claims(&LvvcStatus::Suspended {
            suspend_end_date: None,
        })
        .unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].0, "status");
        assert_eq!(claims[0].1, "SUSPENDED");

        let claims = create_status_claims(&LvvcStatus::Suspended {
            suspend_end_date: Some(datetime!(2005-04-02 21:37 +0)),
        })
        .unwrap();
        assert_eq!(claims.len(), 2);
        let claims: HashMap<String, String> = HashMap::from_iter(
            claims
                .iter()
                .map(|(path, value, _)| (path.to_owned(), value.to_owned())),
        );
        assert_eq!(claims.get("status").unwrap(), "SUSPENDED");
        assert_eq!(
            claims.get("suspendEndDate").unwrap(),
            "2005-04-02T21:37:00Z",
        );
    }

    #[test]
    fn test_status_from_lvvc_claims() {
        assert_eq!(
            status_from_lvvc_claims(&HashMap::from([("status".to_string(), json!("ACCEPTED"))]))
                .unwrap(),
            LvvcStatus::Accepted
        );

        assert_eq!(
            status_from_lvvc_claims(&HashMap::from([("status".to_string(), json!("REVOKED"))]))
                .unwrap(),
            LvvcStatus::Revoked
        );

        assert_eq!(
            status_from_lvvc_claims(&HashMap::from([("status".to_string(), json!("SUSPENDED"))]))
                .unwrap(),
            LvvcStatus::Suspended {
                suspend_end_date: None
            }
        );

        assert_eq!(
            status_from_lvvc_claims(&HashMap::from([
                ("status".to_string(), json!("SUSPENDED")),
                ("suspendEndDate".to_string(), json!("2005-04-02T21:37:00Z"))
            ]))
            .unwrap(),
            LvvcStatus::Suspended {
                suspend_end_date: Some(datetime!(2005-04-02 21:37 +0))
            }
        );
    }
}
