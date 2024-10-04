use std::collections::HashMap;

use shared_types::CredentialId;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::fmt::Urn;

use super::dto::LvvcStatus;
use crate::provider::credential_formatter::model::{PublishedClaim, PublishedClaimValue};
use crate::provider::revocation::error::RevocationError;

const SUSPEND_END_DATE_FORMAT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");

// The status claim should be at the root of the `credentialSubject` object.
// We previously issued the LVVC with all claims nested in an inner `LvvcSubject` object.
// We no longer do this since ONE-3309, but we still support the old format.
// See ONE-3528 for more details.
pub fn status_from_lvvc_claims(
    lvvc_claims: &HashMap<String, serde_json::Value>,
) -> Result<LvvcStatus, RevocationError> {
    let status = lvvc_claims.get("status").or(lvvc_claims
        .get("LvvcSubject")
        .and_then(|claims| claims.get("status")));

    let status = status
        .ok_or(RevocationError::ValidationError(
            "missing status claim in LVVC".to_string(),
        ))?
        .as_str()
        .ok_or(RevocationError::ValidationError(
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
                        date.as_str().ok_or(RevocationError::ValidationError(
                            "suspendEndDate claim in LVVC is not string".to_string(),
                        ))?,
                        &Rfc3339,
                    )
                    .map_err(|e| RevocationError::ValidationError(e.to_string()))?,
                ),
            };
            LvvcStatus::Suspended { suspend_end_date }
        }
        _ => {
            return Err(RevocationError::ValidationError(format!(
                "Unknown LVVC status `{status}`"
            )))
        }
    })
}

pub(super) fn create_status_claims(
    status: &LvvcStatus,
) -> Result<Vec<PublishedClaim>, RevocationError> {
    let mut result = vec![PublishedClaim {
        key: "status".to_owned(),
        value: PublishedClaimValue::String(status.to_string()),
        datatype: Some("STRING".to_owned()),
        array_item: false,
    }];

    if let LvvcStatus::Suspended {
        suspend_end_date: Some(end_date),
    } = status
    {
        result.push(suspend_end_date_claim(end_date, false)?);
    }

    Ok(result)
}

pub(super) fn create_id_claim(credential_id: CredentialId) -> PublishedClaim {
    PublishedClaim {
        key: "id".into(),
        value: PublishedClaimValue::String(Urn::from_uuid(credential_id.into()).to_string()),
        datatype: None,
        array_item: false,
    }
}

fn suspend_end_date_claim(
    end_date: &OffsetDateTime,
    array_item: bool,
) -> Result<PublishedClaim, RevocationError> {
    Ok(PublishedClaim {
        key: "suspendEndDate".to_owned(),
        value: PublishedClaimValue::String(
            end_date
                .format(SUSPEND_END_DATE_FORMAT)
                .map_err(|e| RevocationError::MappingError(e.to_string()))?,
        ),
        datatype: Some("DATE".to_owned()),
        array_item,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;
    use time::macros::datetime;

    use super::*;

    #[test]
    fn test_create_status_claims() {
        let claims = create_status_claims(&LvvcStatus::Accepted).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].key, "status");
        assert_eq!(claims[0].value.to_string(), "ACCEPTED");

        let claims = create_status_claims(&LvvcStatus::Revoked).unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].key, "status");
        assert_eq!(claims[0].value.to_string(), "REVOKED");

        let claims = create_status_claims(&LvvcStatus::Suspended {
            suspend_end_date: None,
        })
        .unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].key, "status");
        assert_eq!(claims[0].value.to_string(), "SUSPENDED");

        let claims = create_status_claims(&LvvcStatus::Suspended {
            suspend_end_date: Some(datetime!(2005-04-02 21:37 +0)),
        })
        .unwrap();
        assert_eq!(claims.len(), 2);
        let claims: HashMap<String, PublishedClaimValue> =
            HashMap::from_iter(claims.iter().map(|published_claim| {
                (
                    published_claim.key.to_owned(),
                    published_claim.value.to_owned(),
                )
            }));
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
