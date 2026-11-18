use std::io::{Read, Write};

use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;

use crate::error::ContextWithErrorCode;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, UpdateRevocationListEntryId,
    UpdateRevocationListEntryRequest,
};
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::RevocationState;
use crate::repository::revocation_list_repository::RevocationListRepository;

pub(super) fn gzip_compress(input: Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Default::default());
    encoder.write_all(&input)?;
    encoder.finish()
}

pub(super) fn gzip_decompress(input: Vec<u8>, index: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = GzDecoder::new(&input[..]);
    let mut result: Vec<u8> = vec![0; index / 8 + 1];
    decoder.read_exact(&mut result)?;
    Ok(result)
}

pub(super) fn status_purpose_to_revocation_state(
    status_purpose: Option<&String>,
) -> Result<RevocationState, RevocationError> {
    match status_purpose
        .ok_or(RevocationError::ValidationError(
            "Missing status purpose ".to_string(),
        ))?
        .as_str()
    {
        "revocation" => Ok(RevocationState::Revoked),
        "suspension" => Ok(RevocationState::Suspended {
            suspend_end_date: None,
        }),
        value => Err(RevocationError::ValidationError(format!(
            "Invalid status purpose: {value}",
        ))),
    }
}

/// Sets the state of the given entries and returns every list containing at least one of them
/// (each list once, in order of first occurrence), so that the caller can republish them.
pub(super) async fn update_entries_state(
    revocation_list_repository: &dyn RevocationListRepository,
    entries: Vec<UpdateRevocationListEntryId>,
    new_state: RevocationState,
) -> Result<Vec<RevocationList>, RevocationError> {
    let mut affected_lists: Vec<RevocationList> = vec![];
    for entry in entries {
        let lists = match &entry {
            UpdateRevocationListEntryId::Credential(credential_id) => revocation_list_repository
                .get_revocation_lists_by_entity(RevocationListEntityId::Credential(Some(
                    *credential_id,
                )))
                .await
                .error_while("getting revocation lists")?,
            UpdateRevocationListEntryId::Id(entry_id) => vec![
                revocation_list_repository
                    .get_revocation_list_by_entry_id(*entry_id)
                    .await
                    .error_while("getting revocation list")?,
            ],
            UpdateRevocationListEntryId::Index(list_id, _) => vec![
                revocation_list_repository
                    .get_revocation_list(list_id)
                    .await
                    .error_while("getting revocation list")?,
            ],
        };

        revocation_list_repository
            .update_entry(
                entry,
                UpdateRevocationListEntryRequest {
                    state: Some(new_state.into()),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating revocation list entry")?;

        for list in lists {
            if !affected_lists.iter().any(|affected| affected.id == list.id) {
                affected_lists.push(list);
            }
        }
    }
    Ok(affected_lists)
}

#[cfg(test)]
mod test {
    use mockall::predicate::eq;
    use shared_types::{CredentialId, RevocationListEntryId, RevocationListId};
    use similar_asserts::assert_eq;

    use super::*;
    use crate::model::revocation_list::{
        RevocationListEntryState, RevocationListPurpose, StatusListCredentialFormat,
    };
    use crate::repository::revocation_list_repository::MockRevocationListRepository;
    use crate::service::test_utilities::dummy_identifier;

    fn dummy_list(id: RevocationListId) -> RevocationList {
        RevocationList {
            id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            formatted_list: vec![],
            format: StatusListCredentialFormat::Jwt,
            r#type: "TOKENSTATUSLIST".into(),
            purpose: RevocationListPurpose::Revocation,
            issuer_identifier: dummy_identifier().into(),
            issuer_certificate: None,
            sequence_number: 0,
            params: None,
        }
    }

    #[tokio::test]
    async fn test_update_entries_state_returns_each_affected_list_once() {
        let credential_id = CredentialId::new();
        let entry_id = RevocationListEntryId::new();
        let list_1 = RevocationListId::new();
        let list_2 = RevocationListId::new();
        let list_3 = RevocationListId::new();

        let mut repository = MockRevocationListRepository::new();
        repository
            .expect_get_revocation_lists_by_entity()
            .once()
            .with(eq(RevocationListEntityId::Credential(Some(credential_id))))
            .return_once(move |_| Ok(vec![dummy_list(list_1), dummy_list(list_2)]));
        repository
            .expect_get_revocation_list()
            .once()
            .with(eq(list_1))
            .return_once(move |_| Ok(dummy_list(list_1)));
        repository
            .expect_get_revocation_list_by_entry_id()
            .once()
            .with(eq(entry_id))
            .return_once(move |_| Ok(dummy_list(list_3)));
        repository
            .expect_update_entry()
            .times(3)
            .withf(|_, request| {
                request
                    == &UpdateRevocationListEntryRequest {
                        state: Some(RevocationListEntryState::Revoked),
                        credential_id: None,
                    }
            })
            .returning(|_, _| Ok(()));

        let lists = update_entries_state(
            &repository,
            vec![
                UpdateRevocationListEntryId::Credential(credential_id),
                UpdateRevocationListEntryId::Index(list_1, 5),
                UpdateRevocationListEntryId::Id(entry_id),
            ],
            RevocationState::Revoked,
        )
        .await
        .unwrap();

        assert_eq!(
            lists.iter().map(|list| list.id).collect::<Vec<_>>(),
            vec![list_1, list_2, list_3]
        );
    }
}
