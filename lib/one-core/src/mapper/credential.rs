use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::claim::Claim;
use crate::model::common::SortDirection;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialRole, CredentialType, SortableCredentialColumn,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::model::relation::OptionalRelatedRefExt;
use crate::repository::credential_repository::CredentialRepository;
#[cfg(test)]
use crate::service::test_utilities::CredentialBuilder;

/// Returns stored claims, resolving parent-owned claims for non-holder batch items.
/// Holder items carry their own claims, including metadata. Holder parents own no claims.
/// This never loads child claims;
/// use [`detail_claims`] to derive a holder batch parent's summary from its newest item.
pub(crate) async fn stored_credential_claims(
    credential: &Credential,
) -> Result<Vec<Claim>, NestedError> {
    if matches!(credential, Credential::HolderBatchParent { .. }) {
        return Ok(vec![]);
    }
    if credential.r#type() != CredentialType::BatchItem
        || credential.role() == CredentialRole::Holder
    {
        return Ok(credential.claims()?.as_ref().await?.to_owned());
    }
    Ok(credential
        .parent()
        .as_required_ref()
        .await?
        .claims()?
        .as_ref()
        .await?
        .to_owned())
}

/// The holder's batch summary follows its newest nondeleted item.
pub(crate) async fn detail_claims(
    credential: &Credential,
    repository: &dyn CredentialRepository,
) -> Result<Vec<Claim>, NestedError> {
    if credential.role() == CredentialRole::Holder
        && credential.r#type() == CredentialType::BatchParent
    {
        holder_batch_parent_claims(credential, repository).await
    } else {
        stored_credential_claims(credential).await
    }
}

async fn holder_batch_parent_claims(
    credential: &Credential,
    repository: &dyn CredentialRepository,
) -> Result<Vec<Claim>, NestedError> {
    let items = repository
        .get_credential_list(ListQuery {
            include_count: false,
            filtering: Some(
                CredentialFilterValue::ParentCredential(credential.common().id).condition()
                    & CredentialFilterValue::Deleted(false),
            ),
            sorting: Some(ListSorting {
                column: SortableCredentialColumn::CreatedDate,
                direction: Some(SortDirection::Descending),
            }),
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            ..Default::default()
        })
        .await
        .error_while("loading newest batch item")?;
    if let Some(item) = items.values.first() {
        return Ok(item.claims()?.as_ref().await?.to_owned());
    }
    Ok(vec![])
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;
    use crate::model::credential::GetCredentialList;
    use crate::repository::credential_repository::MockCredentialRepository;
    use crate::service::test_utilities::dummy_credential;

    #[tokio::test]
    async fn holder_items_use_only_own_claims_while_issuer_items_inherit() {
        let parent = dummy_credential();
        let parent_claim_id = parent.claims().unwrap().as_ref().await.unwrap()[0].id;
        let mut item = {
            let mut updated_credential = dummy_credential();
            updated_credential = CredentialBuilder {
                role: CredentialRole::Holder,
                r#type: CredentialType::BatchItem,
                parent: Some(parent.into()),
                ..updated_credential.into()
            }
            .build();
            updated_credential
        };
        item.claims_mut().unwrap().as_mut().await.unwrap()[0].selectively_disclosable = true;
        let own = stored_credential_claims(&item).await.unwrap();
        assert_eq!(
            own[0].id,
            item.claims().unwrap().as_ref().await.unwrap()[0].id
        );
        assert!(own[0].selectively_disclosable);
        assert_ne!(own[0].id, parent_claim_id);

        item = CredentialBuilder {
            role: CredentialRole::Issuer,
            ..item.into()
        }
        .build();
        assert_eq!(
            stored_credential_claims(&item).await.unwrap()[0].id,
            parent_claim_id
        );
        item = CredentialBuilder {
            role: CredentialRole::Holder,
            ..item.into()
        }
        .build();
        *item.claims_mut().unwrap() = Default::default();
        assert!(stored_credential_claims(&item).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn parent_details_use_only_newest_item_claims() {
        for (has_item, has_item_claims) in [(true, true), (true, false), (false, false)] {
            let parent = {
                let mut updated_credential = dummy_credential();
                updated_credential = CredentialBuilder {
                    role: CredentialRole::Holder,
                    r#type: CredentialType::BatchParent,
                    ..updated_credential.into()
                }
                .build();
                updated_credential
            };
            let mut item = dummy_credential();
            let item_claim_id = item.claims().unwrap().as_ref().await.unwrap()[0].id;
            if !has_item_claims {
                *item.claims_mut().unwrap() = Default::default();
            }
            let mut repository = MockCredentialRepository::new();
            repository
                .expect_get_credential_list()
                .returning(move |query| {
                    assert_eq!(query.pagination.unwrap().page_size, 1);
                    assert_eq!(
                        query.sorting.unwrap().direction,
                        Some(SortDirection::Descending)
                    );
                    Ok(GetCredentialList {
                        values: if has_item { vec![item.clone()] } else { vec![] },
                        total_items: Some(u64::from(has_item)),
                        total_pages: Some(u64::from(has_item)),
                    })
                });
            let claims = detail_claims(&parent, &repository).await.unwrap();
            if has_item_claims {
                assert_eq!(claims[0].id, item_claim_id);
            } else {
                assert!(claims.is_empty());
            }
            assert!(parent.claims().is_err());
            assert_eq!(
                detail_claims(&parent, &repository)
                    .await
                    .unwrap()
                    .is_empty(),
                !has_item_claims
            );
        }
    }
}
