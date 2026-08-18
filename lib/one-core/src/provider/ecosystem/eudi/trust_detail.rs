use shared_types::EntityId;
use shared_types::i18n::I18nString;
use standardized_types::openid4vp::dcql::CredentialQueryId;

use super::EudiEcosystem;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::history::{
    GetHistoryList, History, HistoryAction, HistoryFilterValue, HistoryMetadata,
    SortableHistoryColumn,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListQuery, ListSorting};
use crate::proto::jwt::Jwt;
use crate::provider::blob_storage::BlobStorage;
use crate::provider::ecosystem::dto::{TrustDetails, WalletRelyingPartyDetails};
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::{TrustDetail, TrustDetailInfo};
use crate::util::access_cert_parser::{EtsiParsedAccessCert, etsi_access_cert_from_pem_chain};

impl EudiEcosystem {
    pub(super) async fn get_trust_detail(
        &self,
        entity_id: EntityId,
    ) -> Result<TrustDetail, EcosystemError> {
        let history = self
            .history_repository
            .get_history_list(ListQuery {
                filtering: Some(
                    HistoryFilterValue::EntityIds(vec![entity_id]).condition()
                        & HistoryFilterValue::Actions(vec![
                            HistoryAction::WrpRcReceived,
                            HistoryAction::WrpNrReceived,
                            HistoryAction::WrpAcReceived,
                        ]),
                ),
                sorting: Some(ListSorting {
                    column: SortableHistoryColumn::CreatedDate,
                    direction: Some(SortDirection::Descending),
                }),
                ..Default::default()
            })
            .await
            .error_while("getting history list")?;

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let access_certificate = self
            .parsed_access_cert_from_history(&entity_id, &history, &*blob_storage)
            .await?;
        let (wrp, history_event) = self
            .parsed_wrp_info_from_history(&entity_id, &history, &*blob_storage)
            .await?;

        Ok(TrustDetail {
            received_at: history_event.created_date,
            info: TrustDetailInfo::Eudi(
                TrustDetails::Etsi {
                    wrp,
                    access_certificate,
                }
                .try_into()
                .error_while("converting trust detail")?,
            ),
        })
    }

    async fn parsed_access_cert_from_history(
        &self,
        id: &EntityId,
        history: &GetHistoryList,
        blob_storage: &dyn BlobStorage,
    ) -> Result<EtsiParsedAccessCert, EcosystemError> {
        let access_cert_history = history
            .values
            .iter()
            .find(|h| h.action == HistoryAction::WrpAcReceived)
            .ok_or(EcosystemError::MappingError(format!(
                "Missing access certificate for entity {id}"
            )))?;
        let access_cert_blob_id =
            access_cert_history
                .metadata_blob_id
                .ok_or(EcosystemError::MappingError(format!(
                    "Missing blob id on history entry {}",
                    access_cert_history.id
                )))?;
        let access_cert = blob_storage
            .get(&access_cert_blob_id)
            .await
            .error_while("loading access certificate")?
            .ok_or(EcosystemError::MappingError(format!(
                "Access certificate blob {access_cert_blob_id} not found"
            )))?;
        let access_certificate =
            etsi_access_cert_from_pem_chain(str::from_utf8(&access_cert.value).map_err(|e| {
                EcosystemError::MappingError(format!(
                    "failed to parse access certificate blob: {e}"
                ))
            })?)
            .error_while("parsing access certificate")?;

        Ok(access_certificate)
    }

    async fn parsed_wrp_info_from_history<'a>(
        &self,
        id: &EntityId,
        history: &'a GetHistoryList,
        blob_storage: &dyn BlobStorage,
    ) -> Result<(WalletRelyingPartyDetails, &'a History), EcosystemError> {
        let reg_cert_history = history
            .values
            .iter()
            .find(|h| {
                h.action == HistoryAction::WrpRcReceived || h.action == HistoryAction::WrpNrReceived
            })
            .ok_or(EcosystemError::MappingError(format!(
                "Missing registration certificate for entity {id}"
            )))?;
        let blob_id = reg_cert_history
            .metadata_blob_id
            .ok_or(EcosystemError::MappingError(format!(
                "Missing blob id on history entry {}",
                reg_cert_history.id
            )))?;
        let blob = blob_storage
            .get(&blob_id)
            .await
            .error_while("loading registration certificate")?
            .ok_or(EcosystemError::MappingError(format!(
                "Registration certificate blob {blob_id} not found"
            )))?;
        let blob_value = str::from_utf8(&blob.value).map_err(|e| {
            EcosystemError::MappingError(format!("failed to parse blob value: {e}"))
        })?;
        match reg_cert_history.action {
            HistoryAction::WrpRcReceived => {
                let parsed_token = Jwt::decompose_token(blob_value)
                    .error_while("parsing registration certificate")?;
                Ok((
                    WalletRelyingPartyDetails::RegistrationCertificate(parsed_token.payload),
                    reg_cert_history,
                ))
            }
            HistoryAction::WrpNrReceived => {
                let parsed_token = Jwt::decompose_token(blob_value)
                    .error_while("parsing national registry wrp info")?;
                Ok((
                    WalletRelyingPartyDetails::NationalRegistryInfo(parsed_token.payload),
                    reg_cert_history,
                ))
            }
            action => Err(EcosystemError::MappingError(format!(
                "Unexpected history action: {action:?}"
            ))),
        }
    }

    pub(super) async fn trust_purpose(
        &self,
        entity_id: EntityId,
        query_id: &CredentialQueryId,
    ) -> Result<Option<I18nString>, EcosystemError> {
        let history = self
            .history_repository
            .get_history_list(ListQuery {
                filtering: Some(
                    HistoryFilterValue::EntityIds(vec![entity_id]).condition()
                        & HistoryFilterValue::Actions(vec![
                            HistoryAction::WrpRcReceived,
                            HistoryAction::WrpNrReceived,
                        ]),
                ),
                sorting: Some(ListSorting {
                    column: SortableHistoryColumn::CreatedDate,
                    direction: Some(SortDirection::Descending),
                }),
                ..Default::default()
            })
            .await
            .error_while("getting history list")?;

        Ok(match history.values.into_iter().next() {
            None => None,
            Some(history) => trust_purpose_from_history(history, query_id)?,
        })
    }
}

fn trust_purpose_from_history(
    history: History,
    query_id: &CredentialQueryId,
) -> Result<Option<I18nString>, EcosystemError> {
    let metadata = history
        .metadata
        .ok_or_else(|| EcosystemError::MappingError("missing history metadata".to_string()))?;

    let HistoryMetadata::WalletRelyingParty(metadata) = metadata else {
        return Err(EcosystemError::MappingError(
            "invalid history metadata".to_string(),
        ));
    };

    let Some(purpose) = metadata.purpose.get(query_id) else {
        return Ok(None);
    };

    Ok(Some(I18nString(
        purpose
            .iter()
            .map(|p| (p.lang.to_owned(), p.value.to_owned()))
            .collect(),
    )))
}
