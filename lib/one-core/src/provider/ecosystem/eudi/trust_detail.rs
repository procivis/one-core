use shared_types::EntityId;

use super::EudiEcosystem;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::common::SortDirection;
use crate::model::history::{
    GetHistoryList, HistoryAction, HistoryFilterValue, SortableHistoryColumn,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListQuery, ListSorting};
use crate::proto::jwt::Jwt;
use crate::proto::trust_information::dto::{TrustDetails, WalletRelyingPartyDetails};
use crate::provider::blob_storage::BlobStorage;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::TrustDetail;
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
        let wrp = self
            .parsed_wrp_info_from_history(&entity_id, &history, &*blob_storage)
            .await?;

        Ok(TrustDetail::Eudi(
            TrustDetails::Etsi {
                wrp,
                access_certificate,
            }
            .try_into()
            .error_while("converting trust detail")?,
        ))
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

    async fn parsed_wrp_info_from_history(
        &self,
        id: &EntityId,
        history: &GetHistoryList,
        blob_storage: &dyn BlobStorage,
    ) -> Result<WalletRelyingPartyDetails, EcosystemError> {
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
                Ok(WalletRelyingPartyDetails::RegistrationCertificate(
                    parsed_token.payload,
                ))
            }
            HistoryAction::WrpNrReceived => {
                let parsed_token = Jwt::decompose_token(blob_value)
                    .error_while("parsing national registry wrp info")?;
                Ok(WalletRelyingPartyDetails::NationalRegistryInfo(
                    parsed_token.payload,
                ))
            }
            action => Err(EcosystemError::MappingError(format!(
                "Unexpected history action: {action:?}"
            ))),
        }
    }
}
