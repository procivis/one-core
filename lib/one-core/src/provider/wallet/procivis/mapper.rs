use crate::provider::wallet::procivis::model::EudiWalletInfoConfig;
use crate::service::managed_instance::dto::{EudiWalletGeneralInfo, EudiWalletInfo, WscdInfo};

impl From<EudiWalletInfoConfig> for EudiWalletInfo {
    fn from(value: EudiWalletInfoConfig) -> Self {
        Self {
            general_info: EudiWalletGeneralInfo {
                wallet_provider_name: value.provider_name,
                wallet_solution_id: value.solution_id,
                wallet_solution_version: value.solution_version,
                wallet_solution_certification_information: value.solution_certification_information,
            },
            wscd_info: Some(WscdInfo {
                wscd_type: value.wscd_type,
            }),
        }
    }
}
