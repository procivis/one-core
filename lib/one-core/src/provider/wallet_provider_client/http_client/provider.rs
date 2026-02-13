use serde::Deserialize;
use shared_types::WalletUnitId;
use url::Url;

use crate::error::{ContextWithErrorCode, ErrorCode};
use crate::provider::wallet_provider_client::WalletProviderClient;
use crate::provider::wallet_provider_client::dto::IssueWalletAttestationResponse;
use crate::provider::wallet_provider_client::error::WalletProviderClientError;
use crate::provider::wallet_provider_client::http_client::HTTPWalletProviderClient;
use crate::provider::wallet_provider_client::http_client::dto::{
    ActivateWalletUnitRequestRestDTO, IssueWalletUnitAttestationRequestRestDTO,
    IssueWalletUnitAttestationResponseRestDTO, RegisterWalletUnitRequestRestDTO,
    RegisterWalletUnitResponseRestDTO, WalletProviderMetadataResponseRestDTO,
};
use crate::service::wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, IssueWalletUnitAttestationRequestDTO,
    RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO, WalletProviderMetadataResponseDTO,
};

#[async_trait::async_trait]
impl WalletProviderClient for HTTPWalletProviderClient {
    async fn get_wallet_provider_metadata(
        &self,
        wallet_provider_metadata_url: &str,
    ) -> Result<WalletProviderMetadataResponseDTO, WalletProviderClientError> {
        let response: WalletProviderMetadataResponseRestDTO = async {
            self.http_client
                .get(wallet_provider_metadata_url)
                .send()
                .await?
                .error_for_status()?
                .json::<WalletProviderMetadataResponseRestDTO>()
        }
        .await
        .error_while("fetching wallet provider metadata")?;

        Ok(response.into())
    }

    async fn register(
        &self,
        wallet_provider_url: &str,
        request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, WalletProviderClientError> {
        let url = Url::parse(format!("{wallet_provider_url}/ssi/wallet-unit/v1").as_str())?;

        let response = async {
            self.http_client
                .post(url.as_str())
                .json(RegisterWalletUnitRequestRestDTO::from(request))?
                .send()
                .await
        }
        .await
        .error_while("requesting wallet unit registration")?;

        if response.status.is_client_error() {
            let error_body: ErrorBody = serde_json::from_slice(&response.body)?;
            if error_body.code == ErrorCode::BR_0270 {
                return Err(WalletProviderClientError::IntegrityCheckRequired);
            } else if error_body.code == ErrorCode::BR_0279 {
                return Err(WalletProviderClientError::IntegrityCheckNotRequired);
            }
        }

        let response: RegisterWalletUnitResponseRestDTO = response
            .error_for_status()
            .error_while("requesting wallet unit registration")?
            .json()
            .error_while("requesting wallet unit registration")?;

        Ok(response.into())
    }

    async fn activate(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletUnitId,
        request: ActivateWalletUnitRequestDTO,
    ) -> Result<(), WalletProviderClientError> {
        let url = Url::parse(
            format!("{wallet_provider_url}/ssi/wallet-unit/v1/{wallet_unit_id}/activate").as_str(),
        )?;

        async {
            self.http_client
                .post(url.as_str())
                .json(ActivateWalletUnitRequestRestDTO::from(request))?
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("requesting activation of wallet unit")?;

        Ok(())
    }

    async fn issue_attestation(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletUnitId,
        bearer_token: &str,
        request: IssueWalletUnitAttestationRequestDTO,
    ) -> Result<IssueWalletAttestationResponse, WalletProviderClientError> {
        let url = Url::parse(
            format!("{wallet_provider_url}/ssi/wallet-unit/v1/{wallet_unit_id}/issue-attestation")
                .as_str(),
        )?;

        let response = async {
            self.http_client
                .post(url.as_str())
                .bearer_auth(bearer_token)
                .json(IssueWalletUnitAttestationRequestRestDTO::from(request))?
                .send()
                .await
        }
        .await
        .error_while("requesting issuance of wallet unit")?;

        if response.status.is_client_error() {
            let error_body: ErrorBody = serde_json::from_slice(&response.body)?;

            if error_body.code == ErrorCode::BR_0261 {
                return Ok(IssueWalletAttestationResponse::Revoked);
            }
        }

        let response: IssueWalletUnitAttestationResponseRestDTO = response
            .error_for_status()
            .error_while("requesting issuance of wallet unit")?
            .json()
            .error_while("requesting issuance of wallet unit")?;

        Ok(IssueWalletAttestationResponse::Active(response.into()))
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    code: ErrorCode,
}
