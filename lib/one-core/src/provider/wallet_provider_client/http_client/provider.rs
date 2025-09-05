use anyhow::{Context, anyhow};
use serde_json::{Value, json};
use shared_types::WalletUnitId;
use url::Url;

use crate::provider::http_client::Error;
use crate::provider::wallet_provider_client::WalletProviderClient;
use crate::provider::wallet_provider_client::dto::RefreshWalletUnitResponse;
use crate::provider::wallet_provider_client::error::WalletProviderClientError;
use crate::provider::wallet_provider_client::http_client::HTTPWalletProviderClient;
use crate::provider::wallet_provider_client::http_client::dto::{
    ActivateWalletUnitRequestRestDTO, ActivateWalletUnitResponseRestDTO,
    RefreshWalletUnitRequestRestDTO, RefreshWalletUnitResponseRestDTO,
    RegisterWalletUnitRequestRestDTO, RegisterWalletUnitResponseRestDTO,
};
use crate::service::ssi_wallet_provider::dto::{
    ActivateWalletUnitRequestDTO, ActivateWalletUnitResponseDTO, RefreshWalletUnitRequestDTO,
    RegisterWalletUnitRequestDTO, RegisterWalletUnitResponseDTO,
};

#[async_trait::async_trait]
impl WalletProviderClient for HTTPWalletProviderClient {
    async fn register(
        &self,
        wallet_provider_url: &str,
        request: RegisterWalletUnitRequestDTO,
    ) -> Result<RegisterWalletUnitResponseDTO, WalletProviderClientError> {
        let url = Url::parse(format!("{wallet_provider_url}/ssi/wallet-unit/v1").as_str())
            .context("url error")
            .map_err(WalletProviderClientError::Transport)?;

        let response = self
            .http_client
            .post(url.as_str())
            .json(RegisterWalletUnitRequestRestDTO::from(request))
            .context("json error")
            .map_err(WalletProviderClientError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(WalletProviderClientError::Transport)?;

        if response.status.is_client_error() {
            let body = serde_json::from_slice::<Value>(&response.body)
                .map_err(|e| WalletProviderClientError::Transport(Error::JsonError(e).into()))?;
            let cause = body
                .get("code")
                .ok_or(WalletProviderClientError::Transport(anyhow!(
                    "Error missing code"
                )))?;
            if cause == "BR_0270" {
                return Err(WalletProviderClientError::IntegrityCheckRequired);
            } else if cause == "BR_0279" {
                return Err(WalletProviderClientError::IntegrityCheckNotRequired);
            }
        }

        response
            .error_for_status()
            .context("status error")
            .map_err(WalletProviderClientError::Transport)?
            .json::<RegisterWalletUnitResponseRestDTO>()
            .context("parsing error")
            .map_err(WalletProviderClientError::Transport)
            .map(|r| r.into())
    }

    async fn activate(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletUnitId,
        request: ActivateWalletUnitRequestDTO,
    ) -> Result<ActivateWalletUnitResponseDTO, WalletProviderClientError> {
        let url = Url::parse(
            format!("{wallet_provider_url}/ssi/wallet-unit/v1/{wallet_unit_id}/activate").as_str(),
        )
        .context("url error")
        .map_err(WalletProviderClientError::Transport)?;

        self.http_client
            .post(url.as_str())
            .json(ActivateWalletUnitRequestRestDTO::from(request))
            .context("json error")
            .map_err(WalletProviderClientError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(WalletProviderClientError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(WalletProviderClientError::Transport)?
            .json::<ActivateWalletUnitResponseRestDTO>()
            .context("parsing error")
            .map_err(WalletProviderClientError::Transport)
            .map(|r| r.into())
    }

    async fn refresh(
        &self,
        wallet_provider_url: &str,
        wallet_unit_id: WalletUnitId,
        request: RefreshWalletUnitRequestDTO,
    ) -> Result<RefreshWalletUnitResponse, WalletProviderClientError> {
        let url = Url::parse(
            format!("{wallet_provider_url}/ssi/wallet-unit/v1/{wallet_unit_id}/refresh").as_str(),
        )
        .context("url error")
        .map_err(WalletProviderClientError::Transport)?;

        let result = self
            .http_client
            .post(url.as_str())
            .json(RefreshWalletUnitRequestRestDTO::from(request))
            .context("json error")
            .map_err(WalletProviderClientError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(WalletProviderClientError::Transport)?;

        if result.status.is_client_error() {
            let body = serde_json::from_slice::<Value>(&result.body)
                .map_err(|e| WalletProviderClientError::Transport(Error::JsonError(e).into()))?;
            let cause = body
                .get("code")
                .ok_or(WalletProviderClientError::Transport(anyhow!(
                    "Error missing code"
                )))?;
            if *cause == json!("BR_0261".to_string()) {
                return Ok(RefreshWalletUnitResponse::Revoked);
            }
        }

        result
            .error_for_status()
            .context("status error")
            .map_err(WalletProviderClientError::Transport)?
            .json::<RefreshWalletUnitResponseRestDTO>()
            .context("parsing error")
            .map_err(WalletProviderClientError::Transport)
            .map(|r| RefreshWalletUnitResponse::Active(r.into()))
    }
}
